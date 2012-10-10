/*
 * Copyright (c) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.	IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <arpa/inet.h>

#include "dnstable-private.h"

#include "librsf/ip_arith.h"
#include "librsf/hex_decode.h"

struct dnstable_query {
	dnstable_query_type	q_type;
	bool			do_rrtype;
	char			*err;
	wdns_name_t		name, bailiwick;
	uint32_t		rrtype;
	size_t			len_rdata, len_rdata2;
	uint8_t			*rdata, *rdata2;
};

struct query_iter {
	struct dnstable_query	*query;
	const struct mtbl_source *source;
	struct mtbl_iter	*m_iter, *m_iter2;
	ubuf			*key, *key2;
};

static void
query_set_err(struct dnstable_query *q, const char *err)
{
	free(q->err);
	q->err = strdup(err);
}

static dnstable_res
query_load_name(struct dnstable_query *q, wdns_name_t *name, const char *s_name)
{
	free(name->data);
	name->len = 0;
	name->data = NULL;
	if (s_name == NULL)
		return (dnstable_res_success);
	if (wdns_str_to_name(s_name, name) != wdns_res_success) {
		query_set_err(q, "wdns_str_to_name() failed");
		return (dnstable_res_failure);
	}
	wdns_downcase_name(name);
	return (dnstable_res_success);
}

static dnstable_res
query_load_address(struct dnstable_query *q, const char *data, uint8_t **addr, size_t *len_addr)
{
	uint8_t buf[16];
	free(*addr);
	if (inet_pton(AF_INET, data, buf)) {
		*len_addr = 4;
		*addr = my_malloc(4);
		memcpy(*addr, buf, 4);
		return (dnstable_res_success);
	} else if (inet_pton(AF_INET6, data, buf)) {
		*len_addr = 16;
		*addr = my_malloc(16);
		memcpy(*addr, buf, 16);
		return (dnstable_res_success);
	}
	query_set_err(q, "inet_pton() failed");
	return (dnstable_res_failure);
}

struct dnstable_query *
dnstable_query_init(dnstable_query_type q_type)
{
	assert(q_type == DNSTABLE_QUERY_TYPE_RRSET ||
	       q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME ||
	       q_type == DNSTABLE_QUERY_TYPE_RDATA_IP ||
	       q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW);
	struct dnstable_query *q = my_calloc(1, sizeof(*q));
	q->q_type = q_type;
	return (q);
}

void
dnstable_query_destroy(struct dnstable_query **q)
{
	if (*q) {
		free((*q)->rdata);
		free((*q)->rdata2);
		free((*q)->name.data);
		free((*q)->bailiwick.data);
		free((*q)->err);
		free(*q);
		*q = NULL;
	}
}

const char *
dnstable_query_get_error(struct dnstable_query *q) {
	if (q->err == NULL)
		q->err = strdup("unknown error");
	assert(q->err != NULL);
	return (q->err);
}

dnstable_res
dnstable_query_set_bailiwick(struct dnstable_query *q, const char *s_name)
{
	if (q->q_type != DNSTABLE_QUERY_TYPE_RRSET) {
		query_set_err(q, "bailiwick filtering not supported");
		return (dnstable_res_failure);
	}
	return query_load_name(q, &q->bailiwick, s_name);
}

static dnstable_res
query_set_data_rrset_owner(struct dnstable_query *q, const char *s_name)
{
	return query_load_name(q, &q->name, s_name);
}

static dnstable_res
query_set_data_rdata_name(struct dnstable_query *q, const char *s_name)
{
	return query_load_name(q, &q->name, s_name);
}

static dnstable_res
query_set_data_rdata_raw(struct dnstable_query *q, const char *data)
{
	free(q->rdata);
	q->rdata = NULL;
	if (data == NULL)
		return (dnstable_res_success);
	return hex_decode(data, &q->rdata, &q->len_rdata);
}

static dnstable_res
query_set_data_rdata_ip_range(struct dnstable_query *q, const char *data)
{
	dnstable_res res = dnstable_res_failure;
	char *s = strdup(data);
	char *addr1, *addr2;
	char *saveptr;

	if ((addr1 = strtok_r(s, "-", &saveptr)) == NULL) goto out;
	if ((addr2 = strtok_r(NULL, "-", &saveptr)) == NULL) goto out;
	if (strtok_r(NULL, "-", &saveptr) != NULL) goto out;

	if (!query_load_address(q, addr1, &q->rdata, &q->len_rdata)) goto out;
	if (!query_load_address(q, addr2, &q->rdata2, &q->len_rdata2)) goto out;
	if (q->len_rdata != q->len_rdata2) {
		query_set_err(q, "address family mismatch in IP range");
		goto out;
	}
	q->do_rrtype = true;
	if (q->len_rdata == 4) {
		q->rrtype = WDNS_TYPE_A;
		ip4_incr(q->rdata2);
	} else if (q->len_rdata == 16) {
		q->rrtype = WDNS_TYPE_AAAA;
		ip6_incr(q->rdata2);
	}
	res = dnstable_res_success;
out:
	free(s);
	return (res);
}

static dnstable_res
query_set_data_rdata_ip_prefix(struct dnstable_query *q, const char *data)
{
	dnstable_res res = dnstable_res_failure;
	char *s = NULL;
	uint8_t *ip = NULL;
	size_t len_ip;
	char *address, *prefix_length;
	char *saveptr, *endptr;
	long plen;

	s = strdup(data);
	assert(s != NULL);
	if ((address = strtok_r(s, "/", &saveptr)) == NULL) goto out;
	if ((prefix_length = strtok_r(NULL, "/", &saveptr)) == NULL) goto out;
	if (strtok_r(NULL, "/", &saveptr) != NULL) goto out;

	if (!query_load_address(q, address, &ip, &len_ip)) goto out;

	errno = 0;
	plen = strtol(prefix_length, &endptr, 10);
	if (errno != 0 || *endptr != '\0') goto out;

	if ((len_ip == 4 && plen > 32) ||
	    (len_ip == 16 && plen > 128))
	{
		res = dnstable_res_failure;
		goto out;
	}

	if (len_ip == 4) {
		q->do_rrtype = true;
		q->rrtype = WDNS_TYPE_A;

		q->len_rdata = len_ip;
		q->len_rdata2 = len_ip;
		free(q->rdata);
		free(q->rdata2);
		q->rdata = my_malloc(len_ip);
		q->rdata2 = my_malloc(len_ip);
		ip4_lower(ip, plen, q->rdata);
		ip4_upper(ip, plen, q->rdata2);
		ip4_incr(q->rdata2);
		res = dnstable_res_success;
	} else if (len_ip == 16) {
		q->do_rrtype = true;
		q->rrtype = WDNS_TYPE_AAAA;

		q->len_rdata = len_ip;
		q->len_rdata2 = len_ip;
		free(q->rdata);
		free(q->rdata2);
		q->rdata = my_malloc(len_ip);
		q->rdata2 = my_malloc(len_ip);
		ip6_lower(ip, plen, q->rdata);
		ip6_upper(ip, plen, q->rdata2);
		ip6_incr(q->rdata2);
		res = dnstable_res_success;
	}

out:
	if (res != dnstable_res_success)
		query_set_err(q, "unable to parse IP prefix");
	free(ip);
	free(s);
	return (res);
}

static dnstable_res
query_set_data_rdata_ip_address(struct dnstable_query *q, const char *data)
{
	free(q->rdata2);
	q->rdata2 = NULL;
	if (!query_load_address(q, data, &q->rdata, &q->len_rdata))
		return (dnstable_res_failure);
	q->do_rrtype = true;
	if (q->len_rdata == 4)
		q->rrtype = WDNS_TYPE_A;
	else if (q->len_rdata == 16)
		q->rrtype = WDNS_TYPE_AAAA;
	return (dnstable_res_success);
}

static dnstable_res
query_set_data_rdata_ip(struct dnstable_query *q, const char *data)
{
	if (data == NULL) {
		free(q->rdata);
		free(q->rdata2);
		q->rdata = NULL;
		q->rdata2 = NULL;
		return (dnstable_res_success);
	}

	if (strchr(data, '-')) {
		return query_set_data_rdata_ip_range(q, data);
	} else if (strchr(data, '/')) {
		return query_set_data_rdata_ip_prefix(q, data);
	} else {
		return query_set_data_rdata_ip_address(q, data);
	}
}

dnstable_res
dnstable_query_set_data(struct dnstable_query *q, const char *data)
{
	if (q->q_type == DNSTABLE_QUERY_TYPE_RRSET) {
		return query_set_data_rrset_owner(q, data);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME) {
		return query_set_data_rdata_name(q, data);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_IP) {
		return query_set_data_rdata_ip(q, data);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW) {
		return query_set_data_rdata_raw(q, data);
	} else {
		return (dnstable_res_failure);
	}
}

dnstable_res
dnstable_query_set_rrtype(struct dnstable_query *q, const char *s_rrtype)
{
	uint16_t rrtype;

	if (s_rrtype == NULL) {
		q->do_rrtype = false;
		return (dnstable_res_success);
	}

	if (strcasecmp(s_rrtype, "ANY") == 0 ||
	    strcasecmp(s_rrtype, "ANY-DNSSEC") == 0)
	{
		q->do_rrtype = false;
		return (dnstable_res_success);
	}

	rrtype = wdns_str_to_rrtype(s_rrtype);
	if (rrtype == 0) {
		query_set_err(q, "unknown rrtype mnemonic");
		return (dnstable_res_failure);
	}
	q->rrtype = rrtype;
	q->do_rrtype = true;
	return (dnstable_res_success);
}

dnstable_res
dnstable_query_filter(struct dnstable_query *q, struct dnstable_entry *e, bool *pass)
{
	dnstable_res res;

	if (q->do_rrtype) {
		uint16_t rrtype;
		res = dnstable_entry_get_rrtype(e, &rrtype);
		if (res != dnstable_res_success)
			return (res);
		if (rrtype != q->rrtype)
			goto fail;
	}

	if (q->q_type == DNSTABLE_QUERY_TYPE_RRSET && q->bailiwick.data != NULL) {
		const uint8_t *bailiwick;
		size_t len_bailiwick;
		res = dnstable_entry_get_bailiwick(e, &bailiwick, &len_bailiwick);
		if (res != dnstable_res_success)
			return (res);
		if (q->bailiwick.len != len_bailiwick)
			goto fail;
		if (memcmp(q->bailiwick.data, bailiwick, len_bailiwick) != 0)
			goto fail;
	}

	*pass = true;
	return (dnstable_res_success);
fail:
	*pass = false;
	return (dnstable_res_success);
}

static void
query_iter_free(void *clos)
{
	struct query_iter *it = (struct query_iter *) clos;
	mtbl_iter_destroy(&it->m_iter);
	mtbl_iter_destroy(&it->m_iter2);
	ubuf_destroy(&it->key);
	ubuf_destroy(&it->key2);
	free(it);
}

static void
add_rrtype_to_key(ubuf *key, uint32_t rrtype)
{
	assert(rrtype != WDNS_TYPE_ANY);
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), rrtype));
}

static dnstable_res
query_iter_next(void *clos, struct dnstable_entry **ent)
{
	struct query_iter *it = (struct query_iter *) clos;

	for (;;) {
		bool pass = false;
		dnstable_res res;
		const uint8_t *key, *val;
		size_t len_key, len_val;

		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);
		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		assert(*ent != NULL);
		res = dnstable_query_filter(it->query, *ent, &pass);
		assert(res == dnstable_res_success);
		if (pass) {
			return (dnstable_res_success);
		} else {
			dnstable_entry_destroy(ent);
			continue;
		}
	}
}

static dnstable_res
query_iter_next_name_indirect(void *clos, struct dnstable_entry **ent, uint8_t type_byte)
{
	struct query_iter *it = (struct query_iter *) clos;
	const uint8_t *key, *val;
	size_t len_key, len_val;
	bool pass = false;
	dnstable_res res;

	for (;;) {
		if (it->m_iter == NULL) {
			if (mtbl_iter_next(it->m_iter2,
					   &key, &len_key,
					   &val, &len_val) != mtbl_res_success)
			{
				return (dnstable_res_failure);
			}
			ubuf_clip(it->key, 0);
			ubuf_reserve(it->key, len_key + mtbl_varint_length(it->query->rrtype));
			ubuf_add(it->key, type_byte);
			wdns_reverse_name(key + 1, len_key - 1, ubuf_ptr(it->key));
			ubuf_advance(it->key, len_key - 1);
			if (it->query->do_rrtype)
				add_rrtype_to_key(it->key, it->query->rrtype);
			it->m_iter = mtbl_source_get_prefix(it->source,
							    ubuf_data(it->key),
							    ubuf_size(it->key));
		}
		assert(it->m_iter != NULL);
		if (mtbl_iter_next(it->m_iter,
				   &key, &len_key,
				   &val, &len_val) != mtbl_res_success)
		{
			mtbl_iter_destroy(&it->m_iter);
			continue;
		}
		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		assert(*ent != NULL);
		res = dnstable_query_filter(it->query, *ent, &pass);
		assert(res == dnstable_res_success);
		if (pass) {
			return (dnstable_res_success);
		} else {
			dnstable_entry_destroy(ent);
			continue;
		}
	}
}

static dnstable_res
query_iter_next_rrset_name_fwd(void *clos, struct dnstable_entry **ent)
{
	return query_iter_next_name_indirect(clos, ent, ENTRY_TYPE_RRSET);
}

static dnstable_res
query_iter_next_rdata_name_rev(void *clos, struct dnstable_entry **ent)
{
	return query_iter_next_name_indirect(clos, ent, ENTRY_TYPE_RDATA);
}

static struct dnstable_iter *
query_init_rrset_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET_NAME_FWD);

	/* key: rrset owner name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	it->m_iter2 = mtbl_source_get_prefix(it->source,
					     ubuf_data(it->key),
					     ubuf_size(it->key));

	return dnstable_iter_init(query_iter_next_rrset_name_fwd, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rrset_left_wildcard(struct query_iter *it)
{
	uint8_t name[WDNS_MAXLEN_NAME];

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET);

	/* key: rrset owner name (label-reversed),
	 * less leading "\x01\x2a" and trailing "\x00" */
	size_t len = it->query->name.len - 2;
	wdns_reverse_name(it->query->name.data + 2, len, name);
	ubuf_append(it->key, name, len - 1);

	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static inline bool
is_right_wildcard(wdns_name_t *name)
{
	if (name->len >= 3 &&
	    name->data[name->len - 3] == '\x01' &&
	    name->data[name->len - 2] == '*')
	{
		return (true);
	}
	return (false);
}

static inline bool
is_left_wildcard(wdns_name_t *name)
{
	if (name->len >= 3 &&
	    name->data[0] == '\x01' &&
	    name->data[1] == '*')
	{
		return (true);
	}
	return (false);
}

static struct dnstable_iter *
query_init_rrset(struct query_iter *it)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	it->key = ubuf_init(64);

	if (is_right_wildcard(&it->query->name))
		return query_init_rrset_right_wildcard(it);
	if (is_left_wildcard(&it->query->name))
		return query_init_rrset_left_wildcard(it);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET);

	/* key: rrset owner name (label-reversed) */
	wdns_reverse_name(it->query->name.data, it->query->name.len, name);
	ubuf_append(it->key, name, it->query->name.len);

	if (it->query->do_rrtype) {
		/* key: rrtype */
		add_rrtype_to_key(it->key, it->query->rrtype);

		if (it->query->bailiwick.data != NULL) {
			/* key: bailiwick name (label-reversed) */
			wdns_reverse_name(it->query->bailiwick.data,
					  it->query->bailiwick.len,
					  name);
			ubuf_append(it->key, name, it->query->bailiwick.len);
		}
	}

	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_left_wildcard(struct query_iter *it)
{
	uint8_t name[WDNS_MAXLEN_NAME];

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA_NAME_REV);

	/* key: rdata name (label-reversed), less leading "\x01\x2a" and trailing "\x00" */
	size_t len = it->query->name.len - 2;
	wdns_reverse_name(it->query->name.data + 2, len, name);
	ubuf_append(it->key, name, len - 1);

	it->m_iter2 = mtbl_source_get_prefix(it->source,
					     ubuf_data(it->key),
					     ubuf_size(it->key));

	return dnstable_iter_init(query_iter_next_rdata_name_rev, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_name(struct query_iter *it)
{
	it->key = ubuf_init(64);

	if (is_right_wildcard(&it->query->name))
		return query_init_rdata_right_wildcard(it);
	if (is_left_wildcard(&it->query->name))
		return query_init_rdata_left_wildcard(it);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata name */
	ubuf_append(it->key, it->query->name.data, it->query->name.len);

	/* key: rrtype */
	if (it->query->do_rrtype)
		add_rrtype_to_key(it->key, it->query->rrtype);

	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_ip(struct query_iter *it)
{
	assert(it->query->do_rrtype);
	assert(it->query->rdata != NULL);

	it->key = ubuf_init(64);

	/* key: type byte, rdata, rrtype */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);
	ubuf_append(it->key, it->query->rdata, it->query->len_rdata);
	add_rrtype_to_key(it->key, it->query->rrtype);

	if (it->query->rdata2 != NULL) {
		it->key2 = ubuf_init(64);

		/* key: type byte, rdata */
		ubuf_add(it->key2, ENTRY_TYPE_RDATA);
		ubuf_append(it->key2, it->query->rdata2, it->query->len_rdata2);
	}

	if (it->key2 == NULL) {
		it->m_iter = mtbl_source_get_prefix(it->source,
						    ubuf_data(it->key), ubuf_size(it->key));
	} else {
		it->m_iter = mtbl_source_get_range(it->source,
						    ubuf_data(it->key), ubuf_size(it->key),
						    ubuf_data(it->key2), ubuf_size(it->key2));
	}
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_raw(struct query_iter *it)
{
	it->key = ubuf_init(64);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata */
	ubuf_append(it->key, it->query->rdata, it->query->len_rdata);

	/* key: rrtype */
	if (it->query->do_rrtype)
		add_rrtype_to_key(it->key, it->query->rrtype);

	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

struct dnstable_iter *
dnstable_query_iter(struct dnstable_query *q, const struct mtbl_source *source)
{
	struct dnstable_iter *d_it;
	struct query_iter *it = my_calloc(1, sizeof(*it));
	it->query = q;
	it->source = source;
	if (q->q_type == DNSTABLE_QUERY_TYPE_RRSET) {
		d_it = query_init_rrset(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME) {
		d_it = query_init_rdata_name(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_IP) {
		d_it = query_init_rdata_ip(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW) {
		d_it = query_init_rdata_raw(it);
	} else {
		assert(0);
	}
	return (d_it);
}
