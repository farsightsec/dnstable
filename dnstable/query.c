/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012-2015, 2017-2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/socket.h>
#include <arpa/inet.h>

#include "libmy/my_byteorder.h"

#include "dnstable-private.h"

#include "libmy/ip_arith.h"
#include "libmy/hex_decode.h"

struct dnstable_query {
	dnstable_query_type	q_type;
	bool			do_rrtype, do_timeout;
	bool			do_time_first_before, do_time_first_after;
	bool			do_time_last_before, do_time_last_after;
	char			*err;
	wdns_name_t		name, bailiwick;
	uint32_t		rrtype;
	bool			aggregated;
	size_t			len_rdata, len_rdata2;
	uint8_t			*rdata, *rdata2;
	struct timespec		timeout;
	uint64_t		time_first_before, time_first_after;
	uint64_t		time_last_before, time_last_after;
	uint64_t		offset;
	bool			has_v_type;
	uint8_t			v_type;
};

struct query_iter {
	struct dnstable_query	*query;
	const struct mtbl_source *source_filter;
	const struct mtbl_source *source_index;
	const struct mtbl_source *source;
	struct mtbl_fileset	*fs_filter;
	struct mtbl_fileset	*fs_no_merge;
	struct mtbl_iter	*m_iter, *m_iter2;
	ubuf			*key, *key2;
};

static void
query_set_err(struct dnstable_query *q, const char *err)
{
	my_free(q->err);
	q->err = my_strdup(err);
}

static dnstable_res
query_load_name(struct dnstable_query *q, wdns_name_t *name, const char *s_name)
{
	my_free(name->data);
	name->len = 0;
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
	my_free(*addr);
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
	       q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW ||
	       q_type == DNSTABLE_QUERY_TYPE_TIME_RANGE ||
	       q_type == DNSTABLE_QUERY_TYPE_VERSION);
	struct dnstable_query *q = my_calloc(1, sizeof(*q));
	q->q_type = q_type;
	q->aggregated = true;
	return (q);
}

void
dnstable_query_destroy(struct dnstable_query **q)
{
	if (*q) {
		my_free((*q)->rdata);
		my_free((*q)->rdata2);
		my_free((*q)->name.data);
		my_free((*q)->bailiwick.data);
		my_free((*q)->err);
		my_free(*q);
	}
}

const char *
dnstable_query_get_error(struct dnstable_query *q) {
	if (q->err == NULL)
		q->err = my_strdup("unknown error");
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
	my_free(q->rdata);
	if (data == NULL)
		return (dnstable_res_success);
	return hex_decode(data, &q->rdata, &q->len_rdata);
}

static dnstable_res
query_set_data_rdata_ip_range(struct dnstable_query *q, const char *data)
{
	dnstable_res res = dnstable_res_failure;
	char *s = my_strdup(data);
	char *addr1, *addr2;
	char *saveptr = NULL;

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
	} else if (q->len_rdata == 16) {
		q->rrtype = WDNS_TYPE_AAAA;
	}
	res = dnstable_res_success;
out:
	my_free(s);
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

	s = my_strdup(data);
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
		my_free(q->rdata);
		my_free(q->rdata2);
		q->rdata = my_malloc(len_ip);
		q->rdata2 = my_malloc(len_ip);
		ip4_lower(ip, plen, q->rdata);
		ip4_upper(ip, plen, q->rdata2);
		res = dnstable_res_success;
	} else if (len_ip == 16) {
		q->do_rrtype = true;
		q->rrtype = WDNS_TYPE_AAAA;

		q->len_rdata = len_ip;
		q->len_rdata2 = len_ip;
		my_free(q->rdata);
		my_free(q->rdata2);
		q->rdata = my_malloc(len_ip);
		q->rdata2 = my_malloc(len_ip);
		ip6_lower(ip, plen, q->rdata);
		ip6_upper(ip, plen, q->rdata2);
		res = dnstable_res_success;
	}

out:
	if (res != dnstable_res_success)
		query_set_err(q, "unable to parse IP prefix");
	my_free(ip);
	my_free(s);
	return (res);
}

static dnstable_res
query_set_data_rdata_ip_address(struct dnstable_query *q, const char *data)
{
	my_free(q->rdata2);
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
		my_free(q->rdata);
		my_free(q->rdata2);
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

static dnstable_res
query_set_version_type(struct dnstable_query *q, const char *data)
{
	dnstable_res res;
	dnstable_entry_type type;

	if (data == NULL)
		return (dnstable_res_success);

	res = dnstable_entry_type_from_string(&type, data);
	if (res != dnstable_res_success)
		return res;

	switch(type) {
	case ENTRY_TYPE_RRSET:
	case ENTRY_TYPE_RRSET_NAME_FWD:
	case ENTRY_TYPE_RDATA:
	case ENTRY_TYPE_RDATA_NAME_REV:
		q->has_v_type = true;
		q->v_type = (uint8_t)type;
		return (dnstable_res_success);
	default:
		return (dnstable_res_failure);
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
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_VERSION) {
		return query_set_version_type(q, data);
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
	    strcasecmp(s_rrtype, "TYPE255") == 0 || /* ANY == TYPE255 */
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
dnstable_query_set_offset(struct dnstable_query *q, uint64_t offset)
{
	q->offset = offset;
	return (dnstable_res_success);
}

dnstable_res
dnstable_query_set_aggregated(struct dnstable_query *q, bool aggregated)
{
	q->aggregated = aggregated;
	return (dnstable_res_success);
}

dnstable_res
dnstable_query_set_timeout(struct dnstable_query *q, const struct timespec *timeout)
{
	if (timeout == NULL) {
		q->do_timeout = false;
		return (dnstable_res_success);
	}

	q->do_timeout = true;
	q->timeout = *timeout;

	return (dnstable_res_success);
}

#define set_filter_parameter(q, p_name, param, len_param) \
do { \
	if (param != NULL) { \
		(q)->do_##p_name = true; \
		memcpy(&(q)->p_name, param, len_param); \
	} else { \
		(q)->do_##p_name = false; \
	} \
} while (0)

dnstable_res
dnstable_query_set_filter_parameter(struct dnstable_query *q,
				    dnstable_filter_parameter_type p_type,
				    const void *param,
				    const size_t len_param)
{
	if (len_param != sizeof(uint64_t))
		return (dnstable_res_failure);

	switch (p_type) {
	case DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE:
		set_filter_parameter(q, time_first_before, param, len_param);
		return (dnstable_res_success);
	case DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER:
		set_filter_parameter(q, time_first_after, param, len_param);
		return (dnstable_res_success);
	case DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE:
		set_filter_parameter(q, time_last_before, param, len_param);
		return (dnstable_res_success);
	case DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER:
		set_filter_parameter(q, time_last_after, param, len_param);
		return (dnstable_res_success);
	default:
		return (dnstable_res_failure);
	}
}

dnstable_res
dnstable_query_filter(struct dnstable_query *q, struct dnstable_entry *e, bool *pass)
{
	dnstable_res res;
	uint16_t rrtype;

	if (q->do_rrtype || (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME)) {
		res = dnstable_entry_get_rrtype(e, &rrtype);
		if (res != dnstable_res_success)
			return (res);
	}

	if (q->do_rrtype) {
	       if (rrtype != q->rrtype)
		goto fail;
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME) {
		switch(rrtype) {
		case WDNS_TYPE_SOA:
		case WDNS_TYPE_NS:
		case WDNS_TYPE_CNAME:
		case WDNS_TYPE_DNAME:
		case WDNS_TYPE_PTR:
		case WDNS_TYPE_MX:
		case WDNS_TYPE_SRV:
		case WDNS_TYPE_SVCB:
		case WDNS_TYPE_HTTPS:
		case WDNS_TYPE_NSEC:
			break;
		default:
			goto fail;
		}
	}

	if (q->do_time_first_before || q->do_time_first_after) {
		uint64_t time_first;
		res = dnstable_entry_get_time_first(e, &time_first);
		if (res != dnstable_res_success)
			return (res);

		if (q->do_time_first_before && q->time_first_before < time_first)
			goto fail;
		if (q->do_time_first_after && q->time_first_after > time_first)
			goto fail;
	}

	if (q->do_time_last_before || q->do_time_last_after) {
		uint64_t time_last;
		res = dnstable_entry_get_time_last(e, &time_last);
		if (res != dnstable_res_success)
			return (res);

		if (q->do_time_last_before && q->time_last_before < time_last)
			goto fail;
		if (q->do_time_last_after && q->time_last_after > time_last)
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
	mtbl_fileset_destroy(&it->fs_filter);
	mtbl_fileset_destroy(&it->fs_no_merge);
	ubuf_destroy(&it->key);
	ubuf_destroy(&it->key2);
	my_free(it);
}

static void
add_rrtype_to_key(ubuf *key, uint32_t rrtype)
{
	assert(rrtype != WDNS_TYPE_ANY);
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), rrtype));
}

static dnstable_res
increment_key(ubuf *key, size_t pos)
{
	assert(pos < ubuf_size(key));
	for (uint8_t *ptr = ubuf_data(key) + pos; ptr >= ubuf_data(key); ptr--) {
		(*ptr)++;
		if (*ptr != 0) {
			return (dnstable_res_success);
		}
	}
	return (dnstable_res_failure);
}

static dnstable_res
query_iter_next(void *clos, struct dnstable_entry **ent)
{
	struct query_iter *it = (struct query_iter *) clos;
	struct timespec expiry = {0};

	if (it->query->do_timeout) {
		my_gettime(DNSTABLE__CLOCK_MONOTONIC, &expiry);
		my_timespec_add(&it->query->timeout, &expiry);
	}

	for (;;) {
		bool pass = false;
		dnstable_res res;
		const uint8_t *key, *val;
		size_t len_key, len_val;
		struct timespec now = {0};

		if (it->query->do_timeout) {
			my_gettime(DNSTABLE__CLOCK_MONOTONIC, &now);
			if (my_timespec_cmp(&now, &expiry) >= 0)
				return (dnstable_res_timeout);
		}

		if (it->source_filter != NULL) {
			if (mtbl_iter_next(it->m_iter2, &key, &len_key, &val, &len_val) != mtbl_res_success) {
				return (dnstable_res_failure);
			}
			if (it->query->do_rrtype) {
				uint16_t rrtype;
				struct dnstable_entry *e = dnstable_entry_decode(key, len_key, val, len_val);

				if (e == NULL)
					continue;

				res = dnstable_entry_get_rrtype(e, &rrtype);
				dnstable_entry_destroy(&e);

				if ((res != dnstable_res_success) || (rrtype != it->query->rrtype))
					continue;
			}
			/*
			 * When operating with a time filtered fileset, m_iter2 iterates over a
			 * subset of the keys of m_iter. Thus, we can seek m_iter to a key from
			 * m_iter2 and the next mtbl_iter_next call will return the same key.
			 */
			if (mtbl_iter_seek(it->m_iter, key, len_key) != mtbl_res_success) {
				return (dnstable_res_failure);
			}
		}

		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);

		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		if (*ent == NULL)
			continue;

		res = dnstable_query_filter(it->query, *ent, &pass);
		assert(res == dnstable_res_success);
		if (pass) {
			/* offset (e.g. skip) initial rows */
			if (it->query->offset > 0 && it->query->offset-- > 0)
			{
				dnstable_entry_destroy(ent);
				continue;
			}

			return (dnstable_res_success);
		} else {
			dnstable_entry_destroy(ent);
			continue;
		}
	}
	return (dnstable_res_failure);
}

static dnstable_res
query_iter_next_ip(void *clos, struct dnstable_entry **ent)
{
	struct query_iter *it = (struct query_iter *) clos;
	struct timespec expiry = {0};

	if (it->query->do_timeout) {
		my_gettime(DNSTABLE__CLOCK_MONOTONIC, &expiry);
		my_timespec_add(&(it->query->timeout), &expiry);
	}

	for (;;) {
		bool pass = false;
		dnstable_res res;
		const uint8_t *key, *val;
		size_t len_key, len_val;
		uint16_t rrtype;
		ubuf *seek_key;
		int ret;

		const uint8_t max_llen = 63;	/* RFC 1035 maximum label length in an uncompressed name. */

		if (it->query->do_timeout) {
			struct timespec now;
			my_gettime(DNSTABLE__CLOCK_MONOTONIC, &now);
			if (my_timespec_cmp(&now, &expiry) >= 0)
				return (dnstable_res_timeout);
		}

		if (it->source_filter != NULL) {
			if (mtbl_iter_next(it->m_iter2, &key, &len_key, &val, &len_val) != mtbl_res_success) {
				return (dnstable_res_failure);
			}
			/*
			 * When operating with a time filtered fileset, m_iter2 iterates over a
			 * subset of the keys of m_iter. Thus, we can seek m_iter to a key from
			 * m_iter2 and the next mtbl_iter_next call will return the same key.
			 */
			if (mtbl_iter_seek(it->m_iter, key, len_key) != mtbl_res_success) {
				return (dnstable_res_failure);
			}
		}

		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success) {
			return (dnstable_res_failure);
		}

		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		if (*ent ==  NULL)
			continue;

		/* Get the rrtype of the decoded entry. */
		res = dnstable_entry_get_rrtype(*ent, &rrtype);
		if (res != dnstable_res_success) {
			dnstable_entry_destroy(ent);
			continue;
		}

		if (rrtype == it->query->rrtype) {
			goto filter;
		}

		/* Destroy current entry; skip processing of wrong rrtype. */
		dnstable_entry_destroy(ent);

		/*
		 * Create a new start key in it->key2 (seek_key) with the prefix
		 * of the current entry's key, plus the target rrtype. This ends
		 * up being an IP address derived from the first 4 or 16 bytes
		 * of the current key's rdata, sandwiched between the entry
		 * type byte and the rrtype.
		 *
		 * This is helpful when the query rrtype is AAAA (28), which
		 * comes numerically after many common rrtypes.
		 */

		/* Prefix/range queries don't need key2 again after init. */
		if (it->key2 == NULL) {
			it->key2 = ubuf_init(ubuf_size(it->key));
		}
		seek_key = it->key2;
		ubuf_clip(seek_key, 0);
		size_t rrtype_len = mtbl_varint_length(it->query->rrtype);
		/* Prefix = ENTRY_TYPE_RDATA byte + rdata (no rrtype) */
		size_t key_prefix_len = ubuf_size(it->key) - rrtype_len;

		if (len_key < key_prefix_len) {
			/*
			 * If current key is shorter than a complete address
			 * rdata prefix, then the next possible start key is
			 * the zero-extended rdata address, followed by rrtype.
			 */
			ubuf_reserve(seek_key, key_prefix_len);
			ubuf_append(seek_key, key, len_key);
			memset(ubuf_data(seek_key) + len_key, 0,
			       key_prefix_len - len_key);
			ubuf_advance(seek_key, key_prefix_len - len_key);
			add_rrtype_to_key(seek_key, it->query->rrtype);

			goto seek;
		}

		ubuf_append(seek_key, key, key_prefix_len);
		add_rrtype_to_key(seek_key, it->query->rrtype);

		ret = bytes_compare(ubuf_data(seek_key), ubuf_size(seek_key),
					key, ubuf_size(seek_key));
		if (ret < 0) {
			/*
			 * If the start key sorts before the current key, the
			 * key bytes corresponding to the rrtype sort after the
			 * desired rrtype, meaning that we can move on to the
			 * next IP address.
			 *
			 * Increment the IP address portion of our key by one.
			 * The increment_key function will carry uint8_t
			 * overflows to the previous byte. For example,
			 * 10.1.255.255 will increment to 10.2.0.0.
			 */
			goto increment;
		} else if (ret > 0) {
			/* Seek to start key if it sorts after current key. */
			goto seek;
		}

		/* Now, for the fun part. */

		/*
		 * The current key has sufficient length for an address, and
		 * the bytes corresponding to the rrtype match the desired
		 * rrtype, but it is not a record of the desired rrtype.
		 *
		 * It might seem logical simply to increment the rdata address
		 * portion of the current key and seek to it, but that results
		 * in buggy behavior.
		 *
		 * Imagine that an rdata IP range traversal has been invoked
		 * for 192.168.1.0/24, and the CURRENT key is an IPv6 entry
		 * for c0a8:101:100::, the first 4 bytes of which match the
		 * address 192.168.1.1 (and the final byte of which matches
		 * the A rrtype byte). We cannot simply seek to the first
		 * subsequent rdata entry for 192.168.1.2 because there still
		 * may be 192.168.1.1 entries between the CURRENT key and
		 * where a seek to 192.168.1.2 would take us.
		 *
		 * Thus it is not safe simply to seek to the "next IP", but nor
		 * do we want to iterate needlessly to the next IP via the next
		 * MTBL key, which may take us through a very large collection
		 * of keys similar to our CURRENT key (most likely either many
		 * different IPv6 addresses which share the same first four
		 * bytes, or many records with an identical IPv6 address and
		 * different rrowner values).
		 *
		 * The solution is to determine the next possible start key
		 * for the current key, AS IF the current key were the correct
		 * rrtype. This means interpreting the bytes of the current key
		 * after the rrtype value as a potential rrowner name (even
		 * though they are something else). We can then increment the
		 * last "good" label value in order to derive the next valid
		 * theoretical start key.
		 */

		if (len_key == ubuf_size(seek_key)) {
			/* There's no more key data to copy. Move to next key. */
			continue;
		}

		/* Special case handling if the first byte is a bad label len */
		if (key[ubuf_size(seek_key)] > max_llen) {
			/* Get rid of trailing rrtype and increment address. */
			if (it->query->rrtype == WDNS_TYPE_A ||
			    it->query->rrtype == WDNS_TYPE_AAAA) {
				ubuf_clip(seek_key, key_prefix_len);
				goto increment;
			}
		}

		for (;;) {
			uint8_t llen = key[ubuf_size(seek_key)];

			/*
			 * Note: the ENTRY_TYPE_RDATA has 5 fields. We enter
			 * this loop with the first three encoded: type byte,
			 * rdata, and rrtype (varint). The remaining two are
			 * the RR owner name (in wire format), and the rdata
			 * length (16 bit fixed width).
			 */

			if (llen > max_llen) {
				/*
				 * We hit an invalid label length; if we found
				 * a good label previously, we should increment
				 * its last byte and seek to it.
				 */
				key_prefix_len = ubuf_size(seek_key);
				goto increment;
			} else if (llen == 0) {
				uint16_t rdlen;
				/*
				 * Our byte sequence looks like a series of DNS
				 * labels with llen being the terminating empty
				 * label. Append this label and the rdata length
				 * to form a complete rdata address entry.
				 */
				ubuf_reserve(seek_key, ubuf_size(seek_key) +
							1 + sizeof(rdlen));
				ubuf_add(seek_key, llen);
				switch (it->query->rrtype) {
				case WDNS_TYPE_A:
					rdlen = htole16(4);
					break;
				case WDNS_TYPE_AAAA:
					rdlen = htole16(16);
					break;
				default:
					assert(0);
				}
				ubuf_append(seek_key, (const uint8_t *)&rdlen,
							sizeof(rdlen));

				/* Seek to our key if it's after current key. */
				if (bytes_compare(ubuf_data(seek_key),
						  ubuf_size(seek_key),
							key, len_key) > 0) {
					goto seek;
				}

				/*
				 * There are no rdata entries with the same
				 * rdata address and rrowner after the current
				 * key. We trim the rdlen to increment the final
				 * label to seek to later-sorting rrowner vals.
				 */
				ubuf_clip(seek_key, ubuf_size(seek_key)
							- sizeof(rdlen));
				key_prefix_len = ubuf_size(seek_key);
				goto increment;
			}

			/*
			 * The current label length would extend the search key
			 * to be longer than the current key. We copy the rest
			 * of the bytes from the current key to the search key
			 * truncating the purported label and zero-fill the
			 * remainder of the purported label to advance the search.
			 */
			if (llen + 1 + ubuf_size(seek_key) > len_key) {
				size_t extra = llen + 1 + ubuf_size(seek_key) - len_key;
				ubuf_reserve(seek_key, llen + 1);
				ubuf_append(seek_key, &key[ubuf_size(seek_key)],
						len_key - ubuf_size(seek_key));
				memset(ubuf_ptr(seek_key), 0, extra);
				ubuf_advance(seek_key, extra);
				goto seek;
			}

			/* Append both the label length + data to seek key. */
			ubuf_reserve(seek_key, llen + 1 + ubuf_size(seek_key));
			ubuf_add(seek_key, llen);
			ubuf_append(seek_key, &key[ubuf_size(seek_key)], llen);
		}

increment:
		res = increment_key(seek_key, key_prefix_len - 1);

		/* Bail out if an increment overflow clobbers the type byte. */
		assert(res == dnstable_res_success);
		if (ubuf_value(seek_key, 0) != ENTRY_TYPE_RDATA) {
			mtbl_iter_destroy(&it->m_iter);
			return (dnstable_res_failure);
		}

seek:
		/* Seek to the newly generated key. */
		if (it->source_filter != NULL) {
			if (mtbl_iter_seek(it->m_iter2,
					   ubuf_data(seek_key),
				           ubuf_size(seek_key)) != mtbl_res_success) {
				return (dnstable_res_failure);
			}
		} else if (mtbl_iter_seek(it->m_iter,
				   ubuf_data(seek_key),
				   ubuf_size(seek_key)) != mtbl_res_success) {
			return (dnstable_res_failure);
		}

		/* Restart processing starting from the new key. */
		continue;

filter:
		res = dnstable_query_filter(it->query, *ent, &pass);
		assert(res == dnstable_res_success);
		if (pass) {
			/* offset (e.g. skip) initial rows */
			if (it->query->offset > 0 && it->query->offset-- > 0)
			{
				dnstable_entry_destroy(ent);
				continue;
			}

			return (dnstable_res_success);
		} else {
			dnstable_entry_destroy(ent);
			continue;
		}
	}
	return (dnstable_res_failure);
}

/* this assumes it is called on an entry type with possible new rrtype indexes */
static dnstable_res
query_iter_next_name_indirect(void *clos, struct dnstable_entry **ent, uint8_t type_byte)
{
	struct query_iter *it = (struct query_iter *) clos;
	const uint8_t *key, *val;
	size_t len_key, len_val;
	bool pass = false;
	dnstable_res res;
	struct timespec expiry = {0};

	if (it->query->do_timeout) {
		my_gettime(DNSTABLE__CLOCK_MONOTONIC, &expiry);
		my_timespec_add(&(it->query->timeout), &expiry);
	}

	for (;;) {
		struct timespec now = {0};

		if (it->query->do_timeout) {
			my_gettime(DNSTABLE__CLOCK_MONOTONIC, &now);
			if (my_timespec_cmp(&now, &expiry) >= 0)
				return (dnstable_res_timeout);
		}

		if (it->m_iter == NULL) {
			uint16_t wanted_rrtype = it->query->rrtype;

			if (mtbl_iter_next(it->m_iter2,
					   &key, &len_key,
					   &val, &len_val) != mtbl_res_success)
			{
				return (dnstable_res_failure);
			}

			/* use the new rrtype indexes */
			if (it->query->do_rrtype && !rrtype_test(type_byte, wanted_rrtype, val, len_val))
				continue;

			ubuf_clip(it->key, 0);
			ubuf_reserve(it->key, len_key + mtbl_varint_length(wanted_rrtype));
			ubuf_add(it->key, type_byte);
			if (wdns_reverse_name(key + 1, len_key - 1, ubuf_ptr(it->key))
			    != wdns_res_success)
				return (dnstable_res_failure);
			ubuf_advance(it->key, len_key - 1);
			if (it->query->do_rrtype &&
				(type_byte == ENTRY_TYPE_RRSET))
				add_rrtype_to_key(it->key, wanted_rrtype);
			else if (it->query->do_rrtype) {
				switch(wanted_rrtype) {
				case WDNS_TYPE_NS:
				case WDNS_TYPE_CNAME:
				case WDNS_TYPE_DNAME:
				case WDNS_TYPE_PTR:
				case WDNS_TYPE_MX:
				case WDNS_TYPE_SRV:
					add_rrtype_to_key(it->key, wanted_rrtype);
				}
			}
			it->m_iter = mtbl_source_get_prefix(it->source,
							    ubuf_data(it->key),
							    ubuf_size(it->key));
			if (it->m_iter == NULL)
				continue;
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
		if (*ent == NULL)
			continue;

		res = dnstable_query_filter(it->query, *ent, &pass);
		assert(res == dnstable_res_success);
		if (pass) {
			/* offset (e.g. skip) initial rows */
			if (it->query->offset > 0 && it->query->offset-- > 0)
			{
				dnstable_entry_destroy(ent);
				continue;
			}

			return (dnstable_res_success);
		} else {
			dnstable_entry_destroy(ent);
			continue;
		}
	}
	return (dnstable_res_failure);
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

static struct mtbl_iter *
query_get_iterator(struct query_iter *it, const struct mtbl_source *s)
{
	if (it->key2 != NULL)
		return mtbl_source_get_range(s, ubuf_data(it->key), ubuf_size(it->key),
					        ubuf_data(it->key2), ubuf_size(it->key2));

	return mtbl_source_get_prefix(s, ubuf_data(it->key), ubuf_size(it->key));
}

static void
query_init_iterators(struct query_iter *it)
{
	if (it->source_filter != NULL)
		it->m_iter2 = query_get_iterator(it, it->source_filter);

	it->m_iter = query_get_iterator(it, it->source);
}

static struct dnstable_iter *
query_init_rrset_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET_NAME_FWD);

	/* key: rrset owner name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	it->m_iter2 = mtbl_source_get_prefix(it->source_index,
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
	if (wdns_reverse_name(it->query->name.data + 2, len, name) != wdns_res_success)
		return (NULL);
	ubuf_append(it->key, name, len - 1);

	query_init_iterators(it);
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
	if (is_left_wildcard(&it->query->name))
		return query_init_rrset_left_wildcard(it);
	if (is_right_wildcard(&it->query->name))
		return query_init_rrset_right_wildcard(it);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET);

	/* key: rrset owner name (label-reversed) */
	if (wdns_reverse_name(it->query->name.data, it->query->name.len, name)
	    != wdns_res_success)
	{
		ubuf_destroy(&it->key);
		return (NULL);
	}
	ubuf_append(it->key, name, it->query->name.len);

	if (it->query->do_rrtype) {
		/* key: rrtype */
		add_rrtype_to_key(it->key, it->query->rrtype);

		if (it->query->bailiwick.data != NULL) {
			/* key: bailiwick name (label-reversed) */
			if (wdns_reverse_name(it->query->bailiwick.data,
					      it->query->bailiwick.len,
					      name)
			    != wdns_res_success)
			{
				ubuf_destroy(&it->key);
				return (NULL);
			}
			ubuf_append(it->key, name, it->query->bailiwick.len);
		}
	}

	query_init_iterators(it);
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	query_init_iterators(it);
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
	if (wdns_reverse_name(it->query->name.data + 2, len, name) != wdns_res_success)
		return (NULL);
	ubuf_append(it->key, name, len - 1);

	it->m_iter2 = mtbl_source_get_prefix(it->source_index,
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
	if (it->query->do_rrtype) {
		switch(it->query->rrtype) {
		case WDNS_TYPE_NS:
		case WDNS_TYPE_CNAME:
		case WDNS_TYPE_DNAME:
		case WDNS_TYPE_PTR:
		case WDNS_TYPE_MX:
		case WDNS_TYPE_SRV:
			add_rrtype_to_key(it->key, it->query->rrtype);
		}
	}

	query_init_iterators(it);
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

		/* key2: type byte, rdata2, rrtype */
		ubuf_add(it->key2, ENTRY_TYPE_RDATA);
		ubuf_append(it->key2, it->query->rdata2, it->query->len_rdata2);
		add_rrtype_to_key(it->key2, it->query->rrtype);

		/* increment key2 starting from the last byte */
		increment_key(it->key2, ubuf_size(it->key2) - 1);
	}

	query_init_iterators(it);

	return dnstable_iter_init(query_iter_next_ip, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_raw(struct query_iter *it)
{
	it->key = ubuf_init(64);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata */
	ubuf_append(it->key, it->query->rdata, it->query->len_rdata);

	/*
	 * Note: even though this function does not use it->query->do_rrtype
	 * or call add_rrtype_to_key(), in the post-query filter processing
	 * in dnstable_query_filter(), if do_rrtype is set then the results
	 * will be filtered by rrtype.
	 */
	query_init_iterators(it);
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_time_range(struct query_iter *it)
{
	it->key = ubuf_init(1);
	ubuf_add(it->key, ENTRY_TYPE_TIME_RANGE);
	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_version(struct query_iter *it)
{
	it->key = ubuf_init(1);
	ubuf_add(it->key, ENTRY_TYPE_VERSION);
	if (it->query->has_v_type)
		ubuf_add(it->key, it->query->v_type);
	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
dnstable_query_iter_common(struct query_iter *it)
{
	struct dnstable_iter *d_it;
	struct dnstable_query *q = it->query;

	if (q->q_type == DNSTABLE_QUERY_TYPE_RRSET) {
		d_it = query_init_rrset(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_NAME) {
		d_it = query_init_rdata_name(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_IP) {
		d_it = query_init_rdata_ip(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW) {
		d_it = query_init_rdata_raw(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_TIME_RANGE) {
		d_it = query_init_time_range(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_VERSION) {
		d_it = query_init_version(it);
	} else {
		assert(0);
	}
	if (d_it == NULL)
		query_iter_free(it);
	return (d_it);
}

struct dnstable_iter *
dnstable_query_iter(struct dnstable_query *q, const struct mtbl_source *source)
{
	struct query_iter *it = my_calloc(1, sizeof(*it));

	it->query = q;
	it->source = source;
	it->source_index = source;
	return dnstable_query_iter_common(it);
}

/*
 * dnstable_dupsort_func is used to sort the entries with duplicate
 * keys during the merge process based on their data.  The dnstable
 * data is a triplet of variable-length integers, so (in theory) the
 * byte comparison used for keys would not suffice.  This is mostly of
 * interest with a NULL merge function, although it could be used to
 * enforce some order of merges with a non-NULL merge function.
 *
 * This sorts first by time_first, then by time_last if time_first is the same.
 */
static int
dnstable_dupsort_func(void *clos,
		      const uint8_t *key, size_t len_key,
		      const uint8_t *val0, size_t len_val0,
		      const uint8_t *val1, size_t len_val1)
{
	uint64_t time_first0, time_last0, count0;
	uint64_t time_first1, time_last1, count1;

	if (len_key && (key[0] == ENTRY_TYPE_RRSET ||
			key[0] == ENTRY_TYPE_RDATA))
	{
		assert(len_val0 && len_val1);
		dnstable_res res;

		res = triplet_unpack(val0, len_val0, &time_first0, &time_last0, &count0);
		assert(res == dnstable_res_success);
		res = triplet_unpack(val1, len_val1, &time_first1, &time_last1, &count1);
		assert(res == dnstable_res_success);

		if (time_first0 < time_first1)
			return -1;
		if (time_first0 > time_first1)
			return 1;
		if (time_last0 < time_last1)
			return -1;
		if (time_last0 > time_last1)
			return 1;
		return 0;
	} else
		return 0;
}

static bool
reader_time_filter(struct mtbl_reader *r, void *clos)
{
	struct dnstable_query *q = clos;
	struct dnstable_query *tr_q = dnstable_query_init(DNSTABLE_QUERY_TYPE_TIME_RANGE);
	struct dnstable_iter *tr_it = dnstable_query_iter(tr_q, mtbl_reader_source(r));
	struct dnstable_entry *tr_e = NULL;
	uint64_t min_time_first, max_time_last;
	bool res = true;

	if (tr_it == NULL) goto out;

	if (dnstable_iter_next(tr_it, &tr_e) != dnstable_res_success) {
		goto out;
	}

	if ((dnstable_entry_get_time_first(tr_e, &min_time_first) != dnstable_res_success) ||
	    (dnstable_entry_get_time_last(tr_e, &max_time_last) != dnstable_res_success)) {
		goto out;
	}

	/*
	 * #1. If the current reader has only data observed before our
	 * time_first_after cutoff, the resulting merged entries will
	 * fail our time_first_after filter. Ignore for the filter pass.
	 */
	if (q->do_time_first_after && (q->time_first_after > max_time_last))
		res = false;

	/*
	 * #2. If the current reader has no data with time_last after our
	 * time_last_after cutoff, it will not cause any merged results
	 * to pass our time_last_after filter. Ignore for the filter pass.
	 */
	if (q->do_time_last_after && (q->time_last_after > max_time_last))
		res = false;

	/*
	 * #3. Like with time_first_after (#1), if the current reader has only
	 * data observed after the time_last_before cutoff, the resulting merged
	 * entries will fail our time_last_before filter. Ignore for the filter
	 * pass.
	 */
	if (q->do_time_last_before && (q->time_last_before < min_time_first))
		res = false;

	/*
	 * #4. If the current reader contains no data with time_first before
	 * our time_first_before cutoff, it will not cause any merged
	 * entries to match our time_first_before filter. Ignore for the
	 * filter pass UNLESS a time_last_after filter needs the data.
	 *
	 * Note that the time_first_after (#1) and time_last_before (#3)
	 * tests above exclude readers whose data is sufficient to show
	 * an entry does not match the respective test, and thus will not
	 * match the combined time filter.
	 *
	 * In contrast, the time_last_after (#2) and time_first_before (#4)
	 * tests exclude readers whose data will not establish a match for
	 * the respective test, but may be needed to establish a match for
	 * the other test. Thus, if both tests are active, we choose one
	 * to use to exclude readers for the filter pass.
	 */
	if (q->do_time_first_before && !q->do_time_last_after &&
	    (q->time_first_before < min_time_first))
		res = false;

out:
	dnstable_entry_destroy(&tr_e);
	dnstable_iter_destroy(&tr_it);
	dnstable_query_destroy(&tr_q);
	return res;
}

struct dnstable_iter *
dnstable_query_iter_fileset(struct dnstable_query *q, struct mtbl_fileset *fs)
{
	struct query_iter *it = my_calloc(1, sizeof(*it));
	struct mtbl_fileset_options *fopt;

	it->query = q;
	it->source = mtbl_fileset_source(fs);
	it->source_index = it->source;

	fopt = mtbl_fileset_options_init();
	mtbl_fileset_options_set_merge_func(fopt, dnstable_merge_func, NULL);

	/*
	 * For queries with time filtering, we create a filtered fileset
	 * containing only the set of files in which matching entries or parts
	 * of matching entries will be present. We use this fileset for index
	 * (indirect) queries and to filter candidates for direct queries.
	 */
	if (q->do_time_first_before || q->do_time_first_after ||
	    q->do_time_last_before || q->do_time_last_after) {
		mtbl_fileset_options_set_reader_filter_func(fopt, reader_time_filter, q);
		it->fs_filter = mtbl_fileset_dup(fs, fopt);
		it->source_index = mtbl_fileset_source(it->fs_filter);
		it->source_filter = it->source_index;
	}

	/*
	 * If the query requests unaggregated results, we create a fileset
	 * with no merge function and use it as the source for final results.
	 * The merged index fileset source remains in place to avoid duplicate
	 * results for queries involving indexes.
	 *
	 * If combined with time filtering, the unaggregated fileset will also
	 * be time filtered, which takes the place of the filtered source.
	 */
	if (!q->aggregated) {
		/* Note the reader_filter_func set above remains in effect here. */
		mtbl_fileset_options_set_merge_func(fopt, NULL, NULL);
		mtbl_fileset_options_set_dupsort_func(fopt, dnstable_dupsort_func, NULL);
		it->fs_no_merge = mtbl_fileset_dup(fs, fopt);
		it->source = mtbl_fileset_source(it->fs_no_merge);
		it->source_filter = NULL;
	}

	mtbl_fileset_options_destroy(&fopt);
	return dnstable_query_iter_common(it);
}
