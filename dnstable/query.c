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

/*
 * All rrtypes whose dnstable-encoded rdata consist of a single name component.
 * In other words, their encoding in the MTBL key ensures that they are followed
 * immediately by an rrtype, allowing for the creation of a specific key prefix.
 * This includes sliced encoding of rdata where the name is the terminal field.
 */
#define CASE_RDATA_NAME_TYPE_STANDALONE	\
	case WDNS_TYPE_MX:	/* when sliced */	\
	case WDNS_TYPE_SRV:	/* when sliced */	\
	case WDNS_TYPE_NS:	\
	case WDNS_TYPE_CNAME:	\
	case WDNS_TYPE_DNAME:	\
	case WDNS_TYPE_PTR
/*
 * Every rrtype where the rdata field of its dnstable-encoded (ENTRY_TYPE_RDATA)
 * key begins with a hostname.
 */
#define CASE_RDATA_NAME_TYPE_ALL	\
	CASE_RDATA_NAME_TYPE_STANDALONE:	\
	case WDNS_TYPE_SOA:	\
	case WDNS_TYPE_SVCB:	\
	case WDNS_TYPE_HTTPS:	\
	case WDNS_TYPE_NSEC:	\
	case WDNS_TYPE_RP:	\
	case WDNS_TYPE_NXT

struct dnstable_query {
	dnstable_query_type	q_type;
	bool			do_rrtype, do_timeout, do_deadline;
	uint32_t		rrtype;
	struct timespec		timeout, deadline;
	bool			aggregated, case_sensitive;
	bool			dq_wildplus;		/* '+' wildcard? */
	bool			do_time_first_before, do_time_first_after;
	bool			do_time_last_before, do_time_last_after;
	uint64_t		time_first_before, time_first_after;
	uint64_t		time_last_before, time_last_after;
	char			*err;
	wdns_name_t		name, bailiwick;	/* bailiwick is reversed */
	uint8_t			len_ip1, len_ip2;
	uint8_t			ip1[16], ip2[16];
	size_t			len_rdata;
	uint8_t			*rdata;
	uint64_t		offset;
	bool			has_v_type;
	uint8_t			v_type;
};

struct query_iter {
	struct dnstable_query	*query;
	/*
	 * These two sources are the same except in the case of unaggregated or
	 * time-filtered fileset queries. Even when they contain the same underlying
	 * files, different filters may be applied to them depending on the query
	 * configuration (e.g. rrtype restrictions, single-label wildcard lookups).
	 */
	const struct mtbl_source *source, *source_index;

	/* Pertinent to fileset-based sources */
	struct mtbl_fileset	*fs_filter;	/* time-filtered fileset */
	struct ljoin_mtbl	*ljoin;		/* wraps fill merger */
	struct mtbl_merger	*fill_merger;	/* for aggregated, time-fenced queries */
	struct remove_mtbl	*remove_strict;	/* for aggregated + strict time filtering */
	struct mtbl_fileset	*fs_no_merge;	/* fileset for un-aggregated queries */

	struct timespec		deadline;	/* derived from query->timeout */
	jmp_buf			to_env;
	/* Basically the same, but each applies to either source or source_index */
	struct timeout_mtbl	*timeout, *timeout_index;

	/* m_iter2 for indirect queries: left wildcard rrset or right WC rdata */
	struct mtbl_iter	*m_iter, *m_iter2;
	ubuf			*key, *key2;	/* key2 is a tmp value holder */

	/*
	 * The following filters are applied in the order they are declared,
	 * and they are also evaluated in the order they are declared, meaning
	 * that filter_offset is run only at the end of processing.
	 */
	struct filter_mtbl	*filter_single_label;	/* rrset+rdata wildcard */
	/* Can be filter_rrtype(), filter_rrtype_ip(), or filter_rrtype_rdata_name() */
	struct filter_mtbl	*filter_rrtype;
	struct filter_mtbl	*filter_bailiwick;
	struct filter_mtbl	*filter_time_prefilter;
	/* remove_strict and possibly ljoin applied in between the time filters. */
	struct filter_mtbl	*filter_time;
	struct filter_mtbl	*filter_offset;
	struct {
		uint64_t fileset_merged;
		uint64_t fileset_files;
		uint64_t fill_merged;
		uint64_t fill_files;
	} stats;
};

static void
query_set_err(struct dnstable_query *q, const char *err)
{
	my_free(q->err);
	q->err = my_strdup(err);
}

static dnstable_res
query_load_name(struct dnstable_query *q, wdns_name_t *name, const char *s_name, bool case_sensitive)
{
	my_free(name->data);
	name->len = 0;
	if (s_name == NULL)
		return (dnstable_res_success);
	if (wdns_str_to_name_case(s_name, name) != wdns_res_success) {
		query_set_err(q, "wdns_str_to_name() failed");
		return (dnstable_res_failure);
	}
	if (!case_sensitive)
		wdns_downcase_name(name);
	return (dnstable_res_success);
}

static dnstable_res
query_load_address(struct dnstable_query *q, const char *data, uint8_t addr[16], uint8_t *len_addr)
{
	*len_addr = 0;
	if (inet_pton(AF_INET, data, addr) == 1) {
		*len_addr = 4;
		return (dnstable_res_success);
	} else if (inet_pton(AF_INET6, data, addr) == 1) {
		*len_addr = 16;
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
	q->case_sensitive = false;
	return (q);
}

void
dnstable_query_destroy(struct dnstable_query **q)
{
	if (*q) {
		my_free((*q)->rdata);
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
dnstable_query_set_case_sensitive(struct dnstable_query *q, bool case_sensitive)
{
	q->case_sensitive = case_sensitive;
	return (dnstable_res_success);
}

dnstable_res
dnstable_query_set_bailiwick(struct dnstable_query *q, const char *s_name)
{
	dnstable_res res;
	uint8_t *rev;
	if (q->q_type != DNSTABLE_QUERY_TYPE_RRSET) {
		query_set_err(q, "bailiwick filtering not supported");
		return (dnstable_res_failure);
	}
	res = query_load_name(q, &q->bailiwick, s_name, false);
	if (res != dnstable_res_success || q->bailiwick.data == NULL)
		return res;
	rev = my_malloc(q->bailiwick.len);
	if (wdns_reverse_name(q->bailiwick.data, q->bailiwick.len, rev) != wdns_res_success) {
		my_free(rev);
		return (dnstable_res_failure);
	}
	my_free(q->bailiwick.data);
	q->bailiwick.data = rev;
	return (dnstable_res_success);
}

static dnstable_res
query_set_data_rrset_owner(struct dnstable_query *q, const char *s_name)
{
	return query_load_name(q, &q->name, s_name, q->case_sensitive);
}

static dnstable_res
query_set_data_rdata_name(struct dnstable_query *q, const char *s_name)
{
	return query_load_name(q, &q->name, s_name, q->case_sensitive);
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

	if (!query_load_address(q, addr1, q->ip1, &q->len_ip1)) goto out;
	if (!query_load_address(q, addr2, q->ip2, &q->len_ip2)) goto out;
	if (q->len_ip1 != q->len_ip2) {
		query_set_err(q, "address family mismatch in IP range");
		goto out;
	}
	q->do_rrtype = true;
	if (q->len_ip1 == 4) {
		q->rrtype = WDNS_TYPE_A;
	} else if (q->len_ip1 == 16) {
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
	uint8_t ip[16];
	uint8_t len_ip;
	char *address, *prefix_length;
	char *saveptr, *endptr;
	long plen;

	s = my_strdup(data);
	assert(s != NULL);
	if ((address = strtok_r(s, "/", &saveptr)) == NULL) goto out;
	if ((prefix_length = strtok_r(NULL, "/", &saveptr)) == NULL) goto out;
	if (strtok_r(NULL, "/", &saveptr) != NULL) goto out;

	if (!query_load_address(q, address, ip, &len_ip)) goto out;

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

		q->len_ip1 = len_ip;
		q->len_ip2 = len_ip;
		ip4_lower(ip, plen, q->ip1);
		ip4_upper(ip, plen, q->ip2);
		res = dnstable_res_success;
	} else if (len_ip == 16) {
		q->do_rrtype = true;
		q->rrtype = WDNS_TYPE_AAAA;

		q->len_ip1 = len_ip;
		q->len_ip2 = len_ip;
		ip6_lower(ip, plen, q->ip1);
		ip6_upper(ip, plen, q->ip2);
		res = dnstable_res_success;
	}

out:
	if (res != dnstable_res_success)
		query_set_err(q, "unable to parse IP prefix");
	my_free(s);
	return (res);
}

static dnstable_res
query_set_data_rdata_ip_address(struct dnstable_query *q, const char *data)
{
	q->len_ip2 = 0;
	if (!query_load_address(q, data, q->ip1, &q->len_ip1))
		return (dnstable_res_failure);
	q->do_rrtype = true;
	if (q->len_ip1 == 4)
		q->rrtype = WDNS_TYPE_A;
	else if (q->len_ip1 == 16)
		q->rrtype = WDNS_TYPE_AAAA;
	return (dnstable_res_success);
}

static dnstable_res
query_set_data_rdata_ip(struct dnstable_query *q, const char *data)
{
	if (data == NULL) {
		q->len_ip1 = 0;
		q->len_ip2 = 0;
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

dnstable_res
dnstable_query_set_deadline(struct dnstable_query *q, const struct timespec *deadline)
{
	if (deadline == NULL) {
		q->do_deadline = false;
		return (dnstable_res_success);
	}

	q->do_deadline = true;
	q->deadline = *deadline;
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

/*
 * Run a series of optionally-set query filters against an entry in this order:
 * rrtype matching, time-fencing, and finally bailiwick verification for rrsets.
 */
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
		CASE_RDATA_NAME_TYPE_ALL:
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
		uint8_t rev[WDNS_MAXLEN_NAME];
		size_t len_bailiwick;
		res = dnstable_entry_get_bailiwick(e, &bailiwick, &len_bailiwick);
		if (res != dnstable_res_success)
			return (res);
		if (q->bailiwick.len != len_bailiwick)
			goto fail;
		if (wdns_reverse_name(bailiwick, len_bailiwick, rev) != wdns_res_success)
			goto fail;
		if (memcmp(q->bailiwick.data, rev, len_bailiwick) != 0)
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
	ljoin_mtbl_destroy(&it->ljoin);
	mtbl_fileset_destroy(&it->fs_filter);
	mtbl_fileset_destroy(&it->fs_no_merge);
	mtbl_merger_destroy(&it->fill_merger);
	timeout_mtbl_destroy(&it->timeout);
	timeout_mtbl_destroy(&it->timeout_index);
	filter_mtbl_destroy(&it->filter_single_label);
	filter_mtbl_destroy(&it->filter_rrtype);
	filter_mtbl_destroy(&it->filter_bailiwick);
	filter_mtbl_destroy(&it->filter_time_prefilter);
	filter_mtbl_destroy(&it->filter_time);
	filter_mtbl_destroy(&it->filter_offset);
	remove_mtbl_destroy(&it->remove_strict);
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

/*
 * Used with a "single label" wildcard search to match keys beginning
 * with the search prefix plus a single label.
 *
 * If the key doesn't match, seek to a prefix of the next possible matching key.
 */
static mtbl_res
filter_single_label(void *user, struct mtbl_iter *seek_iter,
		    const uint8_t *key, size_t len_key,
		    const uint8_t *val, size_t len_val,
		    bool *match)
{
	struct query_iter *it = user;
	size_t qks, next_len;
	ubuf *seek_key;

	(void)val;
	(void)len_val;
	*match = false;

	/*
	 * For left-wildcard, the "key" in the query is label-reversed, and the wildcard char is removed.
	 * e.g. For rrset "+.example.com", the key will be:
	 *   \x00\x03com\x07example
	 *
	 * For right-wildcard, the labels are in the original order (and the wildchar char is removed).
	 *
	 * The key that has been found (and is being checked here) will start with these
	 * same bytes, and should have at the very least a trailing length-byte as well.
	 */
	qks = ubuf_size(it->key);		/* Byte-size of original key. */

	if (qks >= len_key)
		return (mtbl_res_success);

	/*
	 * No more labels on this key.
	 *   \x00\x03com\x07example\x00
	 */
	if (key[qks] == '\0') {
		/*
		 * Now skip all keys where the leading-part is the same as this key.
		 * e.g. seek to key
		 *   \x00\x03com\x07example\x01
		 */
		next_len = qks + 1;
		goto seek;
	}

	/* From here, there is at least one more label. */

	/* The position of the "length" byte after the first extra label. */
	next_len = qks + key[qks] + 1;

	/*
	 * If the key is malformed, treat it as if there are no more labels.
	 *
	 * Bad: \x00\x03com\x07example\x03ns
	 */
	if (next_len >= len_key)
		return (mtbl_res_success);

	/*
	 * Key has one or more additional labels.
	 * If more than one, then skip all keys that have that same first additional label.
	 *
	 *  One: \x00\x03com\x07example\x03foo\x00
	 * Seek: \x00\x03com\x07example\x03foo\x03bar\x00
	 */

	if (key[next_len] == '\0') {	/* Only 1 additional label. */
		*match = true;
		return (mtbl_res_success);
	}

seek:
	/*
	 * Create a new key that is just beyond a key containing one extra label.
	 *   \x00\x03com\x07example\x03fop
	 */
	if (it->key2 == NULL)
		it->key2 = ubuf_init(next_len);
	seek_key = it->key2;
	ubuf_clip(seek_key, 0);

	ubuf_reserve(seek_key, next_len);
	ubuf_append(seek_key, key, next_len);

	/* Advance the last byte of the new key. */
	increment_key(seek_key, next_len - 1);

	/* Seek to the newly generated key. */
	return mtbl_iter_seek(seek_iter,
				ubuf_data(seek_key),
				ubuf_size(seek_key));

}

static mtbl_res
filter_rrtype(void *user, struct mtbl_iter *seek_iter,
	      const uint8_t *key, size_t len_key,
	      const uint8_t *val, size_t len_val,
	      bool *match)
{
	struct query_iter *it = user;
	size_t len;
	uint16_t rdlen;
	uint32_t rrtype;

	(void)seek_iter;
	(void)val;
	(void)len_val;

	*match = false;
	switch(key[0]) {
	case ENTRY_TYPE_RRSET:
		if (wdns_len_uname(&key[1], &key[len_key], &len) != wdns_res_success)
			return (mtbl_res_success);
		if (len + 2 >= len_key)
			return (mtbl_res_success);

		break;
	case ENTRY_TYPE_RDATA:
		if (len_key < sizeof(rdlen))
			return (mtbl_res_success);

		memcpy(&rdlen, &key[len_key - sizeof(rdlen)], sizeof(rdlen));
		rdlen = le16toh(rdlen);
		if ((size_t)rdlen + 2 >= len_key)
			return (mtbl_res_success);

		len = rdlen;
		break;
	default:
		assert(0);
	}

	if (mtbl_varint_decode32(&key[len+1], &rrtype) == 0)
		return (mtbl_res_success);

	if (rrtype == it->query->rrtype)
		*match = true;

	return(mtbl_res_success);
}

/*
 * filter_rrtype_rdata_name passes rdata entries with types whose
 * rdata format begin with a domain name, or a domain name at a
 * fixed offset used for "slice" encoding. This prevents rdata name
 * searches from returning non-name (e.g. NULL, IPv6) records.
 */
static mtbl_res
filter_rrtype_rdata_name(void *user, struct mtbl_iter *seek_iter,
			 const uint8_t *key, size_t len_key,
			 const uint8_t *val, size_t len_val,
			 bool *match)
{
	size_t len;
	uint16_t rdlen;
	uint32_t rrtype;

	(void)user;
	*match = false;
	if (len_key < sizeof(rdlen))
		return (mtbl_res_success);

	memcpy(&rdlen, &key[len_key - sizeof(rdlen)], sizeof(rdlen));
	rdlen = le16toh(rdlen);
	if ((size_t)rdlen + 2 >= len_key)
		return (mtbl_res_success);

	len = rdlen;
	mtbl_varint_decode32(&key[len+1], &rrtype);

	switch(rrtype) {
	CASE_RDATA_NAME_TYPE_ALL:
		*match = true;
	}

	return mtbl_res_success;
}

static mtbl_res
filter_bailiwick(void *user, struct mtbl_iter *seek_iter,
		 const uint8_t *key, size_t len_key,
		 const uint8_t *val, size_t len_val,
		 bool *match)
{
	struct query_iter *it = user;
	struct dnstable_query *q = it->query;
	size_t len, len_name;
	uint32_t rrtype;

	*match = false;
	if (wdns_len_uname(&key[1], &key[len_key], &len) != wdns_res_success)
		return (mtbl_res_success);
	if (len + 2 >= len_key)
		return (mtbl_res_success);

	len ++;
	len += mtbl_varint_decode32(&key[len], &rrtype);
	if (len >= len_key)
		return (mtbl_res_success);

	if (wdns_len_uname(&key[len], &key[len_key], &len_name) != wdns_res_success)
		return (mtbl_res_success);

	if (len_name != q->bailiwick.len)
		return (mtbl_res_success);

	if (!memcmp(q->bailiwick.data, &key[len], len_name))
		*match = true;

	return (mtbl_res_success);
}

static mtbl_res
filter_time_common(struct dnstable_query *q, bool prefilter,
		   const uint8_t *val, size_t len_val,
		   bool *match)
{
	dnstable_res dres;
	uint64_t time_first, time_last, count;

	*match = false;

	dres = triplet_unpack(val, len_val, &time_first, &time_last, &count);
	if (dres != dnstable_res_success)
		return (mtbl_res_success);

	/*
	 * Checks 1-4 below correspond to steps 1,3,2,4 in reader_time_filter()
	 * except these accomplish on a per-entry basis roughly what that
	 * other function does on a per-dnstable source basis.
	 */

	/* #1. A strict filtering check that always produces failure. */
	if (q->do_time_first_after && (time_first < q->time_first_after))
		return (mtbl_res_success);

	/* #2. Another strict filtering check that always produces failure. */
	if (q->do_time_last_before && (time_last > q->time_last_before))
		return (mtbl_res_success);

	/*
	 * #3. If NOT pre-filtering, then this evaluation occurs AFTER the
	 *     completion of any merging, and the final result obviously
	 *     fails to satisfy the time fence criteria.
	 *
	 *     But when pre-filtering, any sources from filesets containing data
	 *     that cannot meet these two conditions alone but that MIGHT satisfy
	 *     them post-merger have already been diverted to the fill merger.
	 *     In other words, during the pre-filtering stage we return false in
	 *     the cases where associated data might be found in fill_merger.
	 */
	if (q->do_time_last_after && (time_last < q->time_last_after))
		return (mtbl_res_success);

	/*
	 * #4. When pre-filtering, this complements the final conditional in the
	 * file selection logic in reader_time_filter().
	 */
	if (q->do_time_first_before && (time_first > q->time_first_before))
		*match = prefilter && q->do_time_last_after;
	else
		*match = true;

	return (mtbl_res_success);
}

/*
 * filter_time_prefilter provides a filter removing partially merged entries
 * to save further merges. Entries may be removed at this stage if they have
 * either:
 *  1. failed "strict" time_first_after or time_last_before tests, which will
 *     cause any further merged results to do the same, or
 *  2. failed "loose" time_first_before or time_last_after tests which, since
 *     the input to this filter is constructed so that no data deferred for later
 *     merging will cause the time_first_before or time_last_after test to
 *     succeed, is sufficient to exclude the entry from further consideration.
 */
static mtbl_res
filter_time_prefilter(void *user, struct mtbl_iter *seek_iter,
		      const uint8_t *key, size_t len_key,
		      const uint8_t *val, size_t len_val,
		      bool *match)
{
	struct query_iter *it = user;
	return filter_time_common(it->query, true, val, len_val, match);
}

static mtbl_res
filter_time(void *user, struct mtbl_iter *seek_iter,
	    const uint8_t *key, size_t len_key,
	    const uint8_t *val, size_t len_val,
	    bool *match)
{
	struct query_iter *it = user;

	return filter_time_common(it->query, false, val, len_val, match);
}

static mtbl_res
filter_offset(void *user, struct mtbl_iter *seek_iter,
	      const uint8_t *key, size_t len_key,
	      const uint8_t *val, size_t len_val,
	      bool *match)
{
	struct query_iter *it = user;
	struct dnstable_query *q = it->query;

	*match = true;
	if (q->offset > 0) {
		*match = false;
		q->offset--;
	}
	return (mtbl_res_success);
}

/*
 * Set a timeout for the earliest between whichever happens to come first,
 * an optionally set relative timeout, or an optionally set absolute deadline.
 */
static void
query_iter_set_deadline(struct query_iter *it)
{
	struct dnstable_query *q = it->query;

	if (!q->do_timeout) {
		it->deadline = q->deadline;
		return;
	}

	my_gettime(DNSTABLE__CLOCK_MONOTONIC, &it->deadline);
	my_timespec_add(&q->timeout, &it->deadline);
	if (q->do_deadline && my_timespec_cmp(&q->deadline, &it->deadline) < 0) {
		it->deadline = q->deadline;
	}
}

static dnstable_res
query_iter_next(void *clos, struct dnstable_entry **ent)
{
	struct query_iter *it = (struct query_iter *) clos;
	struct dnstable_query *q = it->query;

	if (q->do_timeout || q->do_deadline) {
		query_iter_set_deadline(it);
		if (setjmp(it->to_env) != 0)
			return (dnstable_res_timeout);
	}

	for (;;) {
		const uint8_t *key, *val;
		size_t len_key, len_val;

		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);

		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		if (*ent == NULL)
			continue;

		return (dnstable_res_success);
	}

	return (dnstable_res_failure);
}

static dnstable_res
get_counter(uint64_t filtered, uint64_t merged, uint64_t seek, uint64_t files,
	    dnstable_stat_category category, uint64_t *count)
{
	uint64_t values[] = {
		[DNSTABLE_STAT_CATEGORY_FILTERED] = filtered,
		[DNSTABLE_STAT_CATEGORY_MERGED] = merged,
		[DNSTABLE_STAT_CATEGORY_SEEK] = seek,
		[DNSTABLE_STAT_CATEGORY_FILES] = files,
	};

	if (category < 0 || category >= sizeof(values)/sizeof(values[0]))
		return (dnstable_res_failure);

	*count = values[category];
	return (dnstable_res_success);
}

static dnstable_res
query_iter_get_count(const void *v,
		     dnstable_stat_stage stage,
		     dnstable_stat_category category,
		     bool *exists,
		     uint64_t *count)
{
	bool exists_local = false;
	const struct query_iter *it = v;
	bool scratch;

	if (exists == NULL)
		exists = &exists_local;

	switch(stage) {
	case DNSTABLE_STAT_STAGE_FILESET:
		*exists = (category == DNSTABLE_STAT_CATEGORY_MERGED) ||
			  (category == DNSTABLE_STAT_CATEGORY_FILES);
		return get_counter(0, it->stats.fileset_merged, 0, it->stats.fileset_files, category, count);
	case DNSTABLE_STAT_STAGE_FILTER_SINGLE_LABEL:
		return filter_mtbl_get_counter(it->filter_single_label, category, exists, count);
	case DNSTABLE_STAT_STAGE_FILTER_RRTYPE:
		return filter_mtbl_get_counter(it->filter_rrtype, category, exists, count);
	case DNSTABLE_STAT_STAGE_FILTER_BAILIWICK:
		*exists = (category == DNSTABLE_STAT_CATEGORY_FILTERED);
		*exists = *exists && (it->filter_bailiwick != NULL);
		return filter_mtbl_get_counter(it->filter_bailiwick, category, &scratch, count);
	case DNSTABLE_STAT_STAGE_FILTER_TIME_PREFILTER:
		*exists = (category == DNSTABLE_STAT_CATEGORY_FILTERED);
		*exists = *exists && (it->filter_time_prefilter != NULL);
		return filter_mtbl_get_counter(it->filter_time_prefilter, category, &scratch, count);
	case DNSTABLE_STAT_STAGE_REMOVE_STRICT:
		return remove_mtbl_get_counter(it->remove_strict, category, exists, count);
	case DNSTABLE_STAT_STAGE_FILL_MERGER:
		*exists = (category == DNSTABLE_STAT_CATEGORY_MERGED) ||
			  (category == DNSTABLE_STAT_CATEGORY_FILES);
		*exists = *exists && (it->fill_merger != NULL);
		return get_counter(0, it->stats.fill_merged, 0, it->stats.fill_files, category, count);
	case DNSTABLE_STAT_STAGE_LJOIN:
		return ljoin_mtbl_get_counter(it->ljoin, category, exists, count);
	case DNSTABLE_STAT_STAGE_FILTER_TIME:
		*exists = (category == DNSTABLE_STAT_CATEGORY_FILTERED);
		*exists = *exists && (it->filter_time != NULL);
		return filter_mtbl_get_counter(it->filter_time, category, &scratch, count);
	case DNSTABLE_STAT_STAGE_FILTER_OFFSET:
		*exists = (category == DNSTABLE_STAT_CATEGORY_FILTERED);
		*exists = *exists && (it->filter_offset != NULL);
		return filter_mtbl_get_counter(it->filter_offset, category, &scratch, count);
	default:
		break;
	}

	return dnstable_res_failure;
}

static mtbl_res
filter_rrtype_ip(void *user, struct mtbl_iter *seek_iter,
		 const uint8_t *key, size_t len_key,
		 const uint8_t *val, size_t len_val,
		 bool *match)
{
	struct query_iter *it = (struct query_iter *) user;
	mtbl_res res;

	res = filter_rrtype(it, NULL, key, len_key, val, len_val, match);
	if (res != mtbl_res_success || *match)
		return res;

	/* Note that *match is false here. We optionally seek below to skip more non-matches. */
	do {
		dnstable_res dres;
		ubuf *seek_key;
		int ret;

		const uint8_t max_llen = 63;	/* RFC 1035 maximum label length in an uncompressed name. */

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

		if (len_key <= ubuf_size(seek_key)) {
			/* There's no more key data to copy. Move to next key. */
			return (mtbl_res_success);
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
		dres = increment_key(seek_key, key_prefix_len - 1);

		/* Bail out if an increment overflow clobbers the type byte. */
		assert(dres == dnstable_res_success);
		if (ubuf_value(seek_key, 0) != ENTRY_TYPE_RDATA) {
			return (mtbl_res_failure);
		}

seek:
		/* Seek to the newly generated key. */
		return mtbl_iter_seek(seek_iter, ubuf_data(seek_key), ubuf_size(seek_key));
	} while(0);

	return (mtbl_res_success);
}

/*
 * This is a dnstable_iter_next_func helper function called in two cases:
 * 1. Right wildcard rrset queries where the source index (m_iter2) iterates over
 *     entries of type ENTRY_TYPE_RRSET_NAME_FWD which are then used to look up
 *     matching entries of type ENTRY_TYPE_RRSET in the source (m_iter)
 * 2. Left wildcard rdata queries where the source index (m_iter2) iterates over
 *    entries of type ENTRY_TYPE_RDATA_NAME_REV which are then used to look up
 *    matching entries of type ENTRY_TYPE_RDATA in the source (m_iter)
 *
 * In both cases, the current m_iter2 candidate key (which are all encountered in
 * sequential order) is used to form a search key to find the ultimate
 * corresponding key in m_iter (which are distributed more randomly).
 */
static dnstable_res
query_iter_next_name_indirect(void *clos, struct dnstable_entry **ent, uint8_t type_byte)
{
	struct query_iter *it = (struct query_iter *) clos;
	struct dnstable_query *q = it->query;
	const uint8_t *key, *val;
	size_t len_key, len_val;

	if (q->do_timeout || q->do_deadline) {
		query_iter_set_deadline(it);
		if (setjmp(it->to_env) != 0)
			return (dnstable_res_timeout);
	}

	for (;;) {

		if (it->m_iter == NULL) {
			uint16_t wanted_rrtype = it->query->rrtype;
			ubuf *full_key;

			if (mtbl_iter_next(it->m_iter2,
					   &key, &len_key,
					   &val, &len_val) != mtbl_res_success)
			{
				return (dnstable_res_failure);
			}

			/* use the new rrtype indexes */
			if (it->query->do_rrtype && !rrtype_test(type_byte, wanted_rrtype, val, len_val))
				continue;

			/* Use the index to create the key for the full data. */
			if (it->key2 == NULL)
				it->key2 = ubuf_init(len_key + 12);
			full_key = it->key2;

			ubuf_clip(full_key, 0);
			/* mtbl_varint_length() is max 12 bytes */
			ubuf_reserve(full_key, len_key + 12);
			ubuf_add(full_key, type_byte);

			/* Skip type-byte in index, reverse the forward-name. */
			if (wdns_reverse_name(key + 1, len_key - 1, ubuf_ptr(full_key)) != wdns_res_success)
				return (dnstable_res_failure);

			ubuf_advance(full_key, len_key - 1);

			/* Add rrtype to new search-key. */
			if (it->query->do_rrtype &&
				(type_byte == ENTRY_TYPE_RRSET))
				add_rrtype_to_key(full_key, wanted_rrtype);
			else if (it->query->do_rrtype) {
				switch(wanted_rrtype) {
				CASE_RDATA_NAME_TYPE_STANDALONE:
					add_rrtype_to_key(full_key, wanted_rrtype);
				}
			}

			it->m_iter = mtbl_source_get_prefix(it->source,
							    ubuf_data(full_key),
							    ubuf_size(full_key));
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

		return (dnstable_res_success);
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

#define FILTER_SET_COND(cond,fname,src)	\
do {	\
	if (it->query->cond) {	\
		it->fname = filter_mtbl_init(it->src, fname, it);	\
		it->src = filter_mtbl_source(it->fname);	\
	}	\
} while (0)
#define FILTER_SET(fname,src)	\
do {	\
	it->fname = filter_mtbl_init(it->src, fname, it);	\
	it->src = filter_mtbl_source(it->fname);	\
} while (0)

/*
 * Requires special handling because rrset entry order is by label-reversed rr-
 * set owner name, while we are traversing by label-forward rrset owner name.
 */
static struct dnstable_iter *
query_init_rrset_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RRSET_NAME_FWD);

	/* key: rrset owner name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	/* Single label wildcard filter applies to the index source (forward rrset owner names) */
	FILTER_SET_COND(dq_wildplus, filter_single_label, source_index);
	it->m_iter2 = mtbl_source_get_prefix(it->source_index, ubuf_data(it->key), ubuf_size(it->key));

	/* rrtype and bailiwick filters are applied to the final source (rrset entries) */
	FILTER_SET_COND(do_rrtype, filter_rrtype, source);
	FILTER_SET_COND(bailiwick.data, filter_bailiwick, source);

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

	FILTER_SET_COND(dq_wildplus, filter_single_label, source);
	FILTER_SET_COND(do_rrtype, filter_rrtype, source);
	FILTER_SET_COND(bailiwick.data, filter_bailiwick, source);

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

/* Lookup with wildcard on right-hand-side: "n.example.*" or "n.example.+" */
static inline bool
is_right_wildcard(struct dnstable_query *q)
{
	const wdns_name_t *name = &q->name;

	if (name->len >= 3 &&
	    name->data[name->len - 3] == '\x01' &&
	   (name->data[name->len - 2] == '*' || name->data[name->len - 2] == '+')) {
		q->dq_wildplus = name->data[name->len - 2] == '+';
		return (true);
	}
	return (false);
}

/* Lookup with wildcard on left-hand-side: "*.example.com" or "+.example.com" */
static inline bool
is_left_wildcard(struct dnstable_query *q)
{
	const wdns_name_t *name = &q->name;

	if (name->len >= 3 &&
	    name->data[0] == '\x01' &&
	   (name->data[1] == '*' || name->data[1] == '+')) {
		q->dq_wildplus = name->data[1] == '+';
		return (true);
	}
	return (false);
}

static struct dnstable_iter *
query_init_rrset(struct query_iter *it)
{
	uint8_t name[WDNS_MAXLEN_NAME];

	it->key = ubuf_init(64);
	if (is_left_wildcard(it->query))
		return query_init_rrset_left_wildcard(it);
	if (is_right_wildcard(it->query))
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

	/* No rrtype filter set because the key prefix can do that work itself */
	if (it->query->do_rrtype) {
		/* key: rrtype */
		add_rrtype_to_key(it->key, it->query->rrtype);

		/* Likewise, the bailiwick filter can also be made unnecessary */
		if (it->query->bailiwick.data != NULL) {
			ubuf_append(it->key, it->query->bailiwick.data, it->query->bailiwick.len);
		}
	} else {
		FILTER_SET_COND(bailiwick.data, filter_bailiwick, source);
	}

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_right_wildcard(struct query_iter *it)
{
	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata name, less trailing "\x01\x2a\x00" */
	ubuf_append(it->key, it->query->name.data, it->query->name.len - 3);

	FILTER_SET_COND(dq_wildplus, filter_single_label, source);

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

/*
 * Requires special handling because rdata names found in ENTRY_TYPE_RDATA
 * entries are in standard wire-format order, while we are traversing by
 * label-reversed rdata names.
 */
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

	/* Note the single label wildcard filter applies to the index source. */
	FILTER_SET_COND(dq_wildplus, filter_single_label, source_index);
	it->m_iter2 = mtbl_source_get_prefix(it->source_index, ubuf_data(it->key), ubuf_size(it->key));

	return dnstable_iter_init(query_iter_next_rdata_name_rev, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_name(struct query_iter *it)
{

	if (it->query->do_rrtype) {
		it->filter_rrtype = filter_mtbl_init(it->source, filter_rrtype, it);
	} else {
		it->filter_rrtype = filter_mtbl_init(it->source, filter_rrtype_rdata_name, it);
	}
	it->source = filter_mtbl_source(it->filter_rrtype);

	it->key = ubuf_init(64);
	if (is_right_wildcard(it->query))
		return query_init_rdata_right_wildcard(it);
	if (is_left_wildcard(it->query))
		return query_init_rdata_left_wildcard(it);

	/* key: type byte */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);

	/* key: rdata name */
	ubuf_append(it->key, it->query->name.data, it->query->name.len);

	/* key: rrtype */
	if (it->query->do_rrtype) {
		switch(it->query->rrtype) {
		CASE_RDATA_NAME_TYPE_STANDALONE:
			add_rrtype_to_key(it->key, it->query->rrtype);
		}
	}

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_rdata_ip(struct query_iter *it)
{
	assert(it->query->do_rrtype);
	assert(it->query->len_ip1 > 0);

	it->key = ubuf_init(64);

	/* key: type byte, rdata, rrtype */
	ubuf_add(it->key, ENTRY_TYPE_RDATA);
	ubuf_append(it->key, it->query->ip1, it->query->len_ip1);
	add_rrtype_to_key(it->key, it->query->rrtype);

	if (it->query->len_ip2 > 0) {
		it->key2 = ubuf_init(64);

		/* key2: type byte, rdata2, rrtype */
		ubuf_add(it->key2, ENTRY_TYPE_RDATA);
		ubuf_append(it->key2, it->query->ip2, it->query->len_ip2);
		add_rrtype_to_key(it->key2, it->query->rrtype);

		/* increment key2 starting from the last byte */
		increment_key(it->key2, ubuf_size(it->key2) - 1);
	}

	it->filter_rrtype = filter_mtbl_init(it->source, filter_rrtype_ip, it);
	it->source = filter_mtbl_source(it->filter_rrtype);

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

	/*
	 * Note: even though this function does not use it->query->do_rrtype
	 * or call add_rrtype_to_key(), if do_rrtype is set then the post-query
	 * filter processing in it->filter_rrtype will filter the results by rrtype.
	 */
	FILTER_SET_COND(do_rrtype, filter_rrtype, source);

	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_time_range(struct query_iter *it)
{
	it->key = ubuf_init(1);
	ubuf_add(it->key, ENTRY_TYPE_TIME_RANGE);
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_source_info(struct query_iter *it)
{
	it->key = ubuf_init(1);
	ubuf_add(it->key, ENTRY_TYPE_SOURCE_INFO);
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
query_init_version(struct query_iter *it)
{
	it->key = ubuf_init(1);
	ubuf_add(it->key, ENTRY_TYPE_VERSION);
	if (it->query->has_v_type)
		ubuf_add(it->key, it->query->v_type);
	return dnstable_iter_init(query_iter_next, query_iter_free, it);
}

static struct dnstable_iter *
dnstable_query_iter_common(struct query_iter *it)
{
	struct dnstable_iter *d_it;
	struct dnstable_query *q = it->query;

	/*
	 * First-added means that timeouts are evaluated before all other filters
	 * are applied, at the very bottom of the filter call chain.
	 * Thus, if a timeout occurs, the last iterator key/value pair is
	 * preserved for the benefit of the caller.
	 */
	if (q->do_timeout || q->do_deadline) {
		it->timeout = timeout_mtbl_init(it->source, &it->deadline, &it->to_env);
		it->source = timeout_mtbl_source(it->timeout);
		it->timeout_index = timeout_mtbl_init(it->source_index, &it->deadline, &it->to_env);
		it->source_index = timeout_mtbl_source(it->timeout_index);
	}

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
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_SOURCE_INFO) {
		d_it = query_init_source_info(it);
	} else if (q->q_type == DNSTABLE_QUERY_TYPE_VERSION) {
		d_it = query_init_version(it);
	} else {
		assert(0);
	}

	if (d_it == NULL) {
		query_iter_free(it);
		return (NULL);
	}

	/* Do the strict time filtering check at end, as it can only advance by one entry. */
	if (q->do_time_first_after || q->do_time_last_before ||
	    q->do_time_first_before || q->do_time_last_after) {
		FILTER_SET(filter_time_prefilter, source);

		/*
		 * Aggregated time-filtered fileset query setup has populated
		 * it->remove_strict with a list of sources that all contain key
		 * entries that we known will ALWAYS FAIL our time filtering checks.
		 *
		 * Right here, our main source only contains keys that MIGHT pass
		 * the time-fence check on their own.
		 */

		if (it->remove_strict != NULL) {
			remove_mtbl_set_upstream(it->remove_strict, it->source);
			it->source = remove_mtbl_source(it->remove_strict);
		}

		/*
		 * But after the application of it->remove_strict, any of the keys
		 * present in it->remove_strict will be hidden so that they are
		 * never produced by iterating through our main source.
		 */
	}

	/*
	 * If time-fencing is requested for an aggregated fileset, there is now a
	 * three-way dance that occurs between the various components populated
	 * by the reader_time_filter() fileset filter function.
	 *
	 * The first player is the above application of it->remove_strict in the
	 * case of strict time-filtering.
	 *
	 * The next is the optional left join below.
	 * The left side of this operation is the (remove-filtered) source, which
	 *     contains only entries that might pass time-filtering alone.
	 * The right side is it->fill_merger, which contains entries that would not
	 *     pass time-filtering on their own, but still might pass once they
	 *     are merged with a left-side entry.
	 */

	if (it->fill_merger != NULL) {
		it->ljoin = ljoin_mtbl_init(it->source,
					    mtbl_merger_source(it->fill_merger),
					    dnstable_merge_func, NULL);
		it->source = ljoin_mtbl_source(it->ljoin);
	}

	/* Note: some combinations of time filters may not require this stage. */
	if (it->filter_time_prefilter != NULL) {
		FILTER_SET(filter_time, source);
	}

	/* Seeing if we've hit the user supplied offset is always the first check */
	if (q->offset > 0) {
		FILTER_SET(filter_offset, source);
	}

	if (it->m_iter2 == NULL) {
		/* Set in the event of rdata IP range iteration */
		if (it->key2 != NULL)
			it->m_iter = mtbl_source_get_range(it->source,
						           ubuf_data(it->key), ubuf_size(it->key),
						           ubuf_data(it->key2), ubuf_size(it->key2));
		else
			it->m_iter = mtbl_source_get_prefix(it->source,
							    ubuf_data(it->key), ubuf_size(it->key));
	}

	dnstable_iter_set_stat_func(d_it, query_iter_get_count);
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

/*
 * This function takes care of narrowing down the contents of time-filtered
 * filesets by filtering out readers that don't contain data that might be used
 * to produce a match.
 *
 * The logic is the simplest for unaggregated queries: simply remove all readers
 * that have no possibility of producing a match.
 *
 * The logic is more complicated for aggregated queries. While the filter works
 * just as it does for unaggregated queries, it also does two things at the end:
 *
 * 1. All readers that would necessarily produce non-matching results are saved
 *    into it->remove_strict.
 * 2. All readers that might not produce matching results on their own but might
 *    form a matching entry post-merger are saved into it->fill_merger.
 *
 * The contents of remove_strict and fill_merger are subsequently used in
 * dnstable_query_iter_common(), where more commentary can be found.
 */
static bool
reader_time_filter(struct mtbl_reader *r, void *clos)
{
	struct query_iter *it = clos;
	struct dnstable_query *q = it->query;
	struct dnstable_query *tr_q = dnstable_query_init(DNSTABLE_QUERY_TYPE_TIME_RANGE);
	struct dnstable_iter *tr_it = dnstable_query_iter(tr_q, mtbl_reader_source(r));
	struct dnstable_entry *tr_e = NULL;
	uint64_t min_time_first, max_time_last;
	bool fill = false;
	bool remove = false;

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
	if (q->do_time_first_after && (q->time_first_after > max_time_last)) {
		remove = true;
		goto out;
	}

	/*
	 * #2. If the current reader has no data with time_last after our
	 * time_last_after cutoff, it will not cause any merged results
	 * to pass our time_last_after filter. Ignore for the filter pass.
	 */
	if (q->do_time_last_after && (q->time_last_after > max_time_last)) {
		fill = true;
		goto out;
	}

	/*
	 * #3. Like with time_first_after (#1), if the current reader has only
	 * data observed after the time_last_before cutoff, the resulting merged
	 * entries will fail our time_last_before filter. Ignore for the filter
	 * pass.
	 */
	if (q->do_time_last_before && (q->time_last_before < min_time_first)) {
		remove = true;
		goto out;
	}

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
	    (q->time_first_before < min_time_first)) {
		fill = true;
	}

out:
	dnstable_entry_destroy(&tr_e);
	dnstable_iter_destroy(&tr_it);
	dnstable_query_destroy(&tr_q);

	/* fill_merger and remove_strict are non-NULL for aggregated queries */
	if (fill && (it->fill_merger != NULL)) {
		mtbl_merger_add_source(it->fill_merger, mtbl_reader_source(r));
		it->stats.fill_files++;
	}

	/* If remove is set, we've failed a STRICT time fencing check. */
	if (remove && (it->remove_strict != NULL))
		remove_mtbl_add_source(it->remove_strict, mtbl_reader_source(r));

	if (!(fill || remove))
		it->stats.fileset_files++;

	return !(fill || remove);
}

static void
count_merge_func(void *clos,
	   const uint8_t *key, size_t len_key,
	   const uint8_t *val0, size_t len_val0,
	   const uint8_t *val1, size_t len_val1,
	   uint8_t **merged_val, size_t *len_merged_val)
{
	uint64_t *counter = clos;
	dnstable_merge_func(clos,
			    key, len_key,
			    val0, len_val0,
			    val1, len_val1,
			    merged_val, len_merged_val);
	(*counter)++;
}

struct dnstable_iter *
dnstable_query_iter_fileset(struct dnstable_query *q, struct mtbl_fileset *fs)
{
	struct query_iter *it = my_calloc(1, sizeof(*it));
	struct mtbl_fileset_options *fopt;

	it->query = q;

	fopt = mtbl_fileset_options_init();
	mtbl_fileset_options_set_reader_filter_func(fopt, reader_time_filter, it);
	mtbl_fileset_options_set_merge_func(fopt, count_merge_func, &it->stats.fileset_merged);

	/*
	 * For time-filtered aggregated queries, set up fill merger for complete results.
	 * If strict time filtering is requested, set up a remove_mtbl to efficiently
	 * exclude non-matching results.
	 */
	if (q->aggregated &&
	    (q->do_time_first_before || q->do_time_first_after ||
	     q->do_time_last_before || q->do_time_last_after)) {

		struct mtbl_merger_options *mopt;

		if (q->do_time_first_after || q->do_time_last_before)
			it->remove_strict = remove_mtbl_init();

		mopt = mtbl_merger_options_init();
		mtbl_merger_options_set_merge_func(mopt, count_merge_func, &it->stats.fill_merged);
		it->fill_merger = mtbl_merger_init(mopt);
		mtbl_merger_options_destroy(&mopt);
	}

	it->fs_filter = mtbl_fileset_dup(fs, fopt);
	it->source_index = mtbl_fileset_source(it->fs_filter);
	it->source = mtbl_fileset_source(it->fs_filter);

	/*
	 * If the query requests unaggregated results, we create a fileset
	 * with no merge function and use it as the source for final results.
	 * The merged index fileset source remains in place to avoid duplicate
	 * results for queries involving indexes.
	 *
	 * Any fileset time-filtering (like the application of reader_filter_func)
	 * above applies to this unaggregated fileset.
	 */
	if (!q->aggregated) {
		mtbl_fileset_options_set_merge_func(fopt, NULL, NULL);
		mtbl_fileset_options_set_dupsort_func(fopt, dnstable_dupsort_func, NULL);
		it->fs_no_merge = mtbl_fileset_dup(fs, fopt);
		/* it->source_index remains merged to prevent duplicate index lookups. */
		it->source = mtbl_fileset_source(it->fs_no_merge);
	}

	mtbl_fileset_options_destroy(&fopt);
	return dnstable_query_iter_common(it);
}
