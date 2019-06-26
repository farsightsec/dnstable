/*
 * Copyright (c) 2012-2015, 2017-2018 by Farsight Security, Inc.
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
	       q_type == DNSTABLE_QUERY_TYPE_RDATA_RAW);
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

bool dnstable_query_is_aggregated(const struct dnstable_query *q)
{
	return q->aggregated;
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

	if (q->do_rrtype) {
		uint16_t rrtype;
		res = dnstable_entry_get_rrtype(e, &rrtype);
		if (res != dnstable_res_success)
			return (res);
		if (rrtype != q->rrtype)
			goto fail;
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
		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);

		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		assert(*ent != NULL);
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

		if (it->query->do_timeout) {
			struct timespec now;
			my_gettime(DNSTABLE__CLOCK_MONOTONIC, &now);
			if (my_timespec_cmp(&now, &expiry) >= 0)
				return (dnstable_res_timeout);
		}

		if (mtbl_iter_next(it->m_iter, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);

		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		assert(*ent != NULL);

		/*
		 * it->key2 != NULL implies an IP prefix/range search, for which
		 * we can perform a special optimization to skip past irrelevant
		 * entries.
		 */
		if (it->query->do_rrtype && it->key2 != NULL) {
			/* Get the rrtype of the decoded entry. */
			uint16_t rrtype;
			res = dnstable_entry_get_rrtype(*ent, &rrtype);
			if (res != dnstable_res_success) {
				dnstable_entry_destroy(ent);
				return (res);
			}

			if (rrtype != it->query->rrtype) {
				/*
				 * Destroy the current entry. It will not be
				 * processed since it's the wrong rrtype.
				 */
				dnstable_entry_destroy(ent);

				/*
				 * Create a new start key with the prefix of the
				 * current entry's key, plus the target rrtype.
				 * This ends up being an IP address derived from
				 * the first 4 or 16 bytes of the current key's
				 * rdata, sandwiched between the entry type byte
				 * and the rrtype.
				 *
				 * This is helpful when the query rrtype is AAAA
				 * (28), which comes numerically after many
				 * common rrtypes.
				 */
				ubuf *new_key = ubuf_init(ubuf_size(it->key));
				size_t rrtype_len = mtbl_varint_length(it->query->rrtype);
				size_t key_prefix_len = ubuf_size(it->key) - rrtype_len;
				if (key_prefix_len <= len_key) {
					ubuf_append(new_key, key, key_prefix_len);
				} else {
					/* Zero fill short keys. */
					ubuf_reserve(new_key, key_prefix_len);
					ubuf_append(new_key, key, len_key);
					ubuf_advance(new_key, key_prefix_len - len_key);
					memset(ubuf_data(new_key) + len_key, 0,
					       key_prefix_len - len_key);
				}
				add_rrtype_to_key(new_key, it->query->rrtype);

				/*
				 * Check if the key that we just generated sorts
				 * prior to the current entry's key. If so, it's
				 * OK to skip ahead to the next IP address,
				 * because we must have *already* consumed any
				 * entries between the key we just generated up
				 * to the current entry's key.
				 *
				 * This check is very likely to succeed for IPv4
				 * addresses, since rrtype A (1) is the lowest
				 * rrtype value in use, but less likely to
				 * succeed for IPv6 addresses since rrtype AAAA
				 * (28) sorts after many common rrtypes.
				 */
				if (bytes_compare(ubuf_data(new_key), ubuf_size(new_key),
						  key, len_key) <= 0)
				{
					/*
					 * Increment the IP address in the
					 * middle of our key by one. This
					 * correctly handles octet overflow,
					 * e.g. 10.0.255.255 -> 10.1.0.0.
					 *
					 * This potentially eliminates a large
					 * number of irrelevant entries, which
					 * we would otherwise have to retrieve
					 * and filter out.
					 */
					res = increment_key(new_key, key_prefix_len - 1);

					/*
					 * If increment_key() failed, then we
					 * were already at the all-ones A/AAAA
					 * address. Entries up to and including
					 * that address have already been
					 * consumed, so stop iterating now.
					 */
					if (res != dnstable_res_success) {
						ubuf_destroy(&new_key);
						mtbl_iter_destroy(&it->m_iter);
						return (dnstable_res_failure);
					}
				}

				/*
				 * Safety check: we should have generated a key
				 * containing embedded data exactly as long as
				 * an IP address, and thus the key should be
				 * exactly as long as the original search key.
				 */
				assert(ubuf_size(new_key) == ubuf_size(it->key));

				/*
				 * Seek to the newly generated key.
				 */
				if (mtbl_iter_seek(it->m_iter, ubuf_data(new_key), ubuf_size(new_key)) != mtbl_res_success) {
					ubuf_destroy(&new_key);
					return (dnstable_res_failure);
				}
				ubuf_destroy(&new_key);

				/*
				 * Restart processing starting from the new key.
				 */
				continue;
			}
		}

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
}

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
			if (mtbl_iter_next(it->m_iter2,
					   &key, &len_key,
					   &val, &len_val) != mtbl_res_success)
			{
				return (dnstable_res_failure);
			}
			ubuf_clip(it->key, 0);
			ubuf_reserve(it->key, len_key + mtbl_varint_length(it->query->rrtype));
			ubuf_add(it->key, type_byte);
			if (wdns_reverse_name(key + 1, len_key - 1, ubuf_ptr(it->key))
			    != wdns_res_success)
				return (dnstable_res_failure);
			ubuf_advance(it->key, len_key - 1);
			if (it->query->do_rrtype &&
				(type_byte == ENTRY_TYPE_RRSET))
				add_rrtype_to_key(it->key, it->query->rrtype);
			else if (it->query->do_rrtype) {
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
		assert(*ent != NULL);
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
	if (wdns_reverse_name(it->query->name.data + 2, len, name) != wdns_res_success)
		return (NULL);
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

	it->m_iter = mtbl_source_get_prefix(it->source, ubuf_data(it->key), ubuf_size(it->key));
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

		/* key2: type byte, rdata2, rrtype */
		ubuf_add(it->key2, ENTRY_TYPE_RDATA);
		ubuf_append(it->key2, it->query->rdata2, it->query->len_rdata2);
		add_rrtype_to_key(it->key2, it->query->rrtype);

		/* increment key2 starting from the last byte */
		increment_key(it->key2, ubuf_size(it->key2) - 1);
	}

	if (it->key2 == NULL) {
		it->m_iter = mtbl_source_get_prefix(it->source,
						    ubuf_data(it->key), ubuf_size(it->key));
	} else {
		it->m_iter = mtbl_source_get_range(it->source,
						   ubuf_data(it->key), ubuf_size(it->key),
						   ubuf_data(it->key2), ubuf_size(it->key2));
	}
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
         * Note: even though this function does not use
         * it->query->do_rrtype nor call add_rrtype_to_key(), in the
         * post-query filter processing in dnstable_query_filter(), if
         * do_rrtype is set then the results will be filtered by
         * rrtype.
         */

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
	if (d_it == NULL)
		query_iter_free(it);
	return (d_it);
}
