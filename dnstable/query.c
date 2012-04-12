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

	if (strcasecmp(s_rrtype, "ANY-DNSSEC") == 0) {
		q->rrtype = DNSTABLE_TYPE_ANY_DNSSEC;
		q->do_rrtype = true;
		return (dnstable_res_success);
	}

	if (strncasecmp(s_rrtype, "TYPE", 4) == 0) {
		long val;
		char *endptr;

		errno = 0;
		val = strtol(s_rrtype + 4, &endptr, 10);
		if (errno != 0 || *endptr != '\0') {
			query_set_err(q, "unable to parse rrtype");
			return (dnstable_res_failure);
		}

		if (val < 0 || val > USHRT_MAX) {
			query_set_err(q, "rrtype value out of range");
			return (dnstable_res_failure);
		}

		q->do_rrtype = true;
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

	if (q->do_rrtype &&
	    (q->rrtype != WDNS_TYPE_ANY && q->rrtype != DNSTABLE_TYPE_ANY_DNSSEC))
	{
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
