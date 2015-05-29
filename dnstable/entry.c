/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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

#include "dnstable-private.h"

VECTOR_GENERATE(rdata_vec, wdns_rdata_t *);

#define add_yajl_string(g, s) do {                                              \
	yajl_gen_status g_status;                                               \
	g_status = yajl_gen_string(g, (const unsigned  char *) s, strlen(s));   \
	assert(g_status == yajl_gen_status_ok);                                 \
} while (0)

struct dnstable_entry {
	dnstable_entry_type	e_type;
	wdns_name_t		name, bailiwick;
	uint32_t		rrtype;
	rdata_vec		*rdatas;
	uint64_t		time_first, time_last, count;
	bool			iszone;
};

static void
fmt_uint64(ubuf *u, uint64_t v)
{
	char s[sizeof("18,446,744,073,709,551,615")];
	snprintf(s, sizeof(s), "%'" PRIu64, v);
	ubuf_add_cstr(u, s);
}

static size_t
fmt_uint64_str(char *s, uint64_t u)
{
	size_t len = 1;
	uint64_t q = u;

	while (q > 9) {
		len++;
		q /= 10;
	}
	s += len;
	do {
		*--s = '0' + (u % 10);
		u /= 10;
	} while (u);

	return (len);
}

static void
fmt_time(ubuf *u, uint64_t v)
{
	struct tm gm;
	time_t tm = v;
	char s[sizeof("4294967295-12-31 23:59:59 -0000")];
	if (gmtime_r(&tm, &gm) != NULL) {
		snprintf(s, sizeof(s), "%d-%02d-%02d %02d:%02d:%02d -0000",
			1900 + gm.tm_year,
			1 + gm.tm_mon,
			gm.tm_mday,
			gm.tm_hour,
			gm.tm_min,
			gm.tm_sec
	       );
	}
	ubuf_add_cstr(u, s);
}

static void
fmt_rrtype(ubuf *u, uint16_t rrtype)
{
	char s[sizeof("TYPE65535")];
	const char *s_rrtype = wdns_rrtype_to_str(rrtype);
	if (s_rrtype) {
		ubuf_add_cstr(u, s_rrtype);
	} else {
		snprintf(s, sizeof(s), "TYPE%hu", rrtype);
		ubuf_add_cstr(u, s);
	}
}

char *
dnstable_entry_to_text(struct dnstable_entry *e)
{
	uint8_t *s = NULL;
	size_t len_s;
	ubuf *u = ubuf_init(256);
	char name[WDNS_PRESLEN_NAME];

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET) {
		/* bailiwick */
		wdns_domain_to_str(e->bailiwick.data, e->bailiwick.len, name);
		ubuf_add_cstr(u, ";;  bailiwick: ");
		ubuf_add_cstr(u, name);

		/* count */
		ubuf_add_cstr(u, "\n;;      count: ");
		fmt_uint64(u, e->count);

		/* first seen */
		if (e->iszone)
			ubuf_add_cstr(u, "\n;; first seen in zone file: ");
		else
			ubuf_add_cstr(u, "\n;; first seen: ");
		fmt_time(u, e->time_first);

		/* last seen */
		if (e->iszone)
			ubuf_add_cstr(u, "\n;;  last seen in zone file: ");
		else
			ubuf_add_cstr(u, "\n;;  last seen: ");
		fmt_time(u, e->time_last);
		ubuf_add(u, '\n');

		/* resource records */
		wdns_domain_to_str(e->name.data, e->name.len, name);
		for (size_t i = 0; i < rdata_vec_size(e->rdatas); i++) {
			wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, i);
			char *data = wdns_rdata_to_str(rdata->data, rdata->len,
						       e->rrtype, WDNS_CLASS_IN);
			ubuf_add_cstr(u, name);
			ubuf_add_cstr(u, " IN ");
			fmt_rrtype(u, e->rrtype);
			ubuf_add(u, ' ');
			ubuf_add_cstr(u, data);
			ubuf_add(u, '\n');
			my_free(data);
		}
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA) {
		if (rdata_vec_size(e->rdatas) != 1)
			goto out;

		wdns_domain_to_str(e->name.data, e->name.len, name);
		wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, 0);
		char *data = wdns_rdata_to_str(rdata->data, rdata->len,
					       e->rrtype, WDNS_CLASS_IN);
		ubuf_add_cstr(u, name);
		ubuf_add_cstr(u, " IN ");
		fmt_rrtype(u, e->rrtype);
		ubuf_add(u, ' ');
		ubuf_add_cstr(u, data);
		ubuf_add(u, '\n');
		my_free(data);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD) {
		wdns_domain_to_str(e->name.data, e->name.len, name);
		ubuf_add_cstr(u, name);
		ubuf_add_cstr(u, " ;; rrset name fwd\n");
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV) {
		wdns_domain_to_str(e->name.data, e->name.len, name);
		ubuf_add_cstr(u, name);
		ubuf_add_cstr(u, " ;; rdata name rev\n");
	}

	ubuf_cterm(u);
	ubuf_detach(u, &s, &len_s);
out:
	ubuf_destroy(&u);
	return ((char *) (s));
}

static void
callback_print_yajl_ubuf(void *ctx, const char *str, size_t len)
{
	ubuf *u = (ubuf *) ctx;
	ubuf_append(u, (const uint8_t *) str, len);
}

char *
dnstable_entry_to_json(struct dnstable_entry *e)
{
	int rc;
	uint8_t *s = NULL;
	char name[WDNS_PRESLEN_NAME];
	char intstr[sizeof("18446744073709551615")];
	size_t len;
	ubuf *u;
	yajl_gen g;
	yajl_gen_status status;

	u = ubuf_init(256);

	g = yajl_gen_alloc(NULL);
	assert(g != NULL);

	rc = yajl_gen_config(g, yajl_gen_print_callback, callback_print_yajl_ubuf, (void *) u);
	assert(rc != 0);

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		/* count */
		add_yajl_string(g, "count");

		len = fmt_uint64_str(intstr, e->count);
		assert(len > 0);
		status = yajl_gen_number(g, intstr, len);
		assert(status == yajl_gen_status_ok);

		/* first seen */
		if (e->iszone)
			add_yajl_string(g, "zone_time_first");
		else
			add_yajl_string(g, "time_first");

		len = fmt_uint64_str(intstr, e->time_first);
		assert(len > 0);
		status = yajl_gen_number(g, intstr, len);
		assert(status == yajl_gen_status_ok);

		/* last seen */
		if (e->iszone)
			add_yajl_string(g, "zone_time_last");
		else
			add_yajl_string(g, "time_last");

		len = fmt_uint64_str(intstr, e->time_last);
		assert(len > 0);
		status = yajl_gen_number(g, intstr, len);
		assert(status == yajl_gen_status_ok);

		/* rrname */
		add_yajl_string(g, "rrname");

		wdns_domain_to_str(e->name.data, e->name.len, name);
		add_yajl_string(g, name);

		/* rrtype */
		add_yajl_string(g, "rrtype");

		const char *s_rrtype = wdns_rrtype_to_str(e->rrtype);
		if (s_rrtype) {
			add_yajl_string(g, s_rrtype);
		} else {
			char buf[sizeof("TYPE65535")];
			len = snprintf(buf, sizeof(buf), "TYPE%hu", (uint16_t) e->rrtype);
			assert(len > 0);
			status = yajl_gen_string(g, (uint8_t *) buf, len);
			assert(status == yajl_gen_status_ok);
		}
	}

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET) {
		/* bailiwick */
		add_yajl_string(g, "bailiwick");

		wdns_domain_to_str(e->bailiwick.data, e->bailiwick.len, name);
		add_yajl_string(g, name);

		/* resource records */
		add_yajl_string(g, "rdata");

		status = yajl_gen_array_open(g);
		assert(status == yajl_gen_status_ok);

		const size_t n_rdatas = rdata_vec_size(e->rdatas);
		for (size_t i = 0; i < n_rdatas; i++) {
			wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, i);
			char *data = wdns_rdata_to_str(rdata->data, rdata->len,
						       e->rrtype, WDNS_CLASS_IN);
			add_yajl_string(g, data);
			my_free(data);
		}

		status = yajl_gen_array_close(g);
		assert(status == yajl_gen_status_ok);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA) {
		if (rdata_vec_size(e->rdatas) != 1)
			goto out;

		/* rdata */
		add_yajl_string(g, "rdata");

		wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, 0);
		char *data = wdns_rdata_to_str(rdata->data, rdata->len,
					       e->rrtype, WDNS_CLASS_IN);
		add_yajl_string(g, data);
		my_free(data);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD ||
		   e->e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV)
	{
		goto out;
	}

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	ubuf_cterm(u);
	ubuf_detach(u, &s, &len);
out:
	ubuf_destroy(&u);
	yajl_gen_free(g);
	return ((char *) s);
}

static dnstable_res
decode_val_triplet(struct dnstable_entry *e, const uint8_t *val, size_t len_val)
{
	return (triplet_unpack(val, len_val,
			       &e->time_first,
			       &e->time_last,
			       &e->count));
}

static dnstable_res
decode_rrset(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf)
{
	const uint8_t *p = buf;
	const uint8_t *end = buf + len_buf;
	uint8_t name[WDNS_MAXLEN_NAME];
	size_t len_name;

	/* rrname */
	if (wdns_len_uname(p, end, &len_name) != wdns_res_success)
		return (dnstable_res_failure);
	if (wdns_reverse_name(p, len_name, name) != wdns_res_success)
		return (dnstable_res_failure);
	e->name.len = len_name;
	e->name.data = my_malloc(e->name.len);
	memcpy(e->name.data, name, len_name);
	p += len_name;
	if (p > end)
		return (dnstable_res_failure);

	/* rrtype */
	p += mtbl_varint_decode32(p, &e->rrtype);
	if (p > end)
		return (dnstable_res_failure);
	
	/* bailiwick */
	if (wdns_len_uname(p, end, &len_name) != wdns_res_success)
		return (dnstable_res_failure);
	if (wdns_reverse_name(p, len_name, name) != wdns_res_success)
		return (dnstable_res_failure);
	e->bailiwick.len = len_name;
	e->bailiwick.data = my_malloc(e->bailiwick.len);
	memcpy(e->bailiwick.data, name, len_name);
	p += len_name;
	if (p > end)
		return (dnstable_res_failure);

	/* rdata array */
	while (p < end) {
		wdns_rdata_t *rdata;
		uint32_t len_rdata;

		p += mtbl_varint_decode32(p, &len_rdata);
		if (len_rdata > USHRT_MAX)
			return (dnstable_res_failure);

		if (p + len_rdata > end)
			return (dnstable_res_failure);
		
		rdata = my_malloc(sizeof(wdns_rdata_t) + len_rdata);
		rdata->len = len_rdata;
		memcpy(rdata->data, p, len_rdata);
		rdata_vec_add(e->rdatas, rdata);

		p += len_rdata;
	}

	return (dnstable_res_success);
}

static dnstable_res
decode_rrset_name_fwd(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf)
{
	e->name.len = len_buf;
	e->name.data = my_malloc(len_buf);
	memcpy(e->name.data, buf, len_buf);
	return (dnstable_res_success);
}

static dnstable_res
decode_rdata_name_rev(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf)
{
	e->name.len = len_buf;
	e->name.data = my_malloc(len_buf);
	if (wdns_reverse_name(buf, len_buf, e->name.data) != wdns_res_success)
		return (dnstable_res_failure);
	return (dnstable_res_success);
}

static dnstable_res
decode_rdata(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf)
{
	uint16_t len_data;
	const uint8_t *p = buf;
	const uint8_t *end = buf + len_buf;
	const uint8_t *data;
	const uint8_t *slice;
	uint8_t name[WDNS_MAXLEN_NAME];
	size_t len_name, len_slice;
	wdns_rdata_t *rdata;

	if (len_buf < sizeof(uint16_t))
		return (dnstable_res_failure);

	/* data length */
	memcpy(&len_data, end - sizeof(uint16_t), sizeof(uint16_t));
	end = buf + len_buf - sizeof(uint16_t);

	/* data */
	data = p;
	p += len_data;
	if (p > end)
		return (dnstable_res_failure);

	/* rrtype */
	p += mtbl_varint_decode32(p, &e->rrtype);
	if (p > end)
		return (dnstable_res_failure);

	/* rrname */
	if (wdns_len_uname(p, end, &len_name) != wdns_res_success)
		return (dnstable_res_failure);
	if (wdns_reverse_name(p, len_name, name) != wdns_res_success)
		return (dnstable_res_failure);
	e->name.len = len_name;
	e->name.data = my_malloc(e->name.len);
	memcpy(e->name.data, name, len_name);
	p += len_name;
	if (p > end)
		return (dnstable_res_failure);

	/* rdata */
	if (p == end) {
		rdata = my_malloc(sizeof(wdns_rdata_t) + len_data);
		rdata->len = len_data;
		memcpy(rdata->data, data, len_data);
	} else {
		slice = p;
		len_slice = end - p;
		rdata = my_malloc(sizeof(wdns_rdata_t) + len_slice + len_data);
		rdata->len = len_slice + len_data;
		memcpy(rdata->data, slice, len_slice);
		memcpy(rdata->data + len_slice, data, len_data);
	}
	rdata_vec_add(e->rdatas, rdata);

	return (dnstable_res_success);
}

struct dnstable_entry *
dnstable_entry_decode(const uint8_t *key, size_t len_key,
		      const uint8_t *val, size_t len_val)
{
	if (len_key < 1)
		return (NULL);

	struct dnstable_entry *e = my_calloc(1, sizeof(*e));
	e->rdatas = rdata_vec_init(4);

	switch (key[0]) {
	case ENTRY_TYPE_RRSET:
		e->e_type = DNSTABLE_ENTRY_TYPE_RRSET;
		if (decode_rrset(e, key+1, len_key-1) != dnstable_res_success) goto err;
		if (decode_val_triplet(e, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_RRSET_NAME_FWD:
		e->e_type = DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD;
		if (decode_rrset_name_fwd(e, key+1, len_key-1) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_RDATA:
		e->e_type = DNSTABLE_ENTRY_TYPE_RDATA;
		if (decode_rdata(e, key+1, len_key-1) != dnstable_res_success) goto err;
		if (decode_val_triplet(e, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_RDATA_NAME_REV:
		e->e_type = DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV;
		if (decode_rdata_name_rev(e, key+1, len_key-1) != dnstable_res_success) goto err;
		break;
	}

	return (e);
err:
	dnstable_entry_destroy(&e);
	return (NULL);
}

void
dnstable_entry_destroy(struct dnstable_entry **e)
{
	if (*e) {
		for (size_t i = 0; i < rdata_vec_size((*e)->rdatas); i++) {
			wdns_rdata_t *rdata = rdata_vec_value((*e)->rdatas, i);
			my_free(rdata);
		}
		rdata_vec_destroy(&(*e)->rdatas);
		my_free((*e)->name.data);
		my_free((*e)->bailiwick.data);
		my_free(*e);
	}
}

dnstable_entry_type
dnstable_entry_get_type(struct dnstable_entry *e)
{
	return (e->e_type);
}

void
dnstable_entry_set_iszone(struct dnstable_entry *e, bool iszone)
{
	e->iszone = iszone;
}

dnstable_res
dnstable_entry_get_rrname(struct dnstable_entry *e,
			  const uint8_t **rrname, size_t *len_rrname)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*rrname = e->name.data;
		*len_rrname = e->name.len;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_bailiwick(struct dnstable_entry *e,
			     const uint8_t **bailiwick, size_t *len_bailiwick)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET)
	{
		*bailiwick = e->bailiwick.data;
		*len_bailiwick = e->bailiwick.len;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_rrtype(struct dnstable_entry *e, uint16_t *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*v = (uint16_t) e->rrtype;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_num_rdata(struct dnstable_entry *e, size_t *num_rdata)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*num_rdata = rdata_vec_size(e->rdatas);
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_rdata(struct dnstable_entry *e, size_t i,
			 const uint8_t **rdata, size_t *len_rdata)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		if (i > rdata_vec_size(e->rdatas))
			return (dnstable_res_failure);
		*rdata = rdata_vec_value(e->rdatas, i)->data;
		*len_rdata = rdata_vec_value(e->rdatas, i)->len;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_rdata_name(struct dnstable_entry *e,
			      const uint8_t **rdata_name, size_t *len_rdata_name)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV)
	{
		*rdata_name = e->name.data;
		*len_rdata_name = e->name.len;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_time_first(struct dnstable_entry *e, uint64_t *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*v = e->time_first;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_time_last(struct dnstable_entry *e, uint64_t *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*v = e->time_last;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_count(struct dnstable_entry *e, uint64_t *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		*v = e->count;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}
