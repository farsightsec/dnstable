/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012, 2014-2016, 2019-2021 by Farsight Security, Inc.
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
#include "dnstable-json.h"

VECTOR_GENERATE(rdata_vec, wdns_rdata_t *);


struct dnstable_entry {
	dnstable_entry_type	e_type;
	wdns_name_t		name, bailiwick;
	uint32_t		rrtype;
	rdata_vec		*rdatas;
	ubuf			*rrtype_map;
	uint64_t		time_first, time_last, count;
	dnstable_entry_type	v_type;
	uint32_t		version;
	bool			iszone;
};

struct dnstable_formatter {
	dnstable_output_format_type	output_format;
	dnstable_date_format_type	date_format;
	bool				always_array;
	bool				add_raw_rdata;
};

static char *
dnstable_entry_to_json_fmt(const struct dnstable_entry *e,
			   dnstable_date_format_type date_format,
			   bool always_array, bool add_raw_rdata);


static void
fmt_uint64(ubuf *u, uint64_t v)
{
	char s[sizeof("18,446,744,073,709,551,615")];
	int ret = snprintf(s, sizeof(s), "%'" PRIu64, v);
	ubuf_append(u, (const uint8_t*) s, ret);
}

static void
fmt_time(ubuf *u, uint64_t v)
{
	struct tm gm, *r;
	time_t tm = v;
	char s[sizeof("4294967295-12-31 23:59:59 -0000")];
	size_t len;

	r = gmtime_r(&tm, &gm);
	if ((r != NULL) && ((len = strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S -0000", r)) > 0))
		ubuf_append(u, (const uint8_t*) s, len);
}

static inline void
fmt_rfc3339(const struct tm *src, char *dst)
{
	my_uint64_to_str(1900 + src->tm_year, dst, 5, NULL);
	dst[4] = '-';
	my_uint64_to_str(1 + src->tm_mon, dst + 5, 3, NULL);
	dst[7] = '-';
	my_uint64_to_str(src->tm_mday, dst + 8, 3, NULL);
	dst[10] = 'T';
	my_uint64_to_str(src->tm_hour, dst + 11, 3, NULL);
	dst[13] = ':';
	my_uint64_to_str(src->tm_min, dst + 14, 3, NULL);
	dst[16] = ':';
	my_uint64_to_str(src->tm_sec, dst + 17, 3, NULL);
	dst[19] = 'Z';
}

static void
fmt_rfc3339_time(ubuf *u, uint64_t v)
{
	struct tm gm, *r;
	time_t tm = v;
	char ts[]="0000-00-00T00:00:00Z";

	r = gmtime_r(&tm, &gm);
	assert(r != NULL);

	fmt_rfc3339(r, ts);

	/*
	 * fmt_rfc3339 will completely fill the ts array, so ubuf_append_cstr_lit can compute the string
	 * length using sizeof
	 */
	ubuf_append_cstr_lit(u, ts);
}

static void
fmt_rfc3339_time_json(ubuf *u, uint64_t v)
{
	struct tm gm, *r;
	time_t tm = v;
	char ts[]="0000-00-00T00:00:00Z";

	r = gmtime_r(&tm, &gm);
	assert(r != NULL);

	fmt_rfc3339(r, ts);

	/*
	 * fmt_rfc3339 will completely fill the ts array, so sizeof can be used to compute the string length
	 */
	
	append_json_value_string(u, ts, sizeof(ts) - 1);
}

/*
 * fill u with the two-digit hex representation of each character in
 * string s of len len_s.
 * Caller is responsible to initialize the ubuf and terminate the ubuf
 * with ubuf_cterm(rbuf).
 */
static void
fmt_hex_str(ubuf *u, uint8_t *s, size_t len_s)
{
	for (size_t c = 0; c < len_s; c++) {
		char hexbuf[3];
		snprintf(hexbuf, sizeof(hexbuf), "%02x", s[c]);
		ubuf_append(u, (const uint8_t*) hexbuf, 2);
	}
}

static void
fmt_rrtype(ubuf *u, uint16_t rrtype)
{
	char s[sizeof("TYPE65535")];
	const char *s_rrtype = wdns_rrtype_to_str(rrtype);
	if (s_rrtype) {
		ubuf_add_cstr(u, s_rrtype);
	} else {
		int ret = snprintf(s, sizeof(s), "TYPE%hu", rrtype);
		ubuf_append(u, (const uint8_t*) s, ret);
	}
}

static void
fmt_rrtype_json(ubuf *u, uint16_t rrtype)
{
	const char *s_rrtype = wdns_rrtype_to_str(rrtype);
	if (s_rrtype)
		append_json_value_string(u, s_rrtype, strlen(s_rrtype));
	else {
		char buf[sizeof("TYPE65535")];
		size_t len = snprintf(buf, sizeof(buf), "TYPE%hu", (uint16_t)rrtype);
		assert(len > 0);
		append_json_value_string(u, buf, len);
	}
}

static void
fmt_rrtypes_union(ubuf *u, const struct dnstable_entry *e)
{
	ubuf_append_cstr_lit(u, " RRtypes=[");

	if (e->rrtype_map != NULL) {
		rrtype_unpacked_set rrtype_set;
		int n_rrtypes = rrtype_union_unpack(ubuf_data(e->rrtype_map), ubuf_size(e->rrtype_map), &rrtype_set);

		if (n_rrtypes == -1)
			ubuf_append_cstr_lit(u, "<failure>");
		else {
			for (int n = 0; n < n_rrtypes; n++) {
				fmt_rrtype(u, rrtype_set.rrtypes[n]);

				if (n + 1 < n_rrtypes)
					ubuf_append_cstr_lit(u, " ");
			}
		}
	}
	ubuf_append_cstr_lit(u, "] ");
}

static void
fmt_rrtypes_union_json(ubuf *u, const struct dnstable_entry *e)
{
	declare_json_value(u, "rrtypes", false);
	ubuf_append(u, (const uint8_t *)"[", 1);

	if (e->rrtype_map != NULL) {
		rrtype_unpacked_set rrtype_set;
		int n_rrtypes = rrtype_union_unpack(ubuf_data(e->rrtype_map), ubuf_size(e->rrtype_map), &rrtype_set);
		if (n_rrtypes == -1) {
			const char *_fail = "<failure>";
			append_json_value_string(u, _fail, strlen(_fail));
		} else {
			for (int n = 0; n < n_rrtypes; n++) {
				fmt_rrtype_json(u, rrtype_set.rrtypes[n]);

				if (n + 1 < n_rrtypes)
					ubuf_append(u, (const uint8_t *)",", 1);
			}
		}
	}

	ubuf_append(u, (const uint8_t *)"]", 1);
}

static char *
dnstable_entry_to_text_fmt(const struct dnstable_entry *e, dnstable_date_format_type date_format)
{
	uint8_t *s = NULL;
	size_t len_s;
	ubuf *u = ubuf_init(256);
	char name[WDNS_PRESLEN_NAME];
	void (*time_formatter)(ubuf *, uint64_t);

	time_formatter = (date_format == dnstable_date_format_unix) ? fmt_time : fmt_rfc3339_time;

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET) {
		/* bailiwick */
		wdns_domain_to_str(e->bailiwick.data, e->bailiwick.len, name);
		ubuf_append_cstr_lit(u, ";;  bailiwick: ");
		ubuf_add_cstr(u, name);

		/* count */
		ubuf_append_cstr_lit(u, "\n;;      count: ");
		fmt_uint64(u, e->count);

		/* first seen */
		if (e->iszone)
			ubuf_append_cstr_lit(u, "\n;; first seen in zone file: ");
		else
			ubuf_append_cstr_lit(u, "\n;; first seen: ");
		time_formatter(u, e->time_first);

		/* last seen */
		if (e->iszone)
			ubuf_append_cstr_lit(u, "\n;;  last seen in zone file: ");
		else
			ubuf_append_cstr_lit(u, "\n;;  last seen: ");
		time_formatter(u, e->time_last);
		ubuf_add(u, '\n');

		/* resource records */
		wdns_domain_to_str(e->name.data, e->name.len, name);
		for (size_t i = 0; i < rdata_vec_size(e->rdatas); i++) {
			wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, i);
			char *data = wdns_rdata_to_str(rdata->data, rdata->len,
						       e->rrtype, WDNS_CLASS_IN);
			ubuf_add_cstr(u, name);
			ubuf_append_cstr_lit(u, " IN ");
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
		ubuf_append_cstr_lit(u, " IN ");
		fmt_rrtype(u, e->rrtype);
		ubuf_add(u, ' ');
		ubuf_add_cstr(u, data);
		ubuf_add(u, '\n');
		my_free(data);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD) {
		wdns_domain_to_str(e->name.data, e->name.len, name);
		ubuf_add_cstr(u, name);
		fmt_rrtypes_union(u, e);
		ubuf_append_cstr_lit(u, " ;; rrset name fwd\n");
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV) {
		wdns_domain_to_str(e->name.data, e->name.len, name);
		ubuf_add_cstr(u, name);
		fmt_rrtypes_union(u, e);
		ubuf_append_cstr_lit(u, " ;; rdata name rev\n");
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_TIME_RANGE) {
		ubuf_append_cstr_lit(u, ";; Earliest time_first: ");
		time_formatter(u, e->time_first);
		ubuf_append_cstr_lit(u, "\n;; Latest time_last: ");
		time_formatter(u, e->time_last);
		ubuf_add(u, '\n');
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_VERSION) {
		char buf[128];
		const char *vtype = dnstable_entry_type_to_string(e->v_type);
		int ret;

		if (vtype == NULL)
			ret = snprintf(buf, sizeof(buf), ";; Version type %u: %u\n",
				(unsigned)e->v_type, (unsigned)e->version);
		else
			ret = snprintf(buf, sizeof(buf), ";; Version type %s: %u\n",
				vtype, (unsigned)e->version);
		ubuf_append(u, (const uint8_t*) buf, ret);

	}

	ubuf_cterm(u);
	ubuf_detach(u, &s, &len_s);
out:
	ubuf_destroy(&u);
	return ((char *) (s));
}

char *
dnstable_entry_to_text(const struct dnstable_entry *e)
{
	return dnstable_entry_to_text_fmt(e, dnstable_date_format_unix);
}

static char *
dnstable_entry_to_json_fmt(const struct dnstable_entry *e,
			   dnstable_date_format_type date_format,
			   bool always_array, bool add_raw_rdata)
{
	uint8_t *s = NULL;
	char name[WDNS_PRESLEN_NAME];
	size_t len;
	ubuf *u;
	void (*time_formatter)(ubuf *, uint64_t);

	time_formatter = (date_format == dnstable_date_format_unix) ?
		append_json_value_int : fmt_rfc3339_time_json;

	u = ubuf_init(256);


	ubuf_append(u, (const uint8_t *)"{", 1);

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		/* count */
		declare_json_value(u, "count", true);

		append_json_value_int(u, e->count);

		/* first seen */
		if (e->iszone)
			declare_json_value(u, "zone_time_first", false);
		else
			declare_json_value(u, "time_first", false);

		time_formatter(u, e->time_first);

		/* last seen */
		if (e->iszone)
			declare_json_value(u, "zone_time_last", false);
		else
			declare_json_value(u, "time_last", false);


		time_formatter(u, e->time_last);

		/* rrname */
		declare_json_value(u, "rrname", false);

		wdns_domain_to_str(e->name.data, e->name.len, name);
		append_json_value_string(u, name, strlen(name));

		/* rrtype */
		declare_json_value(u, "rrtype", false);
		fmt_rrtype_json(u, e->rrtype);
	}

	if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET) {
		/* bailiwick */
		declare_json_value(u, "bailiwick", false);

		wdns_domain_to_str(e->bailiwick.data, e->bailiwick.len, name);
		append_json_value_string(u, name, strlen(name));

		/* resource records */
		declare_json_value(u, "rdata", false);
		ubuf_append(u, (const uint8_t *)"[", 1);

		const size_t n_rdatas = rdata_vec_size(e->rdatas);
		for (size_t i = 0; i < n_rdatas; i++) {
			wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, i);
			char *data = wdns_rdata_to_str(rdata->data, rdata->len,
						       e->rrtype, WDNS_CLASS_IN);
			append_json_value_string(u, data, strlen(data));
			my_free(data);

			if (i + 1 < n_rdatas)
				ubuf_append(u, (const uint8_t *)",", 1);
		}

		ubuf_append(u, (const uint8_t *)"]", 1);

		if (add_raw_rdata) {
			declare_json_value(u, "rdata_raw", false);
			ubuf_append(u, (const uint8_t *)"[", 1);

			for (size_t i = 0; i < n_rdatas; i++) {
				wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, i);
				ubuf *rbuf = ubuf_init(2 * rdata->len + 1);
				uint8_t *rbuf_as_str = NULL;
				size_t rbuf_as_str_len = 0;

				fmt_hex_str(rbuf, rdata->data, rdata->len);

				/* append the rrtype - 16 bit rrtype will be at most 3 bytes of varint */
				uint8_t rrtype[3];
				size_t rrtype_str_len = mtbl_varint_encode32(rrtype, e->rrtype);

				fmt_hex_str(rbuf, rrtype, rrtype_str_len);
				ubuf_cterm(rbuf);
				ubuf_detach(rbuf, &rbuf_as_str, &rbuf_as_str_len);
				ubuf_destroy(&rbuf);
				append_json_value_string(u, (const char *)rbuf_as_str, strlen((const char *)rbuf_as_str));
				my_free(rbuf_as_str);

				if (i + 1 < n_rdatas)
					ubuf_append(u, (const uint8_t *)",", 1);
			}

			ubuf_append(u, (const uint8_t *)"]", 1);
		}
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA) {
		if (rdata_vec_size(e->rdatas) != 1)
			goto out;

		/* rdata */
		declare_json_value(u, "rdata", false);

		wdns_rdata_t *rdata = rdata_vec_value(e->rdatas, 0);
		char *data = wdns_rdata_to_str(rdata->data, rdata->len,
					       e->rrtype, WDNS_CLASS_IN);

		if (always_array)
			ubuf_append(u, (const uint8_t *)"[", 1);

		append_json_value_string(u, data, strlen(data));
		my_free(data);

		if (always_array)
			ubuf_append(u, (const uint8_t *)"]", 1);

		if (add_raw_rdata) {
			declare_json_value(u, "rdata_raw", false);

			if (always_array)
				ubuf_append(u, (const uint8_t *)"[", 1);

			ubuf *rbuf = ubuf_init(2 * rdata->len + 1);
			uint8_t *rbuf_as_str = NULL;
			size_t rbuf_as_str_len = 0;

			fmt_hex_str(rbuf, rdata->data, rdata->len);
			ubuf_cterm(rbuf);
			ubuf_detach(rbuf, &rbuf_as_str, &rbuf_as_str_len);
			ubuf_destroy(&rbuf);
			append_json_value_string(u, (const char *)rbuf_as_str, strlen((const char *)rbuf_as_str));
			my_free(rbuf_as_str);

			if (always_array)
				ubuf_append(u, (const uint8_t *)"]", 1);
		}
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD) {
		declare_json_value(u, "rrset_name", true);
		wdns_domain_to_str(e->name.data, e->name.len, name);
		append_json_value_string(u, name, strlen(name));
		fmt_rrtypes_union_json(u, e);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV) {
		declare_json_value(u, "rdata_name", true);
		wdns_domain_to_str(e->name.data, e->name.len, name);
		append_json_value_string(u, name, strlen(name));
		fmt_rrtypes_union_json(u, e);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_TIME_RANGE) {
		declare_json_value(u, "time_first", true);
		time_formatter(u, e->time_first);
		declare_json_value(u, "time_last", false);
		time_formatter(u, e->time_last);
	} else if (e->e_type == DNSTABLE_ENTRY_TYPE_VERSION) {
		const char *vtype = dnstable_entry_type_to_string(e->v_type);
		char buf[sizeof("unknown-255")];

		if (vtype == NULL) {
			snprintf(buf, sizeof(buf), "unknown-%d", (uint8_t)e->v_type);
			vtype = buf;
		}
		declare_json_value(u, "entry_type", true);
		append_json_value_string(u, vtype, strlen(vtype));
		declare_json_value(u, "version", false);
		append_json_value_int(u, e->version);
	}

	ubuf_append(u, (const uint8_t *)"}", 1);

	ubuf_cterm(u);
	ubuf_detach(u, &s, &len);
out:
	ubuf_destroy(&u);
	return ((char *) s);
}


char *
dnstable_entry_to_json(const struct dnstable_entry *e)
{
	return dnstable_entry_to_json_fmt(e, dnstable_date_format_unix, false, false);
}

struct dnstable_formatter *
dnstable_formatter_init(void)
{
	struct dnstable_formatter *f = my_calloc(1, sizeof(*f));
	f->output_format = dnstable_output_format_json;
	f->date_format = dnstable_date_format_unix;
	f->always_array = false;
	f->add_raw_rdata = false;
	return (f);
}

void
dnstable_formatter_destroy(struct dnstable_formatter **fp)
{
	if (*fp)
		my_free(*fp);
}

void
dnstable_formatter_set_output_format(
    struct dnstable_formatter *f,
    dnstable_output_format_type format)
{
	assert(f != NULL);
	f->output_format = format;
}

void
dnstable_formatter_set_date_format(
   struct dnstable_formatter *f,
   dnstable_date_format_type format)
{
	assert(f != NULL);
	f->date_format = format;
}

/* If always_array is true, the rdata is always rendered as an array, even if there is only
  one rdata value. Default is false, in which case an rrset with only one rdata value
  will have the rdata rendered as a single string. */
void
dnstable_formatter_set_rdata_array(
    struct dnstable_formatter *f,
    bool always_array)
{
	assert(f != NULL);
	f->always_array = always_array;
}

/*
 * If add_raw_rdata is true, the returned JSON objects will contain an
 * additional raw_rdata field.  Default is false.
 */
void
dnstable_formatter_set_raw_rdata(
    struct dnstable_formatter *f,
    bool add_raw_rdata)
{
	assert(f != NULL);
	f->add_raw_rdata = add_raw_rdata;
}

/* Returns dynamically allocated string with the entry rendered in json format */
char *
dnstable_entry_format(
   const struct dnstable_formatter *f,
   const struct dnstable_entry *ent)
{
	assert(f != NULL);
	if (f->output_format == dnstable_output_format_json)
		return dnstable_entry_to_json_fmt(ent, f->date_format, f->always_array, f->add_raw_rdata);
	else
		return dnstable_entry_to_text_fmt(ent, f->date_format);
}

/*------------------------------------------------------------*/

static dnstable_res
decode_val_triplet(struct dnstable_entry *e, const uint8_t *val, size_t len_val)
{
	dnstable_res res;

	res = triplet_unpack(val, len_val, &e->time_first, &e->time_last, &e->count);
	if (res == dnstable_res_success) {
		/* Fixups for "odd" data patterns. */
		if (e->count == 0) {
			e->count = 1;
		}
		if (e->time_last == 0) {
			e->time_last = e->time_first;
		}
	}

	return (res);
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
decode_rrset_name_fwd(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf, const uint8_t *val, size_t len_val)
{
	e->name.len = len_buf;
	e->name.data = my_malloc(len_buf);
	memcpy(e->name.data, buf, len_buf);
	if (len_val > 0) {
		e->rrtype_map = ubuf_init(len_val);
		ubuf_append(e->rrtype_map, val, len_val);
	}
	return (dnstable_res_success);
}

static dnstable_res
decode_rdata_name_rev(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf, const uint8_t *val, size_t len_val)
{
	e->name.len = len_buf;
	e->name.data = my_malloc(len_buf);
	if (wdns_reverse_name(buf, len_buf, e->name.data) != wdns_res_success)
		return (dnstable_res_failure);

	if (len_val > 0) {
		e->rrtype_map = ubuf_init(len_val);
		ubuf_append(e->rrtype_map, val, len_val);
	}

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
	len_data = le16toh(len_data);

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

static dnstable_res
decode_time_range(struct dnstable_entry *e, const uint8_t *buf, size_t len_buf)
{
	return pair_unpack(buf, len_buf, &e->time_first, &e->time_last);
}

static dnstable_res
decode_version(struct dnstable_entry *e,
	       const uint8_t *key, size_t len_key,
	       const uint8_t *val, size_t len_val)
{
	size_t len;

	if (len_key != 1 || len_val == 0)
		return (dnstable_res_failure);

	e->v_type = key[0];
	len = mtbl_varint_decode32(val, &e->version);
	if (len == len_val)
		return (dnstable_res_success);

	return (dnstable_res_failure);
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
		if (decode_rrset_name_fwd(e, key+1, len_key-1, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_RDATA:
		e->e_type = DNSTABLE_ENTRY_TYPE_RDATA;
		if (decode_rdata(e, key+1, len_key-1) != dnstable_res_success) goto err;
		if (decode_val_triplet(e, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_RDATA_NAME_REV:
		e->e_type = DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV;
		if (decode_rdata_name_rev(e, key+1, len_key-1, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_TIME_RANGE:
		e->e_type = DNSTABLE_ENTRY_TYPE_TIME_RANGE;
		if (decode_time_range(e, val, len_val) != dnstable_res_success) goto err;
		break;
	case ENTRY_TYPE_VERSION:
		e->e_type = DNSTABLE_ENTRY_TYPE_VERSION;
		if (decode_version(e, key+1, len_key-1, val, len_val) != dnstable_res_success) goto err;
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

const char *
dnstable_entry_type_to_string(dnstable_entry_type t)
{
	switch(t) {
	case DNSTABLE_ENTRY_TYPE_RRSET:
		return "rrset";
	case DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD:
		return "rrset_name";
	case DNSTABLE_ENTRY_TYPE_RDATA:
		return "rdata";
	case DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV:
		return "rdata_name";
	case DNSTABLE_ENTRY_TYPE_TIME_RANGE:
		return "time_range";
	case DNSTABLE_ENTRY_TYPE_VERSION:
		return "version";
	}
	return NULL;
}

dnstable_res
dnstable_entry_type_from_string(dnstable_entry_type *t, const char *str)
{
	int i;

	struct {
		const char *string;
		dnstable_entry_type type;
	} types[] = {
		{"rrset", DNSTABLE_ENTRY_TYPE_RRSET},
		{"rrset_name", DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD},
		{"rdata", DNSTABLE_ENTRY_TYPE_RDATA},
		{"rdata_name", DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV},
		{"time_range", DNSTABLE_ENTRY_TYPE_TIME_RANGE},
		{"version", DNSTABLE_ENTRY_TYPE_VERSION},
		{0},
	};

	for (i = 0; types[i].string; i++) {
		if (strcmp(str, types[i].string))
			continue;
		*t = types[i].type;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
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
		*v = (uint16_t)e->rrtype;
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
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_TIME_RANGE)
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
	    e->e_type == DNSTABLE_ENTRY_TYPE_RDATA ||
	    e->e_type == DNSTABLE_ENTRY_TYPE_TIME_RANGE)
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

dnstable_res
dnstable_entry_get_version(struct dnstable_entry *e, uint32_t *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_VERSION) {
		*v = e->version;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

dnstable_res
dnstable_entry_get_version_type(struct dnstable_entry *e, dnstable_entry_type *v)
{
	if (e->e_type == DNSTABLE_ENTRY_TYPE_VERSION) {
		/*
		 * The enum dnstable_entry_type values are the same as the
		 * corresponding entry encoding's type byte, which allows
		 * a simple caset to convert from type byte to enum
		 * dnstable_entry_type
		 */
		*v = (dnstable_entry_type)e->v_type;
		return (dnstable_res_success);
	}
	return (dnstable_res_failure);
}

/*------------------------------------------------------------*/

int
rrtype_union_unpack(const uint8_t *rrtype_map, size_t rrtype_map_size, rrtype_unpacked_set *rrtype_set)
{
	unsigned count_rrtypes = 0;

	if (rrtype_map_size == 0) {
		return 0;
	} else if (rrtype_map_size == 1) {
		rrtype_set->rrtypes[0] = (uint16_t)*rrtype_map;
		return 1;
	} else if (rrtype_map_size == 2) {
		rrtype_set->rrtypes[0] = (uint16_t)le16toh(*(uint16_t*)rrtype_map);
		return 1;
	}

	/* must be a bitmap */

	bool saw_a_block = false;
	uint8_t prev_window_block = 0;

	while (rrtype_map_size >= 2) {
		uint8_t window_block = *rrtype_map;
		uint8_t block_len = *(rrtype_map + 1);

		/* ensure block numbers are incrementing */
		if (saw_a_block && window_block <= prev_window_block)
			return -1; /* corrupt encoding */
		prev_window_block = window_block;
		saw_a_block = true;

		rrtype_map_size -= 2;
		rrtype_map += 2;

		if (block_len < 1 || rrtype_map_size < block_len)
			return -1; /* corrupt encoding */

		uint16_t lo = 0;
		for (unsigned i = 0; i < block_len; i++) {
			uint8_t a = rrtype_map[i];
			for (unsigned j = 1; j <= 8; j++) {
				uint8_t is_bit_set = a & (1 << (8 - j));
				if (is_bit_set != 0) {
					/* if not too many rrtypes in the map, then add to our output */
					if (count_rrtypes < sizeof(rrtype_unpacked_set) / sizeof(uint16_t)) {
						/* re-form the rrtype */
						rrtype_set->rrtypes[count_rrtypes++] = (window_block << 8) | lo;
					} else
						return -1; /* too many rrtypes to unpack, an error */
				}
				lo += 1;
			}
		}
		rrtype_map_size -= block_len;
		rrtype_map += block_len;
	}

	if (rrtype_map_size != 0) /* got trailing data that's not a valid additional block to unpack, an error */
		return -1;

	return count_rrtypes;
}

/*
 * Check if the specified rrytpe is present in the RRtype union.
 *
 * Return true if the bit is set, the RRtype union is corrupt, or if
 * entry has no rrtype set (as a value of true will necessarily force
 * a lookup of the indicated rrtype).
 * Returns false if the bit is not set.
 */
static bool
rrtype_union_check(uint16_t rrtype, const uint8_t *rrtype_map, size_t rrtype_map_size)
{
	if (rrtype_map_size == (signed)0) {
		return true;   /* effectively all bits are present since we don't have any specific optimization */
	} else if (rrtype_map_size == (signed)1) {
		return (rrtype == (uint16_t)*rrtype_map);
	} else if (rrtype_map_size == (signed)2) {
		return (rrtype == (uint16_t)le16toh(*(uint16_t*)rrtype_map));
	}

	/* must be a bitmap */

	uint8_t want_window = rrtype / 256;

	uint8_t offset = rrtype % 256;
	uint8_t byte = offset / 8;
	uint8_t bit = offset % 8;
	uint8_t net_order_bit = 0x80 >> bit;

	while (rrtype_map_size >= 2) {
		uint8_t window_block = *rrtype_map;
		uint8_t block_len = *(rrtype_map + 1);
		rrtype_map_size -= 2;
		rrtype_map += 2;
		if (rrtype_map_size < block_len)
			return true; /* corrupt encoding; treat as if all bits are present */

		if (window_block != want_window) {
			rrtype_map_size -= block_len;
			rrtype_map += block_len;
			continue;
		}

		/* at the right block; are there enough bytes in this block? */
		if (byte > block_len)
			return false;
		return (rrtype_map[byte] & net_order_bit);
	}

	if (rrtype_map_size != 0) /* got trailing data that's not a valid additional block to unpack, an error */
		return true;

	/*
	 * Ran out of blocks to check; might be that the window blocks
	 * only covered rrtypes 1 to 255 and checking for rrtype 256.
	 */
	return false;
}

bool
rrtype_test(dnstable_entry_type e_type, uint16_t rrtype, const uint8_t *rrtype_map, size_t rrtype_map_size)
{
	if (rrtype_map == NULL || rrtype_map_size == 0) {
		/*
		 * For testing an rrtype against the rrtype union: length = 0 means we
		 * should treat the index as set for all rrtypes for which we do
		 * corresponding rrtype indexing.
		 *
		 * For RRSET_NAME_FWD, we index any rrtype.
		 *
		 * For RDATA_NAME_REV, we index rrtypes NS, CNAME, SOA, PTR, MX, SRV, DNAME, SVCB, and HTTPS.
		 */

		static const uint16_t all_rrtypes_for_RDATA_NAME_REV[] = {
			WDNS_TYPE_NS, WDNS_TYPE_CNAME, WDNS_TYPE_SOA, WDNS_TYPE_PTR, WDNS_TYPE_MX,
			WDNS_TYPE_SRV, WDNS_TYPE_DNAME, WDNS_TYPE_SVCB, WDNS_TYPE_HTTPS
		};

		if (e_type == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD)
			return true;
		else if (e_type == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV) {
			/* search for rrtype in all_rrtypes_for_RDATA_NAME_REV and send back true if present */
			for (size_t i = 0; i < sizeof(all_rrtypes_for_RDATA_NAME_REV) / sizeof(uint16_t); i++)
				if (rrtype == all_rrtypes_for_RDATA_NAME_REV[i])
					return true;
			return false;
		}
	}

	return rrtype_union_check(rrtype, rrtype_map, rrtype_map_size);
}
