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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <locale.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>
#include <nmsg.h>
#include <nmsg/isc/defs.h>
#include <nmsg/sie/dnsdedupe.pb-c.h>
#include <wdns.h>

#include "dnstable-private.h"
#include "vector_types.h"

static const char		*nmsg_fname;
static const char		*db_fname;
static const char		*db_dnssec_fname;

static nmsg_input_t		input;
static struct mtbl_sorter	*sorter;
static struct mtbl_sorter	*sorter_dnssec;
static struct mtbl_writer	*writer;
static struct mtbl_writer	*writer_dnssec;

static struct timespec		start_time;
static uint64_t			count_messages;
static uint64_t			count_entries;
static uint64_t			count_entries_dnssec;
static uint64_t			count_entries_merged;

static void
do_stats(void)
{
	struct timespec dur;
	double t_dur;

	nmsg_timespec_get(&dur);
	nmsg_timespec_sub(&start_time, &dur);
	t_dur = nmsg_timespec_to_double(&dur);

	fprintf(stderr, "processed "
			"%'" PRIu64 " messages, "
			"%'" PRIu64 " entries (%'" PRIu64 " DNSSEC, %'" PRIu64 " merged) "
			"in %'.2f sec, %'d msg/sec, %'d ent/sec"
			"\n",
		count_messages,
		count_entries,
		count_entries_dnssec,
		count_entries_merged,
		t_dur,
		(int) (count_messages / t_dur),
		(int) (count_entries / t_dur)
	);
}

static void
merge_func(void *clos,
	   const uint8_t *key, size_t len_key,
	   const uint8_t *val0, size_t len_val0,
	   const uint8_t *val1, size_t len_val1,
	   uint8_t **merged_val, size_t *len_merged_val)
{
	dnstable_merge_func(clos,
			    key, len_key,
			    val0, len_val0,
			    val1, len_val1,
			    merged_val, len_merged_val);
	count_entries_merged += 1;
}

static void
add_entry(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val) {
	mtbl_res res;
	switch (dns->rrtype) {
	case WDNS_TYPE_DS:
	case WDNS_TYPE_RRSIG:
	case WDNS_TYPE_NSEC:
	case WDNS_TYPE_DNSKEY:
	case WDNS_TYPE_NSEC3:
	case WDNS_TYPE_NSEC3PARAM:
	case WDNS_TYPE_DLV:
		res = mtbl_sorter_add(sorter_dnssec,
				      ubuf_data(key), ubuf_size(key),
				      ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
		count_entries_dnssec += 1;
		break;
	default:
		res = mtbl_sorter_add(sorter,
				      ubuf_data(key), ubuf_size(key),
				      ubuf_data(val), ubuf_size(val));
		assert(res == mtbl_res_success);
	}
	count_entries += 1;
}

static size_t
pack_triplet(uint8_t *orig_buf, uint64_t val1, uint64_t val2, uint64_t val3)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	buf += mtbl_varint_encode64(buf, val3);
	return (buf - orig_buf);
}

static void
put_triplet(Nmsg__Sie__DnsDedupe *dns, ubuf *val)
{
	uint64_t time_first, time_last, count;

	if (dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__AUTHORITATIVE ||
	    dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__MERGED_AUTHORITATIVE)
	{
		time_first = dns->zone_time_first;
		time_last = dns->zone_time_last;
	} else {
		time_first = dns->time_first;
		time_last = dns->time_last;
	}

	if (dns->type == NMSG__SIE__DNS_DEDUPE_TYPE__INSERTION)
		count = 0;
	else
		count = dns->count;

	ubuf_reserve(val, 32);
	ubuf_advance(val, pack_triplet(ubuf_data(val), time_first, time_last, count));
}

static void
process_rrset(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val)
{
	uint8_t name[WDNS_MAXLEN_NAME];

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RRSET);

	/* key: rrset owner name (label-reversed) */
	wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: bailiwick name (label-reversed) */
	wdns_reverse_name(dns->bailiwick.data, dns->bailiwick.len, name);
	ubuf_append(key, name, dns->bailiwick.len);

	/* key: rdata array (varint encoded rdata lengths) */
	for (size_t i = 0; i < dns->n_rdata; i++) {
		ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rdata[i].len));
		ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rdata[i].len));
		ubuf_append(key, dns->rdata[i].data, dns->rdata[i].len);
	}

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

static void
process_rrset_name_fwd(Nmsg__Sie__DnsDedupe *dns, ubuf *key, ubuf *val)
{
	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RRSET_NAME_FWD);

	/* key: rrset owner name */
	ubuf_append(key, dns->rrname.data, dns->rrname.len);

	add_entry(dns, key, val);
}

static void
process_rdata(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	uint16_t rdlen;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA);

	/* key: rdata */
	ubuf_append(key, dns->rdata[i].data, dns->rdata[i].len);

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: rrname (label-reversed) */
	wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rdlen */
	assert(dns->rdata[i].len <= 65535);
	rdlen = (uint16_t) dns->rdata[i].len;
	ubuf_reserve(key, ubuf_size(key) + sizeof(uint16_t));
	ubuf_append(key, (uint8_t *) &rdlen, sizeof(uint16_t));

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

static void
process_rdata_slice(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	uint8_t name[WDNS_MAXLEN_NAME];
	size_t offset;

	switch (dns->rrtype) {
	case WDNS_TYPE_MX:
		offset = 2;
		break;
	case WDNS_TYPE_SRV:
		offset = 2;
		break;
	default:
		return;
	}

	if (dns->rdata[i].len == 0 || dns->rdata[i].len <= offset)
		return;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA);

	/* key: data */
	ubuf_append(key, dns->rdata[i].data + offset, dns->rdata[i].len - offset);

	/* key: rrtype (varint encoded) */
	ubuf_reserve(key, ubuf_size(key) + mtbl_varint_length(dns->rrtype));
	ubuf_advance(key, mtbl_varint_encode32(ubuf_ptr(key), dns->rrtype));

	/* key: rrname (label-reversed) */
	wdns_reverse_name(dns->rrname.data, dns->rrname.len, name);
	ubuf_append(key, name, dns->rrname.len);

	/* key: rdata slice */
	ubuf_append(key, dns->rdata[i].data, offset);

	/* key: data length */
	uint16_t dlen = (uint16_t) dns->rdata[i].len - offset;
	ubuf_reserve(key, ubuf_size(key) + sizeof(uint16_t));
	ubuf_append(key, (uint8_t *) &dlen, sizeof(uint16_t));

	/* val: time_first, time_last, count (varint) */
	put_triplet(dns, val);

	add_entry(dns, key, val);
}

static void
process_rdata_name_rev(Nmsg__Sie__DnsDedupe *dns, size_t i, ubuf *key, ubuf *val)
{
	size_t offset;
	uint8_t name[WDNS_MAXLEN_NAME];

	switch (dns->rrtype) {
	case WDNS_TYPE_NS:
	case WDNS_TYPE_CNAME:
	case WDNS_TYPE_DNAME:
	case WDNS_TYPE_PTR:
		offset = 0;
		break;
	case WDNS_TYPE_MX:
		offset = 2;
		break;
	case WDNS_TYPE_SRV:
		offset = 6;
		break;
	default:
		return;
	}

	if (dns->rdata[i].len == 0 || dns->rdata[i].len <= offset)
		return;

	/* clear key, val */
	ubuf_clip(key, 0);
	ubuf_clip(val, 0);

	/* key: type byte */
	ubuf_add(key, ENTRY_TYPE_RDATA_NAME_REV);

	/* key: rdata name (label-reversed) */
	wdns_reverse_name(dns->rdata[i].data + offset, dns->rdata[i].len - offset, name);
	ubuf_append(key, name, dns->rdata[i].len - offset);

	add_entry(dns, key, val);
}

static void
do_loop(void) {
	Nmsg__Sie__DnsDedupe *dns;
	nmsg_message_t msg;
	nmsg_res res;
	ubuf *key, *val;

	key = ubuf_init(256);
	val = ubuf_init(256);

	for (;;) {
		res = nmsg_input_read(input, &msg);
		if (res == nmsg_res_eof)
			break;
		assert(res == nmsg_res_success);

		dns = (Nmsg__Sie__DnsDedupe *) nmsg_message_get_payload(msg);
		assert(dns != NULL);
		assert(dns->has_rrname);
		assert(dns->rrname.len < 256);
		assert(dns->has_rrtype);
		assert(dns->has_bailiwick);
		assert(dns->n_rdata > 0);

		process_rrset(dns, key, val);
		process_rrset_name_fwd(dns, key, val);

		for (size_t i = 0; i < dns->n_rdata; i++) {
			process_rdata(dns, i, key, val);
			process_rdata_slice(dns, i, key, val);
			process_rdata_name_rev(dns, i, key, val);
		}

		nmsg_message_destroy(&msg);
		count_messages += 1;

		if ((count_messages % STATS_INTERVAL) == 0)
			do_stats();
	}

	ubuf_destroy(&key);
	ubuf_destroy(&val);
}

static void
write_table(const char *t, struct mtbl_iter *it, struct mtbl_writer *w)
{
	struct timespec start, dur;
	double t_dur;
	uint64_t count = 0;

	const uint8_t *key, *val;
	size_t len_key, len_val;

	nmsg_timespec_get(&start);
	while (mtbl_iter_next(it, &key, &len_key, &val, &len_val) == mtbl_res_success) {
		mtbl_res res = mtbl_writer_add(w, key, len_key, val, len_val);
		assert(res == mtbl_res_success);
		if ((++count % STATS_INTERVAL) == 0) {
			nmsg_timespec_get(&dur);
			nmsg_timespec_sub(&start, &dur);
			t_dur = nmsg_timespec_to_double(&dur);
			fprintf(stderr,
				"%s: wrote %'" PRIu64 " entries in %'.2f sec, %'d ent/sec\n",
				t, count, t_dur, (int) (count / t_dur));
		}
	}
	mtbl_iter_destroy(&it);
}

static void
do_write(void)
{
	struct mtbl_iter *it_dns, *it_dnssec;

	it_dns = mtbl_sorter_iter(sorter);
	assert(it_dns != NULL);

	it_dnssec = mtbl_sorter_iter(sorter_dnssec);
	assert(it_dnssec != NULL);

	do_stats();

	fprintf(stderr, "dnstable_convert: writing DNS table\n");
	write_table("dns", it_dns, writer);
	mtbl_sorter_destroy(&sorter);
	mtbl_writer_destroy(&writer);

	fprintf(stderr, "dnstable_convert: writing DNSSEC table\n");
	write_table("dnssec", it_dnssec, writer_dnssec);
	mtbl_sorter_destroy(&sorter_dnssec);
	mtbl_writer_destroy(&writer_dnssec);
}

static void
init_nmsg(void)
{
	int fd;
	nmsg_res res;
	nmsg_msgmod_t mod;

	res = nmsg_init();
	assert(res == nmsg_res_success);
	fd = open(nmsg_fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open NMSG input file '%s': %s\n",
			nmsg_fname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	input = nmsg_input_open_file(fd);
	assert(input != NULL);

	mod = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	if (mod == NULL) {
		fprintf(stderr, "Unable to initialize SIE/dnsdedupe module\n");
		exit(EXIT_FAILURE);
	}
}

static void
init_mtbl(void)
{
	struct mtbl_sorter_options *sopt;
	struct mtbl_writer_options *wopt;

	sopt = mtbl_sorter_options_init();
	mtbl_sorter_options_set_max_memory(sopt, 2UL * 1024*1024*1024);
	mtbl_sorter_options_set_merge_func(sopt, merge_func, NULL);
	if (getenv("VARTMPDIR"))
		mtbl_sorter_options_set_temp_dir(sopt, getenv("VARTMPDIR"));

	wopt = mtbl_writer_options_init();
	mtbl_writer_options_set_compression(wopt, MTBL_COMPRESSION_ZLIB);

	mtbl_writer_options_set_block_size(wopt, DNS_MTBL_BLOCK_SIZE);
	writer = mtbl_writer_init(db_fname, wopt);

	mtbl_writer_options_set_block_size(wopt, DNSSEC_MTBL_BLOCK_SIZE);
	writer_dnssec = mtbl_writer_init(db_dnssec_fname, wopt);

	assert(writer != NULL);
	assert(writer_dnssec != NULL);

	sorter = mtbl_sorter_init(sopt);
	sorter_dnssec = mtbl_sorter_init(sopt);

	mtbl_sorter_options_destroy(&sopt);
	mtbl_writer_options_destroy(&wopt);
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <NMSG FILE> <DB FILE> <DB DNSSEC FILE>\n",
			argv[0]);
		return (EXIT_FAILURE);
	}
	nmsg_fname = argv[1];
	db_fname = argv[2];
	db_dnssec_fname = argv[3];

	init_nmsg();
	init_mtbl();
	nmsg_timespec_get(&start_time);
	do_loop();
	nmsg_input_close(&input);
	do_write();
	do_stats();

	if (count_entries_dnssec == 0) {
		fprintf(stderr, "no DNSSEC entries generated, unlinking %s\n", db_dnssec_fname);
		unlink(db_dnssec_fname);
	}

	return (EXIT_SUCCESS);
}
