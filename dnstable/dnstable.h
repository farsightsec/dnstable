/*
 * Copyright (c) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef DNSTABLE_H
#define DNSTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include <mtbl.h>

struct dnstable_entry;
struct dnstable_iter;
struct dnstable_query;
struct dnstable_reader;

typedef enum {
	dnstable_res_failure = 0,
	dnstable_res_success = 1
} dnstable_res;

typedef enum {
	DNSTABLE_ENTRY_TYPE_RRSET = 0,
	DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD = 1,
	DNSTABLE_ENTRY_TYPE_RDATA = 2,
	DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV = 3,
} dnstable_entry_type;

typedef enum {
	DNSTABLE_QUERY_TYPE_RRSET = 0,
	DNSTABLE_QUERY_TYPE_RDATA_NAME = 1,
	DNSTABLE_QUERY_TYPE_RDATA_IP = 2,
	DNSTABLE_QUERY_TYPE_RDATA_RAW = 3,
} dnstable_query_type;

/* merge func */

void
dnstable_merge_func(void *clos,
		    const uint8_t *key, size_t len_key,
		    const uint8_t *val0, size_t len_val0,
		    const uint8_t *val1, size_t len_val1,
		    uint8_t **merged_val, size_t *len_merged_val);

/* iter */

typedef dnstable_res
(*dnstable_iter_next_func)(void *, struct dnstable_entry **);

typedef void
(*dnstable_iter_free_func)(void *);

struct dnstable_iter *
dnstable_iter_init(
	dnstable_iter_next_func,
	dnstable_iter_free_func,
	void *);

dnstable_res
dnstable_iter_next(
	struct dnstable_iter *,
	struct dnstable_entry **)
__attribute__((warn_unused_result));

void
dnstable_iter_destroy(struct dnstable_iter **);

/* query */

struct dnstable_query *
dnstable_query_init(dnstable_query_type);

void
dnstable_query_destroy(struct dnstable_query **);

const char *
dnstable_query_get_error(struct dnstable_query *);

dnstable_res
dnstable_query_set_data(struct dnstable_query *,
			const char *);

dnstable_res
dnstable_query_set_rrtype(struct dnstable_query *,
			  const char *);

dnstable_res
dnstable_query_set_bailiwick(struct dnstable_query *,
			     const char *);

dnstable_res
dnstable_query_filter(struct dnstable_query *, struct dnstable_entry *, bool *);

struct dnstable_iter *
dnstable_query_iter(struct dnstable_query *, const struct mtbl_source *);

/* reader */

struct dnstable_reader *
dnstable_reader_init(const struct mtbl_source *);

struct dnstable_reader *
dnstable_reader_init_fname(const char *);

void
dnstable_reader_destroy(struct dnstable_reader **);

struct dnstable_iter *
dnstable_reader_iter(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_query(struct dnstable_reader *, struct dnstable_query *);

/* entry */

struct dnstable_entry *
dnstable_entry_decode(
	const uint8_t *key, size_t len_key,
	const uint8_t *val, size_t len_val);

void
dnstable_entry_destroy(struct dnstable_entry **);

char *
dnstable_entry_to_text(struct dnstable_entry *);

dnstable_entry_type
dnstable_entry_get_type(struct dnstable_entry *);

/*
 * valid for:
 *	entry_type_rrset
 *	entry_type_rrset_name_fwd
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_rrname(
	struct dnstable_entry *,
	const uint8_t **owner, size_t *len_owner);

/*
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_rrtype(
	struct dnstable_entry *,
	uint16_t *rrtype);

/*
 * valid for:
 *	entry_type_rrset
 */
dnstable_res
dnstable_entry_get_bailiwick(
	struct dnstable_entry *,
	const uint8_t **bailiwick, size_t *len_bailiwick);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_num_rdata(
	struct dnstable_entry *,
	size_t *num_rdata);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_rdata(
	struct dnstable_entry *, size_t,
	const uint8_t **rdata, size_t *len_rdata);

/**
 * valid for
 *	entry_type_rdata_name_rev
 */
dnstable_res
dnstable_entry_get_rdata_name(
	struct dnstable_entry *,
	const uint8_t **rdata_name, size_t *len_rdata_name);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_time_first(
	struct dnstable_entry *,
	uint64_t *time_first);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_time_last(
	struct dnstable_entry *,
	uint64_t *time_last);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 */
dnstable_res
dnstable_entry_get_count(
	struct dnstable_entry *,
	uint64_t *count);

#ifdef __cplusplus
}
#endif

#endif /* DNSTABLE_H */
