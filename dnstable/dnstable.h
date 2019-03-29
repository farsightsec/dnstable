/*
 * Copyright (c) 2012, 2014-2015 by Farsight Security, Inc.
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

#ifndef DNSTABLE_H
#define DNSTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <mtbl.h>

struct dnstable_entry;
struct dnstable_iter;
struct dnstable_query;
struct dnstable_reader;

typedef enum {
	dnstable_res_failure = 0,
	dnstable_res_success = 1,
	dnstable_res_timeout = 2
} dnstable_res;

typedef enum {
	DNSTABLE_ENTRY_TYPE_RRSET = 0,
	DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD = 1,
	DNSTABLE_ENTRY_TYPE_RDATA = 2,
	DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV = 3,
} dnstable_entry_type;

typedef enum {
	DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE = 0,
	DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER = 1,
	DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE = 2,
	DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER = 3,
} dnstable_filter_parameter_type;

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
dnstable_query_set_skip(struct dnstable_query *,
			uint64_t);

dnstable_res
dnstable_query_set_aggregated(struct dnstable_query *, bool);

dnstable_res
dnstable_query_set_bailiwick(struct dnstable_query *,
			     const char *);

dnstable_res
dnstable_query_set_filter_parameter(struct dnstable_query *,
				    dnstable_filter_parameter_type,
				    const void *, const size_t);

dnstable_res
dnstable_query_set_timeout(struct dnstable_query *,
			   const struct timespec *);

dnstable_res
dnstable_query_filter(struct dnstable_query *, struct dnstable_entry *, bool *);

struct dnstable_iter *
dnstable_query_iter(struct dnstable_query *, const struct mtbl_source *);

/* reader */

struct dnstable_reader *
dnstable_reader_init(const struct mtbl_source *);

struct dnstable_reader *
dnstable_reader_init_setfile(const char *);

void
dnstable_reader_reload_setfile(struct dnstable_reader *);

void
dnstable_reader_destroy(struct dnstable_reader **);

struct dnstable_iter *
dnstable_reader_iter(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_iter_rrset(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_iter_rrset_names(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_iter_rdata(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_iter_rdata_names(struct dnstable_reader *);

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

char *
dnstable_entry_to_json(struct dnstable_entry *);

dnstable_entry_type
dnstable_entry_get_type(struct dnstable_entry *);

void
dnstable_entry_set_iszone(struct dnstable_entry *, bool);

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
