/*
 * Copyright (c) 2012, 2014-2015, 2019-2023 by Farsight Security, Inc.
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
	DNSTABLE_ENTRY_TYPE_TIME_RANGE = 254,
	DNSTABLE_ENTRY_TYPE_VERSION = 255,
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
	DNSTABLE_QUERY_TYPE_TIME_RANGE = 254,
	DNSTABLE_QUERY_TYPE_VERSION = 255,
} dnstable_query_type;

typedef enum {
	DNSTABLE_STAT_STAGE_FILESET = 0,
	DNSTABLE_STAT_STAGE_FILTER_SINGLE_LABEL = 1,
	DNSTABLE_STAT_STAGE_FILTER_RRTYPE = 2,
	DNSTABLE_STAT_STAGE_FILTER_BAILIWICK = 3,
	DNSTABLE_STAT_STAGE_FILTER_TIME_STRICT = 4,
	DNSTABLE_STAT_STAGE_REMOVE_STRICT = 5,
	DNSTABLE_STAT_STAGE_FILL_MERGER = 6,
	DNSTABLE_STAT_STAGE_LJOIN = 7,
	DNSTABLE_STAT_STAGE_FILTER_TIME = 8,
	DNSTABLE_STAT_STAGE_FILTER_OFFSET = 9,
} dnstable_stat_stage;

typedef enum {
	DNSTABLE_STAT_CATEGORY_FILTERED = 0,
	DNSTABLE_STAT_CATEGORY_ENTRIES = 1,
	DNSTABLE_STAT_CATEGORY_SEEK = 2,
	DNSTABLE_STAT_CATEGORY_MERGED = 3,
	DNSTABLE_STAT_CATEGORY_FILES = 4,
} dnstable_stat_category;

const char *
dnstable_stat_stage_to_str(dnstable_stat_stage);

dnstable_res
dnstable_stat_str_to_stage(const char *, dnstable_stat_stage *);

const char *
dnstable_stat_category_to_str(dnstable_stat_category);

dnstable_res
dnstable_stat_str_to_category(const char *, dnstable_stat_category *);

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

typedef dnstable_res
(*dnstable_iter_stat_func)(const void *,
	dnstable_stat_stage, dnstable_stat_category, bool *, uint64_t *);

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
dnstable_iter_set_stat_func(struct dnstable_iter *, dnstable_iter_stat_func);

dnstable_res
dnstable_iter_get_count(struct dnstable_iter *,
	dnstable_stat_stage,
	dnstable_stat_category,
	bool *,
	uint64_t *);

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
dnstable_query_set_case_sensitive(struct dnstable_query *q, bool case_sensitive);

dnstable_res
dnstable_query_set_data(struct dnstable_query *,
			const char *);

dnstable_res
dnstable_query_set_rrtype(struct dnstable_query *,
			  const char *);

dnstable_res
dnstable_query_set_offset(struct dnstable_query *,
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
dnstable_reader_iter_time_range(struct dnstable_reader *);

struct dnstable_iter *
dnstable_reader_iter_version(struct dnstable_reader *);

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
dnstable_entry_to_text(const struct dnstable_entry *);

char *
dnstable_entry_to_json(const struct dnstable_entry *);

/* more advanced formatting */

typedef enum {
   dnstable_output_format_json,
   dnstable_output_format_text
} dnstable_output_format_type;

typedef enum {
   dnstable_date_format_unix, /* timestamps in Unix seconds since the epoch */
   dnstable_date_format_rfc3339 /* timestamps in RFC3339 string form */
} dnstable_date_format_type;

struct dnstable_formatter *
dnstable_formatter_init(void);

void
dnstable_formatter_destroy(struct dnstable_formatter **fp);

void
dnstable_formatter_set_output_format(
    struct dnstable_formatter *f,
    dnstable_output_format_type format);

void
dnstable_formatter_set_date_format(
    struct dnstable_formatter *f,
    dnstable_date_format_type format);

/* If always_array is true, the rdata is always rendered as an array, even if there is only
  one rdata value. Default is false, in which case an rrset with only one rdata value
  will have the rdata rendered as a single string. */
void
dnstable_formatter_set_rdata_array(
   struct dnstable_formatter *f, bool always_array);

/* If add_raw_rdata is true, the returned JSON objects will contain an
   additional raw_rdata field.  Default is false. */
void
dnstable_formatter_set_raw_rdata(
   struct dnstable_formatter *f, bool add_raw_rdata);

/* Returns dynamically allocated string with the entry rendered in json format */
char *
dnstable_entry_format(
   const struct dnstable_formatter *f,
   const struct dnstable_entry *ent);

/* accessors for dnstable_entry */

dnstable_entry_type
dnstable_entry_get_type(struct dnstable_entry *);

void
dnstable_entry_set_iszone(struct dnstable_entry *, bool);

const char *
dnstable_entry_type_to_string(dnstable_entry_type);

dnstable_res
dnstable_entry_type_from_string(dnstable_entry_type *, const char *);

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
 *	entry_type_time_range
 */
dnstable_res
dnstable_entry_get_time_first(
	struct dnstable_entry *,
	uint64_t *time_first);

/**
 * valid for:
 *	entry_type_rrset
 *	entry_type_rdata
 *	entry_type_time_range
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

/**
 * valid for:
 *	entry_type_version
 */
dnstable_res
dnstable_entry_get_version(
	struct dnstable_entry *,
	uint32_t *version);

/**
 * valid for:
 *	entry_type_version
 */
dnstable_res
dnstable_entry_get_version_type(
	struct dnstable_entry *,
	dnstable_entry_type *);

#ifdef __cplusplus
}
#endif

#endif /* DNSTABLE_H */
