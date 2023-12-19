/*
 * Copyright (c) 2018-2021 by Farsight Security, Inc.
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wdns.h>

#include "errors.h"
#include "libmy/my_alloc.h"
#include "dnstable/dnstable.h"

#define NAME	"test-dnstable"

static int
test_basic(void)
{
	struct mtbl_reader *mreader;
	struct dnstable_reader *reader;
	struct dnstable_iter *iter;
	dnstable_res res, res2, res3, res4, res5;
	size_t n;

	mreader = mtbl_reader_init(SRCDIR "/tests/generic-tests/test.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

	// test dnstable_entry_type_to_string() for unknown entry type
	check_return(dnstable_entry_type_to_string((dnstable_entry_type)999) == NULL);

	// test dnstable_entry_type_to_string() for more entry types
	check_return(dnstable_entry_type_to_string((dnstable_entry_type)DNSTABLE_ENTRY_TYPE_TIME_RANGE) != NULL);
	check_return(dnstable_entry_type_to_string((dnstable_entry_type)DNSTABLE_ENTRY_TYPE_VERSION) != NULL);

	// test dnstable_entry_type_from_string() for entry type not found
	{
		dnstable_entry_type et;
		check_return(dnstable_entry_type_from_string(&et, "BAD") == dnstable_res_failure);
	}

	for (n = 0; n < 5; n++) {
		struct dnstable_entry *entry;

		switch(n) {
		case 0:
			iter = dnstable_reader_iter(reader);
			break;
		case 1:
			iter = dnstable_reader_iter_rrset(reader);
			break;
		case 2:
			iter = dnstable_reader_iter_rrset_names(reader);
			break;
		case 3:
			iter = dnstable_reader_iter_rdata(reader);
			break;
		case 4:
			iter = dnstable_reader_iter_rdata_names(reader);
			break;
		default:
			iter = dnstable_reader_iter(reader);
			break;
		}

		check_return(iter != NULL);

		res = dnstable_iter_next(iter, &entry);
		check_return(res == dnstable_res_success);

		dnstable_entry_type et = dnstable_entry_get_type(entry);

		if (n <= 1) {
			check_return(et == DNSTABLE_ENTRY_TYPE_RRSET);
		} else if (n == 2) {
			check_return(et == DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD);
		} else if (n == 3) {
			check_return(et == DNSTABLE_ENTRY_TYPE_RDATA);
		} else if (n == 4) {
			check_return(et == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV);
		}

		const uint8_t *owner, *bailiwick;
		size_t lowner, lbailiwick;
		uint16_t rrtype;
		res = dnstable_entry_get_rrname(entry, &owner, &lowner);

		if (n < 4) {
			check_return(res == dnstable_res_success);
//check(lowner==2);
		} else {
			check_return(res != dnstable_res_success);
		}

		res = dnstable_entry_get_rrtype(entry, &rrtype);

		if (n == 2 || n == 4) {
			check_return(res != dnstable_res_success);
		} else {
			check_return(res == dnstable_res_success);
//fprintf(stderr, "rrtype = %zu\n", rrtype);
		}

		res = dnstable_entry_get_bailiwick(entry, &bailiwick, &lbailiwick);

		if (n < 2) {
			check_return(res == dnstable_res_success);
//check lbailiwick etc
		} else {
			check_return(res != dnstable_res_success);
		}

		const uint8_t *rdata;
		uint64_t time_first, time_last, count;
		size_t nrdata, lrdata;
		res = dnstable_entry_get_num_rdata(entry, &nrdata);
		res2 = dnstable_entry_get_rdata(entry, 0, &rdata, &lrdata);
		res3 = dnstable_entry_get_time_first(entry, &time_first);
		res4 = dnstable_entry_get_time_last(entry, &time_last);
		res5 = dnstable_entry_get_count(entry, &count);

		if (n == 2 || n == 4) {
			check_return(res != dnstable_res_success);
			check_return(res2 != dnstable_res_success);
			check_return(res3 != dnstable_res_success);
			check_return(res4 != dnstable_res_success);
			check_return(res5 != dnstable_res_success);
		} else {
			check_return(res == dnstable_res_success);
			check_return(res2 == dnstable_res_success);
			check_return(res3 == dnstable_res_success);
			check_return(res4 == dnstable_res_success);
			check_return(res5 == dnstable_res_success);
//fprintf(stderr, "nrdata = %zu\n", nrdata);
//rdata
//time_first, time_last
//count
		}

		char *e_text, *e_json;

		e_text = dnstable_entry_to_text(entry);
		check_return(e_text != NULL);
		free(e_text);

		e_json = dnstable_entry_to_json(entry);
		check_return(e_json != NULL);
		free(e_json);

		struct dnstable_formatter *fmt = dnstable_formatter_init();
		dnstable_formatter_set_date_format(fmt, dnstable_date_format_rfc3339);
		e_text = dnstable_entry_format(fmt, entry);
		check_return(e_text != NULL);
		free(e_text);

		dnstable_formatter_set_output_format(fmt, dnstable_output_format_text);
		e_text = dnstable_entry_format(fmt, entry);
		check_return(e_text != NULL);
		free(e_text);

		dnstable_formatter_set_output_format(fmt, dnstable_output_format_json);
		dnstable_formatter_set_rdata_array(fmt, true);
		e_json = dnstable_entry_format(fmt, entry);
		check_return(e_text != NULL);
		free(e_json);

		dnstable_formatter_set_raw_rdata(fmt, true);
		e_json = dnstable_entry_format(fmt, entry);
		check_return(e_text != NULL);
		free(e_json);

		dnstable_entry_destroy(&entry);
		dnstable_iter_destroy(&iter);
	}


	dnstable_reader_destroy(&reader);

	l_return_test_status();
}

static int
test_filter_parameter(struct dnstable_query *query, struct dnstable_entry *entry, dnstable_filter_parameter_type tparam, uint64_t time_val_succeed, uint64_t time_val_fail) {
	dnstable_res res;
	uint64_t tmptime;
	bool passes;

	/* Reset everything. */
	tmptime = ~(0);
	res = dnstable_query_set_filter_parameter(query, DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE, &tmptime, sizeof(tmptime));
	check_return(res == dnstable_res_success);
	res = dnstable_query_set_filter_parameter(query, DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE, &tmptime, sizeof(tmptime));
	check_return(res == dnstable_res_success);

	tmptime = 0;
	res = dnstable_query_set_filter_parameter(query, DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER, &tmptime, sizeof(tmptime));
	check_return(res == dnstable_res_success);
	res = dnstable_query_set_filter_parameter(query, DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER, &tmptime, sizeof(tmptime));
	check_return(res == dnstable_res_success);

	/* Check first condition. */
	res = dnstable_query_set_filter_parameter(query, tparam, &time_val_succeed, sizeof(time_val_succeed));
	check_return(res == dnstable_res_success);
	check_return(dnstable_query_filter(query, entry, &passes) == dnstable_res_success);
	check_return(passes);

	/* Then opposite condition. */
	res = dnstable_query_set_filter_parameter(query, tparam, &time_val_fail, sizeof(time_val_fail));
	check_return(res == dnstable_res_success);
	check_return(dnstable_query_filter(query, entry, &passes) == dnstable_res_success);
	check_return(!passes);

	l_return_test_status();
}

static int
test_query_iter_stats(struct dnstable_iter *it, const int *stages, const int64_t *counters)
{
	uint64_t tcount = 0;
	const int *stage = stages;
	const int64_t *counter = counters;
	bool check_counter = false;
	bool exists;
	int sti = 0;

	while (*stage >= 0) {
		int category = 0;
		if (sti == *stage) {
			check_counter = true;
			++stage;
		}
		while (1) {
			dnstable_res res = dnstable_iter_get_count(it, sti, category++, &exists, &tcount);
			if (check_counter) {
				/*
				 * Output
				 * exists = true, res = success - got counter value
				 * exists = false, res = success - no counter but continue
				 * exists = false, res = failure - no counter, the end
				 * */

				if (!exists && res == dnstable_res_failure)
					break;
				if (exists) {
					check_return((uint64_t) *counter == tcount);
					++counter;
				}
			} else {
				check_return(tcount == 0);
				break;
			}
		}
		if (check_counter) {
			++counter;
			check_counter = false;
		}
		++sti;
	}

	return 1;
}

static int
test_query_stats_conversion(void)
{
	dnstable_stat_category dummy_cat;
	dnstable_stat_stage dummy_stage;
	int n = 0;
	const char *value;

	while (1) {
		dnstable_stat_stage stage;
		value = dnstable_stat_stage_to_str(n);
		if (value == NULL)
			break;
		check_return(dnstable_stat_str_to_stage(value, &stage) == dnstable_res_success);
		check_return((int) stage == n);
		n++;
	}

	check_return(n == (DNSTABLE_STAT_STAGE_FILTER_OFFSET + 1));

	n = 0;
	while (1) {
		dnstable_stat_category category;
		value = dnstable_stat_category_to_str(n);
		if (value == NULL)
			break;
		check_return(dnstable_stat_str_to_category(value, &category) == dnstable_res_success);
		check_return((int) category == n);
		n++;
	}

	check_return(n == (DNSTABLE_STAT_CATEGORY_FILES + 1));

	check_return(!strcasecmp(dnstable_stat_stage_to_str(DNSTABLE_STAT_STAGE_LJOIN), "left join"));
	check_return(dnstable_stat_stage_to_str(-1) == NULL);
	check_return(dnstable_stat_stage_to_str(1000) == NULL);

	check_return(!strcasecmp(dnstable_stat_category_to_str(DNSTABLE_STAT_CATEGORY_SEEK), "seek"));
	check_return(dnstable_stat_category_to_str(-1) == NULL);
	check_return(dnstable_stat_category_to_str(1000) == NULL);

	check_return(dnstable_stat_str_to_stage(NULL, NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_stage("", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_stage("abcd", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_stage(dnstable_stat_stage_to_str(DNSTABLE_STAT_STAGE_FILTER_RRTYPE), NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_stage("bailiwick", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_stage("bailiwick", &dummy_stage) == dnstable_res_success);

	check_return(dnstable_stat_str_to_category(NULL, NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_category("", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_category("abcd", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_category(dnstable_stat_category_to_str(DNSTABLE_STAT_CATEGORY_FILTERED), NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_category("merged", NULL) == dnstable_res_failure);
	check_return(dnstable_stat_str_to_category("merged", &dummy_cat) == dnstable_res_success);

	l_return_test_status();
}

static int
test_query(void)
{
	struct mtbl_reader *mreader;
	struct dnstable_reader *reader;
	struct dnstable_query *query;
	struct dnstable_iter *iter;
	struct dnstable_entry *entry;
	dnstable_res res;
	const uint8_t *rrname, *bailiwick;
	uint16_t rrtype;
	size_t lrrname, lbailiwick;

	mreader = mtbl_reader_init(SRCDIR "/tests/generic-tests/test.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

// DNSTABLE_QUERY_TYPE_RRSET, DNSTABLE_QUERY_TYPE_RDATA_NAME, DNSTABLE_QUERY_TYPE_RDATA_IP, DNSTABLE_QUERY_TYPE_RDATA_RAW
	query = dnstable_query_init(DNSTABLE_QUERY_TYPE_RRSET);
	check_return(query != NULL);

	res = dnstable_query_set_data(query, "*.com");
	check_return(res == dnstable_res_success);

	/* Bad data type should fail. */
	res = dnstable_query_set_rrtype(query, "ABC");
	check_return(res != dnstable_res_success);

const char *qerror;
	qerror = dnstable_query_get_error(query);
	check_return(qerror != NULL);
	check_return(strstr(qerror, "unknown") != NULL);

	res = dnstable_query_set_rrtype(query, "A");
	check_return(res == dnstable_res_success);
	res = dnstable_query_set_bailiwick(query, "bkk1.cloud.z.com");
	check_return(res == dnstable_res_success);

struct timespec ts = {0, 0};
	res = dnstable_query_set_timeout(query, &ts);
	check_return(res == dnstable_res_success);

	iter = dnstable_reader_query(reader, query);
	check_return(iter != NULL);

	// Check that proper counters are initialized
	{
		int64_t counters[] = { 0,  0, -1,
				       0,  0, -1,
				      -1, -1, -1};
		const int stages[] = {DNSTABLE_STAT_STAGE_FILTER_RRTYPE, DNSTABLE_STAT_STAGE_FILTER_BAILIWICK, -1};
		check_return(test_query_iter_stats(iter, stages, counters));
	}

	/* First attempt should timeout. */
	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_timeout);
	{
		int64_t counters[] = { 0,  0, -1,
				       0,  0, -1,
				      -1, -1, -1};
		int stages[] = {DNSTABLE_STAT_STAGE_FILTER_RRTYPE, DNSTABLE_STAT_STAGE_FILTER_BAILIWICK, -1};
		check_return(test_query_iter_stats(iter, stages, counters));
	}
	dnstable_iter_destroy(&iter);

	/* Second attempt should be fine. */
	ts.tv_sec = 100;
	res = dnstable_query_set_timeout(query, &ts);

	iter = dnstable_query_iter(query, mtbl_reader_source(mreader));
//	iter = dnstable_reader_query(reader, query);
	check_return(iter != NULL);
	{
		int64_t counters[] = { 0,  0, -1,
				       0,  0, -1,
				      -1, -1, -1};
		int stages[] = {DNSTABLE_STAT_STAGE_FILTER_RRTYPE, DNSTABLE_STAT_STAGE_FILTER_BAILIWICK, -1};
		check_return(test_query_iter_stats(iter, stages, counters));
	}
	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_success);
	{
		int64_t counters[] = {19,  0, -1,
				       0,  0, -1,
				      -1, -1, -1};
		int stages[] = {DNSTABLE_STAT_STAGE_FILTER_RRTYPE, DNSTABLE_STAT_STAGE_FILTER_BAILIWICK, -1};
		check_return(test_query_iter_stats(iter, stages, counters));
	}

	res = dnstable_entry_get_rrtype(entry, &rrtype);
	check_return(res == dnstable_res_success);
	/* rrtype A==1 */
	check_return(rrtype == 1);

	/* Should have yielded a dot com extension */
	res = dnstable_entry_get_rrname(entry, &rrname, &lrrname);
	check_return(res == dnstable_res_success);
	check_return(lrrname >= 5);
const char *suffix = "\x03""com""\x00";
	check_return(!memcmp(&rrname[lrrname - 5], suffix, 5));

	res = dnstable_entry_get_bailiwick(entry, &bailiwick, &lbailiwick);
	check_return(res == dnstable_res_success);
const char *ebailiwick = "\x04""bkk1""\x05""cloud""\x01""z""\x03""com\x00";
	check_return(lbailiwick == 18);
	check_return(!memcmp(bailiwick, ebailiwick, strlen((const char *)ebailiwick) + 1));

uint64_t first_time, last_time;
	res = dnstable_entry_get_time_first(entry, &first_time);
	check_return(res == dnstable_res_success);
	res = dnstable_entry_get_time_last(entry, &last_time);
	check_return(res == dnstable_res_success);

bool passes;
	check_return(dnstable_query_filter(query, entry, &passes) == dnstable_res_success);
	check_return(passes);

	/* Check various time fencing filters. */
	return_if_error(test_filter_parameter(query, entry, DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE, first_time + 1000, first_time - 1000));
	return_if_error(test_filter_parameter(query, entry, DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE, last_time + 1000, first_time - 1000));
	return_if_error(test_filter_parameter(query, entry, DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER, last_time - 1000, ~(0)));
	return_if_error(test_filter_parameter(query, entry, DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER, first_time - 1000, first_time + 1000));

	dnstable_entry_destroy(&entry);
	dnstable_iter_destroy(&iter);
	dnstable_query_destroy(&query);
	dnstable_reader_destroy(&reader);

	l_return_test_status();
}

static void
cust_iter_free_func(void *addr)
{
	unsigned long *ival = (unsigned long *)addr;

	if (ival && (*ival == 0x12345678))
		*ival = 0x87654321;

	return;
}

#define TEST_KEYLEN	36
#define TEST_VALLEN	11
const uint8_t test_key[TEST_KEYLEN] = "\x00\x02""at""\x0b""a-webserver""\x03""ns2""\x00\x01\x02""at""\x00\x04""S""\xa""97""\x04\x00\x00\x00\x00";
const uint8_t test_val[TEST_VALLEN] = "\x9b\x9e\xe0\xde\x05\xd0\xda\xe0\xde\x05\x05";

static dnstable_res
cust_iter_next_func(void *addr, struct dnstable_entry **pentry)
{
	unsigned long *ival = (unsigned long *)addr;

	if (!ival || (*ival != 0x12345678))
		return dnstable_res_failure;

	*pentry = dnstable_entry_decode(test_key, TEST_KEYLEN, test_val, TEST_VALLEN);

	if (*pentry == NULL)
		return dnstable_res_failure;

	dnstable_entry_set_iszone(*pentry, 1);

	return dnstable_res_success;
}

static int
test_cust_iter(void)
{
	struct mtbl_reader *mreader;
	struct dnstable_reader *reader;
	struct dnstable_iter *iter;
	struct dnstable_entry *entry = NULL;
	dnstable_res res;
	const uint8_t *owner;
	uint16_t rrtype;
	size_t lowner;
	unsigned long ival = 0x12345678;

	mreader = mtbl_reader_init(SRCDIR "/tests/generic-tests/test.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

	iter = dnstable_iter_init(cust_iter_next_func, cust_iter_free_func, &ival);
	check_return(iter != NULL);

	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_success);

	check_return(dnstable_entry_get_type(entry) == DNSTABLE_ENTRY_TYPE_RRSET);

	res = dnstable_entry_get_rrtype(entry, &rrtype);
	check_return(res == dnstable_res_success);
	/* It's RRtype A (1) */
	check_return(rrtype == 1);

	res = dnstable_entry_get_rrname(entry, &owner, &lowner);
	check_return(res == dnstable_res_success);
	check_return(lowner == 20);
const uint8_t key_owner[20] = "\x03""ns2""\x0b""a-webserver""\x02""at""\x00";
	check_return(!memcmp(key_owner, owner, lowner));

const uint8_t *bailiwick;
size_t lbailiwick;
	res = dnstable_entry_get_bailiwick(entry, &bailiwick, &lbailiwick);
	check_return(res == dnstable_res_success);
	check_return(lbailiwick == 4);
	check_return(!memcmp(bailiwick, "\x02""at""\x0", 4));

uint64_t time_first, time_last;
	res = dnstable_entry_get_time_first(entry, &time_first);
	check_return(res == dnstable_res_success);
	check_return(time_first == 0x5bd80f1b);

	res = dnstable_entry_get_time_last(entry, &time_last);
	check_return(res == dnstable_res_success);
	check_return(time_last == 0x5bd82d50);

size_t nrdata;
	res = dnstable_entry_get_num_rdata(entry, &nrdata);
	check_return(res == dnstable_res_success);
	check_return(nrdata == 2);

const uint8_t *rdata;
size_t lrdata;
	res = dnstable_entry_get_rdata(entry, 0, &rdata, &lrdata);
	check_return(res == dnstable_res_success);
	check_return(lrdata == 4);
	check_return(!memcmp(rdata, "\x53\x0a\x39\x37", lrdata));

const uint8_t *rdata_name;
size_t lrdata_name;
	res = dnstable_entry_get_rdata_name(entry, &rdata_name, &lrdata_name);
	check_return(res != dnstable_res_success);

	dnstable_entry_destroy(&entry);
	dnstable_iter_destroy(&iter);

	check_return(ival == 0x87654321);
	dnstable_reader_destroy(&reader);


	/* A special test for dnstable_entry_get_rdata_name(). */
	mreader = mtbl_reader_init(SRCDIR "/tests/generic-tests/test.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

	iter = dnstable_reader_iter_rdata_names(reader);
	check_return(iter != NULL);

	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_success);

	check_return(dnstable_entry_get_type(entry) == DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV);

const uint8_t rev_name[24] = "\x12""bestbuddiespetcare""\x03""biz\x00";
	res = dnstable_entry_get_rdata_name(entry, &rdata_name, &lrdata_name);
	check_return(res == dnstable_res_success);
	check_return(lrdata_name == 24);
	check_return(!memcmp(rdata_name, rev_name, lrdata_name));

	/* This shouldn't work here. */
	res = dnstable_entry_get_rrtype(entry, &rrtype);
	check_return(res != dnstable_res_success);

	dnstable_entry_destroy(&entry);
	dnstable_iter_destroy(&iter);
	dnstable_reader_destroy(&reader);

	l_return_test_status();
}

static int
compare_merger_to_file(struct mtbl_iter *iter, const char *mtbl_file) {
	struct mtbl_iter *riter;
	struct mtbl_reader *reader;
	const uint8_t *key1, *key2, *val1, *val2;
	size_t len_key1, len_key2, len_val1, len_val2;

	reader = mtbl_reader_init(mtbl_file, NULL);
	check_return(reader != NULL);

	riter = mtbl_source_iter(mtbl_reader_source(reader));
	check_return(riter != NULL);

	while (1) {
		mtbl_res res1, res2;

		res1 = mtbl_iter_next(riter, &key1, &len_key1, &val1, &len_val1);
		res2 = mtbl_iter_next(iter, &key2, &len_key2, &val2, &len_val2);

		if (res1 != mtbl_res_success)
			break;

		check_return(res1 == res2);
		check_return(len_key1 == len_key2);
		check_return(len_val1 == len_val2);
		check_return(!memcmp(val1, val2, len_val1));
		check_return(!memcmp(key1, key2, len_key1));
	}

	mtbl_iter_destroy(&riter);
	mtbl_reader_destroy(&reader);

	l_return_test_status();
}

static int
test_merger(void)
{
	struct mtbl_merger *merger;
	struct mtbl_merger_options *moptions;
	const struct mtbl_source *msource;
	struct mtbl_reader *reader;
	struct mtbl_iter *iter;

	moptions = mtbl_merger_options_init();
	check_return(moptions != NULL);

	mtbl_merger_options_set_merge_func(moptions, dnstable_merge_func, NULL);

	merger = mtbl_merger_init(moptions);
	check_return(merger != NULL);

	reader = mtbl_reader_init(SRCDIR "/tests/generic-tests/m1.mtbl", NULL);
	check_return(reader != NULL);
	mtbl_merger_add_source(merger, mtbl_reader_source(reader));

	reader = mtbl_reader_init(SRCDIR "/tests/generic-tests/m2.mtbl", NULL);
	check_return(reader != NULL);
	mtbl_merger_add_source(merger, mtbl_reader_source(reader));

	msource = mtbl_merger_source(merger);
	check_return(msource != NULL);

	iter = mtbl_source_iter(msource);
	check_return(iter != NULL);

	return_if_error(compare_merger_to_file(iter, SRCDIR "/tests/generic-tests/m12.mtbl"));

	mtbl_iter_destroy(&iter);
	mtbl_merger_options_destroy(&moptions);
	mtbl_merger_destroy(&merger);

	l_return_test_status();
}

static int
do_test_query_case(struct dnstable_query *query,
	struct mtbl_reader *mreader,
	bool case_sensitive,
	const char *t_rrname,
	const char *t_rrtype,
	const char *t_bailiwick,
	dnstable_res exp_res)
{
	wdns_name_t test;
	size_t lrrname, lbailiwick;
	dnstable_res res;
	uint16_t rrtype, e_rrtype;
	const uint8_t *rrname, *bailiwick;
	struct timespec ts = {0, 0};
	struct dnstable_iter *iter;
	struct dnstable_entry *entry;

	// Set query case sensitivity
	dnstable_query_set_case_sensitive(query, case_sensitive);

	res = dnstable_query_set_data(query, t_rrname);
	check_return(res == dnstable_res_success);

	res = dnstable_query_set_rrtype(query, t_rrtype);
	check_return(res == dnstable_res_success);

	if (t_bailiwick != NULL)
	{
		res = dnstable_query_set_bailiwick(query, t_bailiwick);
		check_return(res == dnstable_res_success);
	}

	ts.tv_sec = 100;
	res = dnstable_query_set_timeout(query, &ts);

	iter = dnstable_query_iter(query, mtbl_reader_source(mreader));
	check_return(iter != NULL);

	// Case-sensitive query should not find anything
	res = dnstable_iter_next(iter, &entry);
	check_return(res == exp_res);
	if (res == dnstable_res_success) {
		uint16_t star_offset = (*t_rrname == '*' ? 2 : 0);
		check_return(res == dnstable_res_success);

		e_rrtype = wdns_str_to_rrtype(t_rrtype);
		check_abort(e_rrtype != 0);

		res = dnstable_entry_get_rrtype(entry, &rrtype);
		check_return(res == dnstable_res_success);
		check_return(rrtype == e_rrtype);

		/* Should have yielded a dot com extension */
		res = dnstable_entry_get_rrname(entry, &rrname, &lrrname);
		check_return(res == dnstable_res_success);
		check_return(lrrname >= 5);

		memset(&test, 0, sizeof(test));
		if (case_sensitive) {
			check_return(wdns_str_to_name_case(t_rrname + star_offset, &test) == wdns_res_success);
		} else {
			check_return(wdns_str_to_name(t_rrname + star_offset, &test) == wdns_res_success);
		}

		check_return(!strncasecmp((const char *) &rrname[lrrname - test.len], (const char *) test.data, test.len));

		my_free(test.data);
		test.len = 0;

		if (t_bailiwick != NULL) {
			check_return(wdns_str_to_name_case(t_bailiwick, &test) == wdns_res_success);
			res = dnstable_entry_get_bailiwick(entry, &bailiwick, &lbailiwick);
			check_return(res == dnstable_res_success);
			check_return(lbailiwick == test.len);
			check_return(!memcmp(bailiwick, test.data, test.len));
			my_free(test.data);
			test.len = 0;
		}

		dnstable_entry_destroy(&entry);
	}

	dnstable_iter_destroy(&iter);

	l_return_test_status();
}

static int
test_query_case(void)
{
	struct mtbl_reader *mreader;
	struct dnstable_reader *reader;
	struct dnstable_query *query;

	mreader = mtbl_reader_init(SRCDIR "/tests/generic-tests/test2.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

	query = dnstable_query_init(DNSTABLE_QUERY_TYPE_RRSET);
	check_return(query != NULL);

	/* These two test shall both find exactly one entry */
	check_return(do_test_query_case(query, mreader, true, "_WILDCARD_.ea.com", "NS", NULL, dnstable_res_success) == 0)
	check_return(do_test_query_case(query, mreader, false, "_WILDCARD_.ea.COM", "NS", NULL, dnstable_res_success) == 0)

	/* This test should not find an entry */
	check_return(do_test_query_case(query, mreader, true, "*.COM", "A", "bkk1.cloud.z.com", dnstable_res_failure) == 0)

	/* This test should find an entry */
	check_return(do_test_query_case(query, mreader, false, "*.COM", "A", "bkk1.cloud.z.com", dnstable_res_success) == 0)

	dnstable_reader_destroy(&reader);
	dnstable_query_destroy(&query);
	
	l_return_test_status();
}

static dnstable_res
cust_iter_stat_func(const void *clos, dnstable_stat_stage cat, dnstable_stat_category stage, bool *exists, uint64_t *u)
{
	int ival = *(const int*) clos;
	*u = ((uint64_t) ival) * 1234;
	(void) cat;
	(void) stage;
	return dnstable_res_success;
}

static int
test_query_count(void)
{
	int ival = 1000;
	uint64_t expect = ((uint64_t) ival) * 1234;
	uint64_t res = 0;
	struct dnstable_iter *iter = dnstable_iter_init(cust_iter_next_func, cust_iter_free_func, &ival);
	check_return(iter != NULL);
	dnstable_iter_set_stat_func(iter, cust_iter_stat_func);
	check_return(dnstable_iter_get_count(iter, DNSTABLE_STAT_STAGE_FILTER_SINGLE_LABEL, DNSTABLE_STAT_CATEGORY_FILTERED, NULL, &res) == dnstable_res_success);
	check_return(res == expect);

	l_return_test_status();
}

int
main(void)
{
	check_explicit2_display_only(test_basic() == 0, "test-dnstable/ test_basic");
	check_explicit2_display_only(test_query() == 0, "test-dnstable/ test_query");
	check_explicit2_display_only(test_query_case() == 0, "test-dnstable/ test_query_case");
	check_explicit2_display_only(test_cust_iter() == 0, "test-dnstable/ test_cust_iter");
	check_explicit2_display_only(test_merger() == 0, "test-dnstable/ test_merger");
	check_explicit2_display_only(test_query_stats_conversion() == 0, "test-dnstable/ test_query_stats_conversion");
	check_explicit2_display_only(test_query_count() == 0, "test-dnstable/ test_query_count");

	g_check_test_status(0);

}
