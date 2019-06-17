/*
 * Copyright (c) 2018 by Farsight Security, Inc.
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

#include "errors.h"

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

	mreader = mtbl_reader_init("./tests/generic-tests/test.mtbl", NULL);
	check_return(mreader != NULL);
	reader = dnstable_reader_init(mtbl_reader_source(mreader));
	check_return(reader != NULL);

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

	dnstable_entry_type et;
		et = dnstable_entry_get_type(entry);

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
	check_return(passes == true);

	/* Then opposite condition. */
	res = dnstable_query_set_filter_parameter(query, tparam, &time_val_fail, sizeof(time_val_fail));
	check_return(res == dnstable_res_success);
	check_return(dnstable_query_filter(query, entry, &passes) == dnstable_res_success);
	check_return(passes == false);

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

	mreader = mtbl_reader_init("./tests/generic-tests/test.mtbl", NULL);
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

	/* First attempt should timeout. */
	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_timeout);
	dnstable_iter_destroy(&iter);

	/* Second attempt should be fine. */
	ts.tv_sec = 100;
	res = dnstable_query_set_timeout(query, &ts);

	iter = dnstable_query_iter(query, mtbl_reader_source(mreader));
//	iter = dnstable_reader_query(reader, query);
	check_return(iter != NULL);

	res = dnstable_iter_next(iter, &entry);
	check_return(res == dnstable_res_success);

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
	check_return(passes == true);

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

	mreader = mtbl_reader_init("./tests/generic-tests/test.mtbl", NULL);
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
	mreader = mtbl_reader_init("./tests/generic-tests/test.mtbl", NULL);
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

	reader = mtbl_reader_init("./tests/generic-tests/m1.mtbl", NULL);
	check_return(reader != NULL);
	mtbl_merger_add_source(merger, mtbl_reader_source(reader));

	reader = mtbl_reader_init("./tests/generic-tests/m2.mtbl", NULL);
	check_return(reader != NULL);
	mtbl_merger_add_source(merger, mtbl_reader_source(reader));

	msource = mtbl_merger_source(merger);
	check_return(msource != NULL);

	iter = mtbl_source_iter(msource);
	check_return(iter != NULL);

	return_if_error(compare_merger_to_file(iter, "./tests/generic-tests/m12.mtbl"));

	mtbl_iter_destroy(&iter);
	mtbl_merger_options_destroy(&moptions);
	mtbl_merger_destroy(&merger);

	l_return_test_status();
}

int
main(void)
{
	check_explicit2_display_only(test_basic() == 0, "test-dnstable/ test_basic");
	check_explicit2_display_only(test_query() == 0, "test-dnstable/ test_query");
	check_explicit2_display_only(test_cust_iter() == 0, "test-dnstable/ test_cust_iter");
	check_explicit2_display_only(test_merger() == 0, "test-dnstable/ test_merger");

        g_check_test_status(0);

}
