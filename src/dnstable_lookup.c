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

#include <assert.h>
#include <errno.h>
#include <locale.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>

static void
print_entry(struct dnstable_entry *ent)
{
	char *s = dnstable_entry_to_text(ent);
	assert(s != NULL);
	if (strlen(s) > 0) {
		fputs(s, stdout);
		if (dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RRSET)
			putchar('\n');
		free(s);
	}
}

static void
do_dump(struct dnstable_iter *it)
{
	struct dnstable_entry *ent;
	uint64_t count = 0;

	while (dnstable_iter_next(it, &ent) == dnstable_res_success) {
		assert(ent != NULL);
		print_entry(ent);
		dnstable_entry_destroy(&ent);
		count++;
	}
	fprintf(stderr, ";;; Dumped %'" PRIu64 " entries.\n", count);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: dnstable_lookup rrset <OWNER NAME> [<RRTYPE> [<BAILIWICK>]]\n");
	fprintf(stderr, "Usage: dnstable_lookup rdata ip <ADDRESS | RANGE | PREFIX>\n");
	fprintf(stderr, "Usage: dnstable_lookup rdata raw <HEX STRING> [<RRTYPE>]\n");
	fprintf(stderr, "Usage: dnstable_lookup rdata name <RDATA NAME> [<RRTYPE>]\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");

	const char *env_fname = NULL;
	const char *env_setfile = NULL;
	const char *arg_owner_name = NULL;
	const char *arg_rrtype = NULL;
	const char *arg_bailiwick = NULL;
	const char *arg_rdata = NULL;
	struct mtbl_reader *m_reader = NULL;
	struct dnstable_iter *d_iter;
	struct dnstable_reader *d_reader;
	struct dnstable_query *d_query;
	dnstable_query_type d_qtype;
	dnstable_res res;

	if (argc < 3)
		usage();

	if (strcmp(argv[1], "rrset") == 0) {
		d_qtype = DNSTABLE_QUERY_TYPE_RRSET;
		if (argc >= 3)
			arg_owner_name = argv[2];
		if (argc >= 4)
			arg_rrtype = argv[3];
		if (argc >= 5)
			arg_bailiwick = argv[4];
		if (argc > 5)
			usage();
	} else if (strcmp(argv[1], "rdata") == 0) {
		if (strcmp(argv[2], "ip") == 0 && argc == 4) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_IP;
		} else if (strcmp(argv[2], "raw") == 0 && (argc == 4 || argc == 5)) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_RAW;
		} else if (strcmp(argv[2], "name") == 0 && (argc == 4 || argc == 5)) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_NAME;
		} else {
			usage();
		}
		arg_rdata = argv[3];
		if (argc == 5)
			arg_rrtype = argv[4];
	} else {
		usage();
	}

	env_fname = getenv("DNSTABLE_FNAME");
	env_setfile = getenv("DNSTABLE_SETFILE");
	if ((!env_fname && !env_setfile) || (env_fname && env_setfile)) {
		fprintf(stderr, "dnstable_lookup: error: exactly one of "
			"DNSTABLE_FNAME, DNSTABLE_SETFILE must be set\n");
		exit(EXIT_FAILURE);
	}

	if (env_setfile) {
		d_reader = dnstable_reader_init_setfile(env_setfile);
	} else {
		m_reader = mtbl_reader_init(env_fname, NULL);
		if (m_reader == NULL) {
			fprintf(stderr, "dnstable_lookup: unable to open file %s\n", env_fname);
			exit(EXIT_FAILURE);
		}
		d_reader = dnstable_reader_init(mtbl_reader_source(m_reader));
	}
	assert(d_reader != NULL);
	d_query = dnstable_query_init(d_qtype);

	if (d_qtype == DNSTABLE_QUERY_TYPE_RRSET) {
		res = dnstable_query_set_data(d_query, arg_owner_name);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_data() failed\n");
			exit(EXIT_FAILURE);
		}

		res = dnstable_query_set_rrtype(d_query, arg_rrtype);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_rrtype() failed\n");
			exit(EXIT_FAILURE);
		}

		res = dnstable_query_set_bailiwick(d_query, arg_bailiwick);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_bailiwick() failed\n");
			exit(EXIT_FAILURE);
		}
	} else {
		res = dnstable_query_set_data(d_query, arg_rdata);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_data() failed: %s\n",
				dnstable_query_get_error(d_query));
			exit(EXIT_FAILURE);
		}

		if (arg_rrtype != NULL) {
			res = dnstable_query_set_rrtype(d_query, arg_rrtype);
			if (res != dnstable_res_success) {
				fprintf(stderr, "dnstable_lookup: "
					"dnstable_query_set_rrtype() failed\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	d_iter = dnstable_reader_query(d_reader, d_query);
	do_dump(d_iter);
	dnstable_iter_destroy(&d_iter);
	dnstable_query_destroy(&d_query);
	dnstable_reader_destroy(&d_reader);
	if (m_reader != NULL)
		mtbl_reader_destroy(&m_reader);

	return (EXIT_SUCCESS);
}
