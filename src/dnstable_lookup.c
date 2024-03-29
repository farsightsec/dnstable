/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012, 2018-2021 by Farsight Security, Inc.
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
#include <time.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>

#include "libmy/my_time.h"

static bool g_json = false;
static bool g_Json = false;
static bool g_add_raw;
static bool g_count = false;
static bool g_aggregate = true;
static int64_t g_offset = 0;
static int32_t g_stats = 0;

static struct timespec g_deadline;	/* absolute timeout */
static struct timespec g_interval;	/* periodic interval for stats */

static void
print_entry(struct dnstable_entry *ent)
{
	char *s;

	if (g_count)
		return;

	if (g_Json || g_json) {
		struct dnstable_formatter *fmt = dnstable_formatter_init();
		dnstable_formatter_set_output_format(fmt, dnstable_output_format_json);
		if (g_json)
			dnstable_formatter_set_date_format(fmt, dnstable_date_format_unix);
		else
			dnstable_formatter_set_date_format(fmt, dnstable_date_format_rfc3339);
		dnstable_formatter_set_raw_rdata(fmt, g_add_raw);
		s = dnstable_entry_format(fmt, ent);
		dnstable_formatter_destroy(&fmt);
	} else {
		s = dnstable_entry_to_text(ent);
	}
	assert(s != NULL);
	if (strlen(s) > 0) {
		fputs(s, stdout);
		if (g_Json || g_json ||
		    (dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RRSET))
			putchar('\n');
		free(s);
	}
}

static size_t
do_dump_stats_stage(struct dnstable_iter *it)
{
	dnstable_stat_stage stage = 0;
	dnstable_stat_category cat = 0;
	const char *scat;
	bool exists;
	size_t n, max = 0;

	fputs("\n", stderr);
	for (n = 0; n <= 1; n++) {
		for (cat = 0; (scat = dnstable_stat_category_to_str(cat)) != NULL; ++cat) {
			uint64_t total = 0;

			if (n == 0) {
				max = (strlen(scat) > max) ? strlen(scat) : max;
				continue;
			}

			for (stage = 0; dnstable_stat_stage_to_str(stage) != NULL; ++stage) {
				uint64_t cnt;
				(void) dnstable_iter_get_count(it, stage, cat, &exists, &cnt);
				if (exists)
					total += cnt;
			}
			fprintf(stderr, "%-*s : %"PRIu64"\n", (int)max, scat, total);
		}
	}
	fputs("\n", stderr);
	return max;
}

static size_t
do_dump_stats_category(struct dnstable_iter *it)
{
	char tmpbuf[128] = {0};
	dnstable_stat_stage stage = 0;
	dnstable_stat_category cat = 0;
	const char *sstg, *scat;
	bool exists;
	uint64_t cnt;
	size_t n, maxl = 0;

	fputs("\n", stderr);

	for (n = 0; n <= 1; n++) {
		for (stage = 0; (sstg = dnstable_stat_stage_to_str(stage)) != NULL; ++stage) {
			for (cat = 0; (scat = dnstable_stat_category_to_str(cat)) != NULL; ++cat) {
				(void) dnstable_iter_get_count(it, stage, cat, &exists, &cnt);
				if (!exists)
					continue;

				if (n == 0) {
					size_t l = strlen(scat) + strlen(sstg) + 1;
					maxl = l > maxl ? l : maxl;
					continue;
				}

				snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", sstg, scat);
				fprintf(stderr, "%-*s : %"PRIu64"\n", (int)maxl, tmpbuf, cnt);
			}
		}
	}
	fputs("\n", stderr);
	return maxl;
}

static void
do_dump(struct dnstable_iter *it, struct dnstable_query *q)
{
	struct dnstable_entry *ent;
	dnstable_res res;
	uint64_t count = 0;
	struct timespec start, next;
	size_t maxl = 0;

	my_gettime(CLOCK_MONOTONIC, &start);

	for (;;) {

		/* loop until error or timeout */
		while ((res = dnstable_iter_next(it, &ent)) == dnstable_res_success) {
			assert(ent != NULL);
			print_entry(ent);
			dnstable_entry_destroy(&ent);
			count++;
		}

		if (g_stats > 1)
			maxl = do_dump_stats_category(it);
		else if (g_stats > 0)
			maxl = do_dump_stats_stage(it);

		if (g_stats > 0) {
			struct timespec elapsed;
			my_gettime(CLOCK_MONOTONIC, &elapsed);
			my_timespec_sub(&start, &elapsed);
			fprintf(stderr, "%-*s : %" PRIu64 "\n%-*s : %ld.%09lds\n",
				(int)maxl, "entries", count, (int)maxl, "elapsed",
				elapsed.tv_sec, elapsed.tv_nsec);
		}

		if (res != dnstable_res_timeout) break;
		if (g_interval.tv_sec == 0) break;	/* Must have hit an absolute deadline */

		my_gettime(CLOCK_MONOTONIC, &next);
		if (g_deadline.tv_sec != 0 && my_timespec_cmp(&next, &g_deadline) > 0)
			break;	/* Current time is after absolute deadline */

		my_timespec_add(&g_interval, &next);
		if (g_deadline.tv_sec != 0 && my_timespec_cmp(&next, &g_deadline) > 0)
			next = g_deadline;	/* Next interval can't exceed absolute deadline */

		res = dnstable_query_set_deadline(q, &next);
		if (res != dnstable_res_success) break;
	}

	if (!g_json && !g_Json) {
		if (res == dnstable_res_timeout)
			fprintf(stderr, ";;; timed out\n");
		fprintf(stderr, ";;; Dumped %'" PRIu64 " entries.\n", count);
	}
}

static uint64_t
parse_time(const char *s)
{
	long long ll, total = 0;
	char *endp;
	struct timespec now;
	struct tm tt = {0};


	/* Parse absolute ISO8601 time */
	if (((endp = strptime(s, "%F", &tt)) && (*endp == '\0')) ||
	    ((endp = strptime(s, "%F %T", &tt)) && (*endp == '\0')) ||
	    ((endp = strptime(s, "%FT%T", &tt)) && (*endp == '\0')) ||
	    ((endp = strptime(s, "%FT%TZ", &tt)) && (*endp == '\0'))) {
		return (uint64_t)timegm(&tt);
	}

	clock_gettime(CLOCK_REALTIME, &now);

	/* Parse absolute or negative relative numeric time */
	ll = strtoll(s, &endp, 10);
	if (*endp == '\0') {
		if (ll < 0) {
			if (ll + now.tv_sec < 0)
				return 0;
			return (uint64_t)(ll + now.tv_sec);
		}
		return (uint64_t)ll;
	}

	/* Parse 10w3d4h */
	while(*s) {
		ll = strtoll(s, &endp, 10);
		if (ll <= 0)
			return 0;
		switch(*endp) {
		case 'W':
		case 'w':
			ll *= 7;
		case 'D':
		case 'd':
			ll *= 24;
		case 'H':
		case 'h':
			ll *= 60;
		case 'M':
		case 'm':
			ll *= 60;
		case 'S':
		case 's':
		case '\0':
			break;
		default:
			return 0;
		}
		total += ll;
		s = endp;
		if (*s) s++;
	}
	if (total > now.tv_sec)
		return 0;
	return (uint64_t)(now.tv_sec - total);
}

static void
usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tdnstable_lookup [options] rrset <OWNER NAME> [<RRTYPE> [<BAILIWICK>]]\n");
	fprintf(stderr, "\tdnstable_lookup [options] rdata ip <ADDRESS | RANGE | PREFIX>\n");
	fprintf(stderr, "\tdnstable_lookup [options] rdata raw <HEX STRING> [<RRTYPE>]\n");
	fprintf(stderr, "\tdnstable_lookup [options] rdata name <RDATA NAME> [<RRTYPE>]\n");
	fprintf(stderr, "\tdnstable_lookup [options] version [type]\n");
	fprintf(stderr, "\tdnstable_lookup [options] time_range\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-a FIRST_AFTER: select results with time_first after FIRST_AFTER.\n");
	fprintf(stderr, "\t-A LAST_AFTER: select results with time_last after LAST_AFTER.\n");
	fprintf(stderr, "\t-b LAST_BEFORE: select results with time_last before LAST_BEFORE.\n");
	fprintf(stderr, "\t-B FIRST_BEFORE: select results with time_first before FIRST_BEFORE.\n");
	fprintf(stderr, "\t-c: treat -A as -a, -B as -b for dnsdbq \"complete (strict) matching\" semantics.\n");
	fprintf(stderr, "\t-j: output in JSON format with epoch time; default is 'dig' presentation format\n");
	fprintf(stderr, "\t-J: output in JSON format with human time (RFC3339 format); default is 'dig' presentation format\n");
	fprintf(stderr, "\t-n: output only the number of matches\n");
	fprintf(stderr, "\t-R: add raw rdata representation\n");
	fprintf(stderr, "\t-u: output unaggregated results; default is aggregated results\n");
	fprintf(stderr, "\t-O #: offset the first # results (must be a positive number)\n");
	fprintf(stderr, "\t-C case sensitive lookup\n");
	fprintf(stderr, "\t-s print lookup stats\n");
	fprintf(stderr, "\t-t TIMEOUT: stop after TIMEOUT seconds.\n");
	fprintf(stderr, "\t-i INTERVAL: print stats every INTERVAL seconds.\n");
	fprintf(stderr, "\nUse exactly one of the following environment variables to specify the dnstable\ndata file(s) to query:\n\tDNSTABLE_FNAME - Path to a single dnstable data file, or\n\tDNSTABLE_SETFILE - Path to a \"set file\"\n");
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
	const char *arg_version_type = NULL;
	struct mtbl_reader *m_reader = NULL;
	struct dnstable_iter *d_iter;
	struct dnstable_reader *d_reader;
	struct dnstable_query *d_query;
	uint64_t time_last_after = 0, time_first_after = 0;
	uint64_t time_first_before = 0, time_last_before = 0;
	int64_t timeout = 0, interval = 0;
	bool time_strict = false;
	bool case_sensitive = false;
	dnstable_query_type d_qtype = 0; /* fix lint warning; will always override */
	dnstable_res res;
	int ch;

	while ((ch = getopt(argc, argv, "a:A:b:B:cCi:njJRst:uO:")) != -1) {
		switch (ch) {
		case 'a':
			time_first_after = parse_time(optarg);
			if (time_first_after == 0) {
				fprintf(stderr, "Invalid time '%s'\n\n", optarg);
				usage();
			}
			break;
		case 'A':
			time_last_after = parse_time(optarg);
			if (time_last_after == 0) {
				fprintf(stderr, "Invalid time '%s'\n\n", optarg);
				usage();
			}
			break;
		case 'b':
			time_last_before = parse_time(optarg);
			if (time_last_before == 0) {
				fprintf(stderr, "Invalid time '%s'\n\n", optarg);
				usage();
			}
			break;
		case 'B':
			time_first_before = parse_time(optarg);
			if (time_first_before == 0) {
				fprintf(stderr, "Invalid time '%s'\n\n", optarg);
				usage();
			}
			break;
		case 'c':
			time_strict = true;
			break;
		case 'C':
			case_sensitive = true;
			break;
		case 'i':
			interval = atoi(optarg);
			if (interval <= 0)
				usage();
			break;
		case 'j':
			g_json = true;
			break;
		case 'J':
			g_Json = true;
			break;
		case 'n':
			g_count = true;
			break;
		case 'R':
			g_add_raw = true;
			break;
		case 's':
			g_stats++;
			break;
		case 't':
			timeout = atoi(optarg);
			if (timeout <= 0)
				usage();
			break;
		case 'u':
			g_aggregate = false;
			break;
		case 'O':
			g_offset = atoi(optarg);
			if (g_offset <= 0)
				usage();
			break;
		case -1:
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (strcmp(argv[0], "rrset") == 0) {
		if (argc < 2 || argc > 4)
			usage();
		d_qtype = DNSTABLE_QUERY_TYPE_RRSET;

		arg_owner_name = argv[1];

		if (strchr(arg_owner_name, '/') > 0) {
			fprintf(stderr, "/ is not allowed in OWNER NAME\n\n");
			usage();
		}

		if (argc >= 3)
			arg_rrtype = argv[2];
		if (argc >= 4)
			arg_bailiwick = argv[3];
	} else if (strcmp(argv[0], "rdata") == 0) {
		if (argc == 3 && strcmp(argv[1], "ip") == 0) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_IP;
		} else if ((argc == 3 || argc == 4) && strcmp(argv[1], "raw") == 0) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_RAW;
		} else if ((argc == 3 || argc == 4) && strcmp(argv[1], "name") == 0) {
			d_qtype = DNSTABLE_QUERY_TYPE_RDATA_NAME;
		} else {
			usage();
		}
		arg_rdata = argv[2];
		if (argc == 4)
			arg_rrtype = argv[3];
	} else if (strcmp(argv[0], "version") == 0) {
		if (argc > 2)
			usage();
		d_qtype = DNSTABLE_QUERY_TYPE_VERSION;
		if (argc == 2)
			arg_version_type = argv[1];
	} else if (strcmp(argv[0], "time_range") == 0) {
		if (argc > 1)
			usage();
		d_qtype = DNSTABLE_QUERY_TYPE_TIME_RANGE;
	} else {
		usage();
	}

	// check for certain options that make no sense with version or time_range commands
	if (d_qtype == DNSTABLE_QUERY_TYPE_VERSION || d_qtype == DNSTABLE_QUERY_TYPE_TIME_RANGE) {
		if (g_offset != 0) {
			fprintf(stderr, "dnstable_lookup: Offset option makes no sense with version or time_range commands\n");
			exit(EXIT_FAILURE);
		}
		if (g_add_raw != 0) {
			fprintf(stderr, "dnstable_lookup: Raw option makes no sense with version or time_range commands\n");
			exit(EXIT_FAILURE);
		}
	}

	if (g_count && (g_Json || g_json || g_add_raw)) {
		fprintf(stderr, "dnstable_lookup: cannot specify -n with either -j, -J or -R\n");
		exit(EXIT_FAILURE);
	}

	if (g_Json && g_json) {
		fprintf(stderr, "dnstable_lookup: cannot specify both -j and -J\n");
		exit(EXIT_FAILURE);
	}

	if (!(g_Json || g_json) && g_add_raw) {
		fprintf(stderr, "dnstable_lookup: adding raw rdata only supported with a json output format\n");
		exit(EXIT_FAILURE);
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
		if (g_aggregate == false) {
			fprintf(stderr, "-u flag not valid with a single input mtbl file; it is only valid with a setfile\n");
			exit(EXIT_FAILURE);
		}
		m_reader = mtbl_reader_init(env_fname, NULL);
		if (m_reader == NULL) {
			fprintf(stderr, "dnstable_lookup: unable to open file %s\n", env_fname);
			exit(EXIT_FAILURE);
		}
		d_reader = dnstable_reader_init(mtbl_reader_source(m_reader));
	}
	assert(d_reader != NULL);
	d_query = dnstable_query_init(d_qtype);

	dnstable_query_set_case_sensitive(d_query, case_sensitive);

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
	} else if ((d_qtype == DNSTABLE_QUERY_TYPE_RDATA_IP) ||
		   (d_qtype == DNSTABLE_QUERY_TYPE_RDATA_NAME) ||
		   (d_qtype == DNSTABLE_QUERY_TYPE_RDATA_RAW)) {
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
	} else if (d_qtype == DNSTABLE_QUERY_TYPE_VERSION) {
		res = dnstable_query_set_data(d_query, arg_version_type);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: Invalid version type '%s'\n",
				arg_version_type);
			exit(EXIT_FAILURE);
		}

	}

	if ((d_qtype != DNSTABLE_QUERY_TYPE_VERSION) &&
	    (d_qtype != DNSTABLE_QUERY_TYPE_TIME_RANGE)) {
		if (time_strict) {
			if (time_first_after < time_last_after) {
				time_first_after = time_last_after;
				time_last_after = 0;
			}

			if ((time_first_before > 0) &&
			    ((time_last_before == 0) ||
			     (time_last_before > time_first_before))) {
				time_last_before = time_first_before;
				time_first_before = 0;
			}
		}

		if (time_first_after != 0)
			dnstable_query_set_filter_parameter(d_query,
					DNSTABLE_FILTER_PARAMETER_TIME_FIRST_AFTER,
					&time_first_after, sizeof(time_first_after));

		if (time_first_before != 0)
			dnstable_query_set_filter_parameter(d_query,
					DNSTABLE_FILTER_PARAMETER_TIME_FIRST_BEFORE,
					&time_first_before, sizeof(time_first_before));

		if (time_last_after != 0)
			dnstable_query_set_filter_parameter(d_query,
					DNSTABLE_FILTER_PARAMETER_TIME_LAST_AFTER,
					&time_last_after, sizeof(time_last_after));

		if (time_last_before != 0)
			dnstable_query_set_filter_parameter(d_query,
					DNSTABLE_FILTER_PARAMETER_TIME_LAST_BEFORE,
					&time_last_before, sizeof(time_last_before));
	}

	if (g_offset != 0) {
		res = dnstable_query_set_offset(d_query, g_offset);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_offset() failed\n");
			exit(EXIT_FAILURE);
		}
	}

	if (timeout != 0) {
		my_gettime(CLOCK_MONOTONIC, &g_deadline);
		g_deadline.tv_sec += timeout;
		res = dnstable_query_set_deadline(d_query, &g_deadline);
		if (res != dnstable_res_success) {
			fprintf(stderr, "dnstable_lookup: dnstable_query_set_deadline() failed\n");
			exit(EXIT_FAILURE);
		}
	}

	if (interval != 0) {
		struct timespec next;

		g_interval.tv_sec = interval;
		my_gettime(CLOCK_MONOTONIC, &next);
		my_timespec_add(&g_interval, &next);
		/* Ignore the interval if the absolute timeout comes earlier. */
		if (g_deadline.tv_sec == 0 || my_timespec_cmp(&next, &g_deadline) < 0) {
			res = dnstable_query_set_deadline(d_query, &next);
			if (res != dnstable_res_success) {
				fprintf(stderr, "dnstable_lookup: dnstable_query_set_deadline() failed\n");
				exit(EXIT_FAILURE);
			}
		}

		if (g_stats == 0) g_stats ++;
	}

	res = dnstable_query_set_aggregated(d_query, g_aggregate);
	if (res != dnstable_res_success) {
		fprintf(stderr, "dnstable_lookup: dnstable_query_set_aggregated() failed\n");
		exit(EXIT_FAILURE);
	}

	d_iter = dnstable_reader_query(d_reader, d_query);
	if (d_iter == NULL) {
		fprintf(stderr, "dnstable_lookup: dnstable_reader_query() failed\n");
		exit(EXIT_FAILURE);
	}

	do_dump(d_iter, d_query);
	dnstable_iter_destroy(&d_iter);
	dnstable_query_destroy(&d_query);
	dnstable_reader_destroy(&d_reader);
	if (m_reader != NULL)
		mtbl_reader_destroy(&m_reader);

	return (EXIT_SUCCESS);
}
