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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>

#include "libmy/argv.h"
#include "libmy/print_string.h"

static bool g_json;
static bool g_add_raw;
static bool g_rrset;
static bool g_rdata;
static bool g_rrset_names;
static bool g_rdata_names;
static char *g_fname;

static struct dnstable_formatter *fmt = NULL;

static argv_t args[] = {
	{ 'j',	"json",
		ARGV_BOOL,
		&g_json,
		NULL,
		"output in JSON format (default: text)" },

	{ 'R',	"raw",
		ARGV_BOOL,
		&g_add_raw,
		NULL,
		"add raw rdata representation" },

	{ 'r',	"rrset",
		ARGV_BOOL,
		&g_rrset,
		NULL,
		"output rrset records" },

	{ ARGV_ONE_OF },

	{ 'd',	"rdata",
		ARGV_BOOL,
		&g_rdata,
		NULL,
		"output rdata records" },

	{ ARGV_ONE_OF },

	{ '\0', "rrset_names",
		ARGV_BOOL,
		&g_rrset_names,
		NULL,
		"output rrset names" },

	{ ARGV_ONE_OF },

	{ '\0', "rdata_names",
		ARGV_BOOL,
		&g_rdata_names,
		NULL,
		"output rdata names" },

	{ ARGV_MAND, NULL,
		ARGV_CHAR_P,
		&g_fname,
		"filename",
		"input file" },

	{ ARGV_LAST }
};

static void
print_entry(struct dnstable_entry *ent)
{
	switch (dnstable_entry_get_type(ent)) {
	case DNSTABLE_ENTRY_TYPE_RRSET:
	case DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD:
	case DNSTABLE_ENTRY_TYPE_RDATA:
	case DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV: {
		char *s;
		if (g_json)
			s = dnstable_entry_format(fmt, ent);
		else
			s = dnstable_entry_to_text(ent);
		if (s != NULL) {
			fputs(s, stdout);
			if (!(!g_json &&
			      dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RDATA))
			{
				putchar('\n');
			}
			free(s);
		}
	}
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
}

int
main(int argc, char **argv)
{
	struct mtbl_reader *m_reader;
	struct dnstable_reader *d_reader;
	struct dnstable_iter *d_it = NULL;

	argv_process(args, argc, argv);

	if (!g_json && g_add_raw) {
		fprintf(stderr, "dnstable_dump: adding raw rdata only supported with json output format\n");
		exit(EXIT_FAILURE);
	}

	m_reader = mtbl_reader_init(g_fname, NULL);
	if (m_reader == NULL) {
		perror("mtbl_reader_init");
		fprintf(stderr, "dnstable_dump: unable to open database file %s\n",
			g_fname);
		exit(EXIT_FAILURE);
	}

	d_reader = dnstable_reader_init(mtbl_reader_source(m_reader));

	if (g_rrset) {
		d_it = dnstable_reader_iter_rrset(d_reader);
	} else if (g_rdata) {
		d_it = dnstable_reader_iter_rdata(d_reader);
	} else if (g_rrset_names) {
		d_it = dnstable_reader_iter_rrset_names(d_reader);
	} else if (g_rdata_names) {
		d_it = dnstable_reader_iter_rdata_names(d_reader);
	}

	fmt = dnstable_formatter_init();
	dnstable_formatter_set_output_format(fmt, dnstable_output_format_json);
	dnstable_formatter_set_date_format(fmt, dnstable_date_format_unix);
	dnstable_formatter_set_add_raw_rdata(fmt, g_add_raw);

	assert(d_it != NULL);
	do_dump(d_it);

	dnstable_formatter_destroy(&fmt);

	dnstable_iter_destroy(&d_it);
	dnstable_reader_destroy(&d_reader);
	mtbl_reader_destroy(&m_reader);

	argv_cleanup(args);

	return (EXIT_SUCCESS);
}
