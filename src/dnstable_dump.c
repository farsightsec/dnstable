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
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>

#include "librsf/argv.h"
#include "librsf/print_string.h"

static bool g_json;
static bool g_rrset;
static bool g_rdata;
static char *g_fname;

static argv_t args[] = {
	{ 'j',	"json",
		ARGV_BOOL,
		&g_json,
		NULL,
		"output in JSON format (default: text)" },

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
	if (dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RRSET ||
	    dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RDATA)
	{
		char *s;
		if (g_json)
			s = dnstable_entry_to_json(ent);
		else
			s = dnstable_entry_to_text(ent);
		if (s != NULL) {
			fputs(s, stdout);
			if (dnstable_entry_get_type(ent) == DNSTABLE_ENTRY_TYPE_RRSET)
				putchar('\n');
			free(s);
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
	struct dnstable_iter *d_it;

	argv_process(args, argc, argv);

	m_reader = mtbl_reader_init(g_fname, NULL);
	if (m_reader == NULL) {
		perror("mtbl_reader_init");
		fprintf(stderr, "dnstable_dump: unable to open database file %s\n",
			g_fname);
		exit(EXIT_FAILURE);
	}

	d_reader = dnstable_reader_init(mtbl_reader_source(m_reader));

	if (g_rrset)
		d_it = dnstable_reader_iter_rrset(d_reader);
	else if (g_rdata)
		d_it = dnstable_reader_iter_rdata(d_reader);

	do_dump(d_it);
	dnstable_iter_destroy(&d_it);
	dnstable_reader_destroy(&d_reader);
	mtbl_reader_destroy(&m_reader);

	argv_cleanup(args);

	return (EXIT_SUCCESS);
}
