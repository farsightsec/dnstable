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
#include <locale.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <dnstable.h>
#include <mtbl.h>

#include "librsf/print_string.h"

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
do_dump(struct mtbl_iter *it)
{
	const uint8_t *key;
	const uint8_t *val;
	size_t len_key;
	size_t len_val;
	struct dnstable_entry *ent;
	uint64_t count = 0;

	while (mtbl_iter_next(it, &key, &len_key, &val, &len_val) == mtbl_res_success) {
		ent = dnstable_entry_decode(key, len_key, val, len_val);
		if (ent == NULL) {
			fprintf(stderr, "Error: unable to decode key= ");
			print_string(key, len_key, stderr);
			fprintf(stderr, " val= ");
			print_string(val, len_val, stderr);
			fputc('\n', stderr);
			assert(ent != NULL);
		}
		print_entry(ent);
		dnstable_entry_destroy(&ent);
		count++;
	}

	fprintf(stderr, "Dumped %'" PRIu64 " entries.\n", count);
}

int
main(int argc, char **argv)
{
	setlocale(LC_ALL, "");

	const char *mtbl_fname;
	struct mtbl_reader *reader;
	struct mtbl_iter *it;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <DB FILE>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	mtbl_fname = argv[1];

	reader = mtbl_reader_init(mtbl_fname, NULL);
	if (reader == NULL) {
		fprintf(stderr, "dnstable_dump: unable to open database file %s\n",
			mtbl_fname);
		exit(EXIT_FAILURE);
	}

	it = mtbl_source_iter(mtbl_reader_source(reader));
	if (it != NULL)
		do_dump(it);

	mtbl_iter_destroy(&it);
	mtbl_reader_destroy(&reader);

	return (EXIT_SUCCESS);
}
