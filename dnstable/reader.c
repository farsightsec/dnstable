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

#include "dnstable-private.h"

struct reader_iter {
	struct dnstable_query		*q;
	struct mtbl_iter		*m_it;
};

struct dnstable_reader {
	const struct mtbl_source	*source;
};

static void
reader_iter_free(void *);

static dnstable_res
reader_iter_next(void *, struct dnstable_entry **);

struct dnstable_reader *
dnstable_reader_init_fname(const char *fname)
{
	assert(0);
	return (NULL);
}

struct dnstable_reader *
dnstable_reader_init_source(const struct mtbl_source *source)
{
	assert(source != NULL);
	struct dnstable_reader *r = my_malloc(sizeof(*r));
	r->source = source;
	return (r);
}

void
dnstable_reader_destroy(struct dnstable_reader **r)
{
	if (*r) {
		free(*r);
		*r = NULL;
	}
}

struct dnstable_iter *
dnstable_reader_iter(struct dnstable_reader *r)
{
	struct reader_iter *it = my_calloc(1, sizeof(*it));
	it->m_it = mtbl_source_iter(r->source);
	return (dnstable_iter_init(reader_iter_next, reader_iter_free, it));
}

struct dnstable_iter *
dnstable_reader_query(struct dnstable_reader *r, struct dnstable_query *q)
{
	struct reader_iter *it = my_malloc(sizeof(*it));
	it->q = q;
	it->m_it = NULL; /* XXX do mtbl_source_getXXX() */
	return (dnstable_iter_init(reader_iter_next, reader_iter_free, it));
}

static void
reader_iter_free(void *clos)
{
	struct reader_iter *it = (struct reader_iter *) clos;
	mtbl_iter_destroy(&it->m_it);
	free(it);
}

static dnstable_res
reader_iter_next(void *clos, struct dnstable_entry **ent)
{
	struct reader_iter *it = (struct reader_iter *) clos;

	for (;;) {
		const uint8_t *key, *val;
		size_t len_key, len_val;

		if (mtbl_iter_next(it->m_it, &key, &len_key, &val, &len_val) != mtbl_res_success)
			return (dnstable_res_failure);
		*ent = dnstable_entry_decode(key, len_key, val, len_val);
		assert(*ent != NULL);
		if (it->q != NULL) {
			bool pass = false;
			dnstable_res res;
			
			res = dnstable_query_filter(it->q, *ent, &pass);
			assert(res == dnstable_res_success);
			if (pass) {
				return (dnstable_res_success);
			} else {
				dnstable_entry_destroy(ent);
				continue;
			}
		} else {
			return (dnstable_res_success);
		}
	}
}
