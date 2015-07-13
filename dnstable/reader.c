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

#include "dnstable-private.h"

struct reader_iter {
	struct dnstable_query		*q;
	struct mtbl_iter		*m_it;
};

struct dnstable_reader {
	const struct mtbl_source	*source;
	struct mtbl_fileset		*fs;
};

static void
reader_iter_free(void *);

static dnstable_res
reader_iter_next(void *, struct dnstable_entry **);

struct dnstable_reader *
dnstable_reader_init(const struct mtbl_source *source)
{
	assert(source != NULL);
	struct dnstable_reader *r = my_calloc(1, sizeof(*r));
	r->source = source;
	return (r);
}

struct dnstable_reader *
dnstable_reader_init_setfile(const char *setfile)
{
	assert(setfile != NULL);
	struct dnstable_reader *r = my_calloc(1, sizeof(*r));
	struct mtbl_fileset_options *fopt = mtbl_fileset_options_init();
	mtbl_fileset_options_set_merge_func(fopt, dnstable_merge_func, NULL);
	r->fs = mtbl_fileset_init(setfile, fopt);
	mtbl_fileset_options_destroy(&fopt);
	r->source = mtbl_fileset_source(r->fs);
	return (r);
}

void
dnstable_reader_reload_setfile(struct dnstable_reader *r)
{
	if (r->fs != NULL)
		mtbl_fileset_reload_now(r->fs);
}

void
dnstable_reader_destroy(struct dnstable_reader **r)
{
	if (*r) {
		mtbl_fileset_destroy(&(*r)->fs);
		my_free(*r);
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
dnstable_reader_iter_rrset(struct dnstable_reader *r)
{
	uint8_t prefix[] = { ENTRY_TYPE_RRSET };
	struct reader_iter *it = my_calloc(1, sizeof(*it));
	it->m_it = mtbl_source_get_prefix(r->source, prefix, 1);
	return (dnstable_iter_init(reader_iter_next, reader_iter_free, it));
}

struct dnstable_iter *
dnstable_reader_iter_rdata(struct dnstable_reader *r)
{
	uint8_t prefix[] = { ENTRY_TYPE_RDATA };
	struct reader_iter *it = my_calloc(1, sizeof(*it));
	it->m_it = mtbl_source_get_prefix(r->source, prefix, 1);
	return (dnstable_iter_init(reader_iter_next, reader_iter_free, it));
}

struct dnstable_iter *
dnstable_reader_query(struct dnstable_reader *r, struct dnstable_query *q)
{
	return (dnstable_query_iter(q, r->source));
}

static void
reader_iter_free(void *clos)
{
	struct reader_iter *it = (struct reader_iter *) clos;
	mtbl_iter_destroy(&it->m_it);
	my_free(it);
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
