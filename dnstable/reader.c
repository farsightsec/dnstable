/*
 * Copyright (c) 2012, 2014-2015, 2019, 2021 by Farsight Security, Inc.
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
	struct mtbl_iter		*m_it;
};

struct dnstable_reader {
	const struct mtbl_source	*source;
	struct mtbl_fileset		*fs;
};

static struct dnstable_iter *
reader_iter_prefix(struct dnstable_reader *, uint8_t);

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
	return (reader_iter_prefix(r, ENTRY_TYPE_RRSET));
}

struct dnstable_iter *
dnstable_reader_iter_rrset_names(struct dnstable_reader *r)
{
	return (reader_iter_prefix(r, ENTRY_TYPE_RRSET_NAME_FWD));
}

struct dnstable_iter *
dnstable_reader_iter_rdata(struct dnstable_reader *r)
{
	return (reader_iter_prefix(r, ENTRY_TYPE_RDATA));
}

struct dnstable_iter *
dnstable_reader_iter_rdata_names(struct dnstable_reader *r)
{
	return (reader_iter_prefix(r, ENTRY_TYPE_RDATA_NAME_REV));
}

struct dnstable_iter *
dnstable_reader_iter_time_range(struct dnstable_reader *r)
{
	return (reader_iter_prefix(r, ENTRY_TYPE_TIME_RANGE));
}

struct dnstable_iter *
dnstable_reader_iter_version(struct dnstable_reader *r)
{
	return (reader_iter_prefix(r, ENTRY_TYPE_VERSION));
}


/*
 * dnstable_reader_query returns aggregated (e.g. a dnstable merge
 * function is applied) or unaggregated results depending upon the
 * query object's aggregated flag.
 */
struct dnstable_iter *
dnstable_reader_query(struct dnstable_reader *r, struct dnstable_query *q)
{
	if (r->fs != NULL)
		return (dnstable_query_iter_fileset(q, r->fs));
	else
		return (dnstable_query_iter(q, r->source));
}

static struct dnstable_iter *
reader_iter_prefix(struct dnstable_reader *r, uint8_t prefix_byte)
{
	uint8_t prefix[] = { prefix_byte };
	struct reader_iter *it = my_calloc(1, sizeof(*it));
	it->m_it = mtbl_source_get_prefix(r->source, prefix, 1);
	return (dnstable_iter_init(reader_iter_next, reader_iter_free, it));
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
		if (*ent == NULL)
			continue;

		return (dnstable_res_success);
	}
}
