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

#include "dnstable-private.h"

struct reader_iter {
	struct dnstable_query		*q;
	struct mtbl_iter		*m_it;
};

struct dnstable_reader {
	const struct mtbl_source	*source;
	const struct mtbl_source	*source_no_merge;
	struct mtbl_fileset		*fs;
	struct mtbl_fileset		*fs_no_merge;
};

static struct dnstable_iter *
reader_iter_prefix(struct dnstable_reader *, uint8_t);

static void
reader_iter_free(void *);

static dnstable_res
reader_iter_next(void *, struct dnstable_entry **);

static int
dnstable_dupsort_func(void *clos,
		      const uint8_t *key, size_t len_key,
		      const uint8_t *val0, size_t len_val0,
		      const uint8_t *val1, size_t len_val1);

struct dnstable_reader *
dnstable_reader_init(const struct mtbl_source *source)
{
	assert(source != NULL);
	struct dnstable_reader *r = my_calloc(1, sizeof(*r));
	r->source = source;
	return (r);
}

/*
 * dnstable_dupsort_func is used to sort the entries with duplicate
 * keys during the merge process based on their data.  The dnstable
 * data is a triplet of variable-length integers, so (in theory) the
 * byte comparison used for keys would not suffice.  This is mostly of
 * interest with a NULL merge function, although it could be used to
 * enforce some order of merges with a non-NULL merge function.
 *
 * This sorts first by time_first, then by time_last if time_first is the same.
 */
static int
dnstable_dupsort_func(void *clos,
		      const uint8_t *key, size_t len_key,
		      const uint8_t *val0, size_t len_val0,
		      const uint8_t *val1, size_t len_val1)
{
	uint64_t time_first0, time_last0, count0;
	uint64_t time_first1, time_last1, count1;

	if (len_key && (key[0] == ENTRY_TYPE_RRSET ||
			key[0] == ENTRY_TYPE_RDATA))
	{
		assert(len_val0 && len_val1);
		dnstable_res res;

		res = triplet_unpack(val0, len_val0, &time_first0, &time_last0, &count0);
		assert(res == dnstable_res_success);
		res = triplet_unpack(val1, len_val1, &time_first1, &time_last1, &count1);
		assert(res == dnstable_res_success);

		if (time_first0 < time_first1)
			return -1;
		if (time_first0 > time_first1)
			return 1;
		if (time_last0 < time_last1)
			return -1;
		if (time_last0 > time_last1)
			return 1;
		return 0;
	} else
		return 0;
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

	/* reset and redo the mtbl fileset options */
	fopt = mtbl_fileset_options_init();
	mtbl_fileset_options_set_merge_func(fopt, NULL, NULL);
	mtbl_fileset_options_set_dupsort_func(fopt, dnstable_dupsort_func, NULL);
	r->fs_no_merge = mtbl_fileset_dup(r->fs, fopt);
	mtbl_fileset_options_destroy(&fopt);

	r->source = mtbl_fileset_source(r->fs);
	r->source_no_merge = mtbl_fileset_source(r->fs_no_merge);

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
		mtbl_fileset_destroy(&(*r)->fs_no_merge);
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

/*
 * dnstable_reader_query returns aggregated (e.g. a dnstable merge
 * function is applied) or unaggregated results depending upon the
 * query object's aggregated flag.
 */
struct dnstable_iter *
dnstable_reader_query(struct dnstable_reader *r, struct dnstable_query *q)
{
	if (dnstable_query_is_aggregated(q) == false) {
		if (r->source_no_merge != NULL)
			return (dnstable_query_iter(q, r->source_no_merge));
		else
			return NULL; /* this is an error */
	} else
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
