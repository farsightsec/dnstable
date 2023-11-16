/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012-2015, 2017-2021 by Farsight Security, Inc.
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

#include <mtbl.h>
#include "dnstable-private.h"

#include "libmy/my_time.h"
#include "libmy/list.h"

/*
 * Generic mtbl_source_{iter,get,get_prefix,get_range} wrappers to
 * reduce repeated code.
 */

typedef struct mtbl_iter *(*source_iter_func)(
	const struct mtbl_source *s,
	const uint8_t *key, size_t len_key,
	const uint8_t *key2, size_t len_key2);

static struct mtbl_iter *
wrap_source_iter(const struct mtbl_source *s,
		 const uint8_t *key, size_t len_key,
		 const uint8_t *key2, size_t len_key2)
{
	(void)key;
	(void)len_key;
	(void)key2;
	(void)len_key2;
	return mtbl_source_iter(s);
}

static struct mtbl_iter *
wrap_source_get(const struct mtbl_source *s,
		const uint8_t *key, size_t len_key,
		const uint8_t *key2, size_t len_key2)
{
	(void)key2;
	(void)len_key2;
	return mtbl_source_get(s, key, len_key);
}

static struct mtbl_iter *
wrap_source_get_prefix(const struct mtbl_source *s,
		       const uint8_t *key, size_t len_key,
		       const uint8_t *key2, size_t len_key2)
{
	(void)key2;
	(void)len_key2;
	return mtbl_source_get_prefix(s, key, len_key);
}

static struct mtbl_iter *
wrap_source_get_range(const struct mtbl_source *s,
		      const uint8_t *key, size_t len_key,
		      const uint8_t *key2, size_t len_key2)
{
	return mtbl_source_get_range(s, key, len_key, key2, len_key2);
}

/*
 * Mtbl "left join"
 *
 * For each key in "left" source, merge value with that of any corresponding
 * key in "right" source.
 */

struct ljoin_mtbl {
	struct mtbl_source *source;
	const struct mtbl_source *left;
	const struct mtbl_source *right;
	mtbl_merge_func merge_fn;
	void *merge_clos;
};

struct ljoin_mtbl_iter {
	struct ljoin_mtbl *join;
	struct mtbl_iter *iter_left;
	struct mtbl_iter *iter_right;
	bool right_finished;

	const uint8_t *right_key, *right_val;
	size_t len_right_key, len_right_val;

	uint8_t *merged_val;
};

static mtbl_res
ljoin_iter_seek(void *impl, const uint8_t *key, size_t len_key)
{
	struct ljoin_mtbl_iter *it = impl;
	mtbl_res res;
	res = mtbl_iter_seek(it->iter_left, key, len_key);
	if (res != mtbl_res_success)
		return res;

	it->right_finished = false;
	it->right_key = NULL;
	res = mtbl_iter_seek(it->iter_right, key, len_key);
	if (res != mtbl_res_success) {
		it->right_finished = true;
	}
	return (mtbl_res_success);
}

static mtbl_res
ljoin_iter_next(void *impl, const uint8_t **key, size_t *len_key,
			    const uint8_t **val, size_t *len_val)
{
	struct ljoin_mtbl_iter *it = impl;
	const uint8_t *left_key, *left_val;
	size_t len_left_key, len_left_val;
	mtbl_res res;

	res = mtbl_iter_next(it->iter_left,
			     &left_key, &len_left_key,
			     &left_val, &len_left_val);

	if (res != mtbl_res_success)
		return res;

	*key = left_key;
	*len_key = len_left_key;
	*val = left_val;
	*len_val = len_left_val;

	while (!it->right_finished) {
		if (it->right_key == NULL) {
			res = mtbl_iter_next(it->iter_right,
					     &it->right_key, &it->len_right_key,
					     &it->right_val, &it->len_right_val);
			if (res != mtbl_res_success) {
				it->right_finished = true;
				break;
			}
		}
		int cmp = bytes_compare(it->right_key, it->len_right_key, left_key, len_left_key);

		/*
		 * If the right iterator's current key is less than the left, we
		 * seek forward to the left key and retry.
		 */
		if (cmp < 0) {
			res = mtbl_iter_seek(it->iter_right, left_key, len_left_key);
			if (res != mtbl_res_success) {
				it->right_finished = true;
				break;
			}
			it->right_key = NULL;
			continue;
		}

		/*
		 * If the right iterator's current key is greater than the left, we
		 * are finished.
		 */
		if (cmp > 0)
			break;

		/*
		 * Otherwise, the right iterator's key is the same as the left. Merge
		 * the two values and return.
		 */
		free(it->merged_val);
		it->join->merge_fn(it->join->merge_clos,
				   left_key, len_left_key,
				   left_val, len_left_val,
				   it->right_val, it->len_right_val,
				   &it->merged_val, len_val);
		if (it->merged_val == NULL)
			return (mtbl_res_failure);
		*val = it->merged_val;
		break;
	}

	return (mtbl_res_success);
}

static void
ljoin_iter_free(void *impl)
{
	struct ljoin_mtbl_iter *it = impl;
	free(it->merged_val);
	mtbl_iter_destroy(&it->iter_left);
	mtbl_iter_destroy(&it->iter_right);
	free(it);
}

static struct mtbl_iter *
ljoin_source_iter_common(void *impl, source_iter_func source_iter,
			 const uint8_t *key, size_t len_key,
			 const uint8_t *key2, size_t len_key2)
{
	struct ljoin_mtbl *j = impl;
	struct ljoin_mtbl_iter *it = calloc(1, sizeof(*it));
	it->join = j;
	it->iter_left = source_iter(j->left, key, len_key, key2, len_key2);
	it->iter_right = source_iter(j->right, key, len_key, key2, len_key2);
	return mtbl_iter_init(ljoin_iter_seek, ljoin_iter_next, ljoin_iter_free, it);
}


static struct mtbl_iter *
ljoin_source_iter(void *impl)
{
	return ljoin_source_iter_common(impl, wrap_source_iter, NULL, 0, NULL, 0);
}

static struct mtbl_iter *
ljoin_source_get(void *impl, const uint8_t *key, size_t len_key)
{
	return ljoin_source_iter_common(impl, wrap_source_get, key, len_key, NULL, 0);
}

static struct mtbl_iter *
ljoin_source_get_prefix(void *impl, const uint8_t *key, size_t len_key)
{
	return ljoin_source_iter_common(impl, wrap_source_get_prefix, key, len_key, NULL, 0);
}

static struct mtbl_iter *
ljoin_source_get_range(void *impl, const uint8_t *key, size_t len_key,
				   const uint8_t *key2, size_t len_key2)
{
	return ljoin_source_iter_common(impl, wrap_source_get_range, key, len_key, key2, len_key2);
}

/*
 * The ljoin source's private data is the ljoin_mtbl structure itself,
 * which is reclaimed with ljoin_mtbl_destroy()
 */
static void
ljoin_source_free(void *impl)
{
	(void)impl;
}

struct ljoin_mtbl *
ljoin_mtbl_init(const struct mtbl_source *left, const struct mtbl_source *right,
		mtbl_merge_func merge_fn, void *merge_clos)
{
	struct ljoin_mtbl *j = calloc(1, sizeof(*j));

	assert(j != NULL);
	j->left = left;
	j->right = right;
	j->merge_fn = merge_fn;
	j->merge_clos = merge_clos;
	j->source = mtbl_source_init(ljoin_source_iter,
				     ljoin_source_get,
				     ljoin_source_get_prefix,
				     ljoin_source_get_range,
				     ljoin_source_free,
				     j);
	return j;
}

const struct mtbl_source *
ljoin_mtbl_source(const struct ljoin_mtbl *j)
{
	return j->source;
}

void
ljoin_mtbl_destroy(struct ljoin_mtbl **pj)
{
	if (pj == NULL) return;
	free(*pj);
	*pj = NULL;
}

/*
 * Mtbl "filter"
 *
 * Present a filtered version of an mtbl source, based on a filter function
 * which can accept or reject entries and optionally seek past subsequent
 * non-matches.
 */

struct filter_mtbl {
	filter_mtbl_func filter_func;
	void *filter_data;
	const struct mtbl_source *upstream;
	struct mtbl_source *source;
};

struct filter_mtbl_iter {
	const struct filter_mtbl *filter;
	struct mtbl_iter *it;
};

static mtbl_res
filter_iter_next(void *impl, const uint8_t **key, size_t *len_key,
			     const uint8_t **val, size_t *len_val)
{
	struct filter_mtbl_iter *fit = impl;
	mtbl_res res;
	bool match = false;

	for (;;) {
		res = mtbl_iter_next(fit->it, key, len_key, val, len_val);
		if (res != mtbl_res_success)
			return res;
		res = fit->filter->filter_func(fit->filter->filter_data,
					       fit->it,
					       *key, *len_key,
					       *val, *len_val,
					       &match);
		if (res != mtbl_res_success || match)
			return res;
	}
}

static mtbl_res
filter_iter_seek(void *impl, const uint8_t *key, size_t len_key)
{
	struct filter_mtbl_iter *fit = impl;
	return mtbl_iter_seek(fit->it, key, len_key);
}

static void
filter_iter_free(void *impl)
{
	struct filter_mtbl_iter *fit = impl;
	mtbl_iter_destroy(&fit->it);
	free(fit);
}

static struct mtbl_iter *
filter_source_iter_common(void *impl, source_iter_func source_iter,
			  const uint8_t *key, size_t len_key,
			  const uint8_t *key2, size_t len_key2)
{
	struct filter_mtbl *filter = impl;
	struct filter_mtbl_iter *fit = calloc(1, sizeof(*fit));

	fit->filter = filter;
	fit->it = source_iter(filter->upstream, key, len_key, key2, len_key2);

	return mtbl_iter_init(filter_iter_seek,
			      filter_iter_next,
			      filter_iter_free,
			      fit);
}

static struct mtbl_iter *
filter_source_iter(void *impl)
{
	return filter_source_iter_common(impl, wrap_source_iter,
					 NULL, 0, NULL, 0);
}

static struct mtbl_iter *
filter_source_get(void *impl, const uint8_t *key, size_t len_key)
{
	return filter_source_iter_common(impl, wrap_source_get,
					 key, len_key, NULL, 0);
}

static struct mtbl_iter *
filter_source_get_prefix(void *impl, const uint8_t *key, size_t len_key)
{
	return filter_source_iter_common(impl, wrap_source_get_prefix,
					 key, len_key, NULL, 0);
}

static struct mtbl_iter *
filter_source_get_range(void *impl, const uint8_t *key, size_t len_key, const uint8_t *key2, size_t len_key2)
{
	return filter_source_iter_common(impl, wrap_source_get_range,
					 key, len_key, key2, len_key2);
}

/*
 * The filter source's private data is the filter_mtbl structure itself,
 * which is reclaimed with filter_mtbl_destroy()
 */
static void
filter_source_free(void *impl)
{
	(void)impl;
}

struct filter_mtbl *
filter_mtbl_init(const struct mtbl_source *upstream, filter_mtbl_func filter, void *filter_data)
{
	struct filter_mtbl *f = calloc(1, sizeof(*f));
	f->filter_func = filter;
	f->filter_data = filter_data;
	f->upstream = upstream;

	f->source = mtbl_source_init(filter_source_iter,
				     filter_source_get,
				     filter_source_get_prefix,
				     filter_source_get_range,
				     filter_source_free,
				     f);
	return f;
}

const struct mtbl_source *
filter_mtbl_source(const struct filter_mtbl *filter)
{
	return filter->source;
}

void
filter_mtbl_destroy(struct filter_mtbl **pfilter)
{
	if (pfilter == NULL || *pfilter == NULL)
		return;
	mtbl_source_destroy(&((*pfilter)->source));
	free(*pfilter);
	*pfilter = NULL;
}


/*
 * Mtbl "timeout"
 *
 * Enforce a deadline for mtbl operations whose intermediate results may be
 * hidden from the caller by filters.
 */

struct timeout_mtbl {
	jmp_buf *expire_env;
	const struct timespec *deadline;
	const struct mtbl_source *upstream;
	struct mtbl_source *source;
};

struct timeout_mtbl_iter {
	const struct timeout_mtbl *timeout;
	struct mtbl_iter *it;
};

static mtbl_res
timeout_iter_next(void *impl, const uint8_t **key, size_t *len_key,
			     const uint8_t **val, size_t *len_val)
{
	struct timeout_mtbl_iter *to_it = impl;
	struct timespec now;

	my_gettime(CLOCK_MONOTONIC, &now);
	if (my_timespec_cmp(&now, to_it->timeout->deadline) >= 0)
		longjmp(*to_it->timeout->expire_env, 1);

	return mtbl_iter_next(to_it->it, key, len_key, val, len_val);
}

static mtbl_res
timeout_iter_seek(void *impl, const uint8_t *key, size_t len_key)
{
	struct timeout_mtbl_iter *to_it = impl;
	return mtbl_iter_seek(to_it->it, key, len_key);
}

static void
timeout_iter_free(void *impl)
{
	struct timeout_mtbl_iter *to_it = impl;
	mtbl_iter_destroy(&to_it->it);
	free(to_it);
}

static struct mtbl_iter *
timeout_source_iter_common(void *impl, source_iter_func source_iter,
			   const uint8_t *key, size_t len_key,
			   const uint8_t *key2, size_t len_key2)
{
	struct timeout_mtbl *timeout = impl;
	struct timeout_mtbl_iter *to_it = calloc(1, sizeof(*to_it));

	to_it->it = source_iter(timeout->upstream, key, len_key, key2, len_key2);
	to_it->timeout = timeout;

	return mtbl_iter_init(timeout_iter_seek,
			      timeout_iter_next,
			      timeout_iter_free,
			      to_it);
}

static struct mtbl_iter *
timeout_source_iter(void *impl)
{
	return timeout_source_iter_common(impl, wrap_source_iter,
					  NULL, 0, NULL, 0);
}

static struct mtbl_iter *
timeout_source_get(void *impl, const uint8_t *key, size_t len_key)
{
	return timeout_source_iter_common(impl, wrap_source_get,
					  key, len_key, NULL, 0);
}

static struct mtbl_iter *
timeout_source_get_prefix(void *impl, const uint8_t *key, size_t len_key)
{
	return timeout_source_iter_common(impl, wrap_source_get_prefix,
					  key, len_key, NULL, 0);
}

static struct mtbl_iter *
timeout_source_get_range(void *impl, const uint8_t *key, size_t len_key, const uint8_t *key2, size_t len_key2)
{
	return timeout_source_iter_common(impl, wrap_source_get_range,
					  key, len_key, key2, len_key2);
}

/*
 * The timeout source's private data is the timeout_mtbl structure itself,
 * which is reclaimed with timeout_mtbl_destroy()
 */
static void
timeout_source_free(void *impl)
{
	(void)impl;
}

struct timeout_mtbl *
timeout_mtbl_init(const struct mtbl_source *upstream, const struct timespec *deadline, jmp_buf *env)
{
	struct timeout_mtbl *timeout = calloc(1, sizeof(*timeout));
	timeout->deadline = deadline;
	timeout->expire_env = env;
	timeout->upstream = upstream;
	timeout->source = mtbl_source_init(timeout_source_iter,
					   timeout_source_get,
					   timeout_source_get_prefix,
					   timeout_source_get_range,
					   timeout_source_free,
					   timeout);

	return timeout;
}

const struct mtbl_source *
timeout_mtbl_source(const struct timeout_mtbl *timeout)
{
	return timeout->source;
}

void
timeout_mtbl_destroy(struct timeout_mtbl **ptimeout)
{
	if (ptimeout == NULL || *ptimeout == NULL)
		return;
	mtbl_source_destroy(&((*ptimeout)->source));
	free(*ptimeout);
	*ptimeout = NULL;
}

/* mtbl "remove" */

VECTOR_GENERATE(source_vec, const struct mtbl_source *)

struct remove_mtbl {
	const struct mtbl_source *upstream;
	source_vec *rm_sources;
	struct mtbl_source *source;
};

struct remove_entry {
	const struct mtbl_source *source;
	struct mtbl_iter *it;
	const uint8_t *key;
	size_t len_key;
	bool finished;
	ISC_LINK(struct remove_entry) link;
};

struct remove_iter {
	ISC_LIST(struct remove_entry) list;
	struct mtbl_iter *it;
	struct remove_entry *entries;
	size_t nentries;
	source_iter_func source_iter;
	uint8_t *key, *key2;
	size_t len_key, len_key2;
};

static bool
match_key(struct remove_iter *rit, const uint8_t *key, size_t len_key)
{
	struct remove_entry *re;
	mtbl_res res = mtbl_res_success;
	int ret;

	for (re = ISC_LIST_HEAD(rit->list);
	     re != NULL;
	     re = ISC_LIST_NEXT(re, link)) {

		const uint8_t *val;
		size_t len_val;

		if (re->it == NULL) {
			re->it = rit->source_iter(re->source, rit->key, rit->len_key,
							      rit->key2, rit->len_key2);
			res = mtbl_iter_seek(re->it, key, len_key);
			if (res != mtbl_res_success) {
				re->finished = true;
				continue;
			}
			res = mtbl_iter_next(re->it, &re->key, &re->len_key, &val, &len_val);
			if (res != mtbl_res_success) {
				re->finished = true;
				continue;
			}
		}

		while (!re->finished) {

			ret = bytes_compare(re->key, re->len_key, key, len_key);
			if (ret > 0)
				break;
			if (ret < 0) {
				res = mtbl_iter_seek(re->it, key, len_key);
				if (res != mtbl_res_success)
					break;
				res = mtbl_iter_next(re->it, &re->key, &re->len_key, &val, &len_val);
				if (res != mtbl_res_success)
					break;
				continue;
			}

			/* we have a match. Move it to head of list. */
			ISC_LIST_UNLINK(rit->list, re, link);
			ISC_LIST_PREPEND(rit->list, re, link);
			return true;
		}

		if (res != mtbl_res_success) {
			re->finished = true;
		}
	}

	return false;
}

static mtbl_res
remove_iter_next(void *impl, const uint8_t **key, size_t *len_key,
			     const uint8_t **val, size_t *len_val)
{
	struct remove_iter *rit = impl;
	mtbl_res res;

	do {
		res = mtbl_iter_next(rit->it, key, len_key, val, len_val);
		if (res != mtbl_res_success)
			return res;
	} while (match_key(rit, *key, *len_key));

	return mtbl_res_success;
}

static mtbl_res
remove_iter_seek(void *impl, const uint8_t *key, size_t len_key)
{
	struct remove_iter *rit = impl;
	struct remove_entry *re;
	mtbl_res res;
	unsigned i;

	for (i = 0; i < rit->nentries; i++) {
		const uint8_t *val;
		size_t len_val;

		re = &rit->entries[i];

		if (re->it == NULL)
			continue;

		if (re->finished ||
		    (bytes_compare(re->key, re->len_key, key, len_key) > 0)) {
			res = mtbl_iter_seek(re->it, key, len_key);
			if (res != mtbl_res_success) {
				re->finished = true;
				continue;
			}
			res = mtbl_iter_next(re->it, &re->key, &re->len_key, &val, &len_val);
			if (res != mtbl_res_success) {
				re->finished = true;
				continue;
			}
			re->finished = false;
		}
	}

	return  mtbl_iter_seek(rit->it, key, len_key);
}

static void
remove_iter_free(void *impl)
{
	struct remove_iter *rit = impl;
	unsigned i;

	mtbl_iter_destroy(&rit->it);

	for (i = 0; i < rit->nentries; i++) {
		mtbl_iter_destroy(&rit->entries[i].it);
	}
	free(rit->entries);

	free(rit);
}

static struct mtbl_iter *
remove_source_iter_common(void *impl, source_iter_func source_iter,
			  const uint8_t *key, size_t len_key,
			  const uint8_t *key2, size_t len_key2)
{
	struct remove_mtbl *rm = impl;
	struct remove_iter *rit = calloc(1, sizeof(*rit));
	unsigned i;

	rit->source_iter = source_iter;
	rit->it = source_iter(rm->upstream, key, len_key, key2, len_key2);
	if (len_key > 0) {
		rit->len_key = len_key;
		rit->key = malloc(len_key);
		memcpy(rit->key, key, len_key);
	}
	if (len_key2 > 0) {
		rit->len_key2 = len_key2;
		rit->key2 = malloc(len_key2);
		memcpy(rit->key2, key2, len_key2);
	}

	rit->nentries = source_vec_size(rm->rm_sources);
	rit->entries = calloc(rit->nentries, sizeof(*rit->entries));

	ISC_LIST_INIT(rit->list);
	for (i = 0; i < rit->nentries; i++) {
		rit->entries[i].source = source_vec_value(rm->rm_sources, i);
		ISC_LIST_APPEND(rit->list, &rit->entries[i], link);
	}
	return mtbl_iter_init(remove_iter_seek, remove_iter_next, remove_iter_free, rit);
}

static struct mtbl_iter *
remove_source_iter(void *impl)
{
	return remove_source_iter_common(impl, wrap_source_iter, NULL, 0, NULL, 0);
}

static struct mtbl_iter *
remove_source_get(void *impl, const uint8_t *key, size_t len_key)
{
	return remove_source_iter_common(impl, wrap_source_get, key, len_key, NULL, 0);
}

static struct mtbl_iter *
remove_source_get_prefix(void *impl, const uint8_t *key, size_t len_key)
{
	return remove_source_iter_common(impl, wrap_source_get_prefix, key, len_key, NULL, 0);
}

static struct mtbl_iter *
remove_source_get_range(void *impl, const uint8_t *key, size_t len_key,
				    const uint8_t *key2, size_t len_key2)
{
	return remove_source_iter_common(impl, wrap_source_get_range, key, len_key, key2, len_key2);
}

static void
remove_source_free(void *impl)
{
	(void)impl;
}

struct remove_mtbl *
remove_mtbl_init(void)
{
	struct remove_mtbl *rm = calloc(1, sizeof(*rm));
	rm->rm_sources = source_vec_init(1);
	rm->source = mtbl_source_init(remove_source_iter,
				      remove_source_get,
				      remove_source_get_prefix,
				      remove_source_get_range,
				      remove_source_free,
				      rm);
	return rm;
}

const struct mtbl_source *
remove_mtbl_source(struct remove_mtbl *rm)
{
	return rm->source;
}

void
remove_mtbl_add_source(struct remove_mtbl *rm, const struct mtbl_source *s)
{
	source_vec_add(rm->rm_sources, s);
}

void
remove_mtbl_set_upstream(struct remove_mtbl *rm, const struct mtbl_source *upstream)
{
	rm->upstream = upstream;
}

void
remove_mtbl_destroy(struct remove_mtbl **prm)
{
	struct remove_mtbl *rm = *prm;
	if (rm == NULL) return;
	source_vec_destroy(&rm->rm_sources);
	mtbl_source_destroy(&rm->source);
	free(rm);
	*prm = NULL;
}
