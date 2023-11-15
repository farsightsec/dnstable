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
