/*
 * Copyright (c) 2023 by Farsight Security, Inc.
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

struct dnstable_iter {
	dnstable_iter_next_func	iter_next;
	dnstable_iter_free_func	iter_free;
	dnstable_iter_stat_func iter_stat;
	void			*clos;
};

struct dnstable_iter *
dnstable_iter_init(dnstable_iter_next_func iter_next,
		   dnstable_iter_free_func iter_free,
		   void *clos)
{
	assert(iter_next != NULL);
	struct dnstable_iter *it = my_malloc(sizeof(*it));
	it->iter_next = iter_next;
	it->iter_free = iter_free;
	it->iter_stat = NULL;
	it->clos = clos;
	return (it);
}

void
dnstable_iter_destroy(struct dnstable_iter **it)
{
	if (*it) {
		if ((*it)->iter_free != NULL)
			(*it)->iter_free((*it)->clos);
		my_free(*it);
	}
}

void
dnstable_iter_set_stat_func(struct dnstable_iter *it, dnstable_iter_stat_func fp)
{
	if (it)
		it->iter_stat = fp;
}

dnstable_res
dnstable_iter_next(struct dnstable_iter *it, struct dnstable_entry **ent)
{
	if (it == NULL)
		return (dnstable_res_failure);
	return (it->iter_next(it->clos, ent));
}

dnstable_res
dnstable_iter_get_count(struct dnstable_iter * it,
	dnstable_stat_category category,
	dnstable_stat_stage stage,
	uint64_t *count)
{
	if (it == NULL || it->iter_stat == NULL || count == NULL)
		return dnstable_res_failure;

	return it->iter_stat(it->clos, category, stage, count);
}