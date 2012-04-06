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

struct dnstable_iter {
	dnstable_iter_next_func	iter_next;
	dnstable_iter_free_func	iter_free;
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
	it->clos = clos;
	return (it);
}

void
dnstable_iter_destroy(struct dnstable_iter **it)
{
	if (*it) {
		if ((*it)->iter_free != NULL)
			(*it)->iter_free((*it)->clos);
		free(*it);
		*it = NULL;
	}
}

dnstable_res
dnstable_iter_next(struct dnstable_iter *it, struct dnstable_entry **ent)
{
	if (it == NULL)
		return (dnstable_res_failure);
	return (it->iter_next(it->clos, ent));
}
