/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012, 2014, 2015, 2018, 2019, 2021 by Farsight Security, Inc.
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

#ifndef DNSTABLE_PRIVATE_H
#define DNSTABLE_PRIVATE_H

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
# ifdef HAVE_SYS_ENDIAN_H
#  include <sys/endian.h>
# endif
#endif

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>

#include <mtbl.h>
#include <wdns.h>


#include "dnstable.h"

#include "libmy/my_alloc.h"
#include "libmy/my_time.h"
#include "libmy/ubuf.h"
#include "libmy/my_byteorder.h"
#include "libmy/my_format.h"

#define ENTRY_TYPE_RRSET			((uint8_t)0)
#define ENTRY_TYPE_RRSET_NAME_FWD		((uint8_t)1)
#define ENTRY_TYPE_RDATA			((uint8_t)2)
#define ENTRY_TYPE_RDATA_NAME_REV		((uint8_t)3)

#define ENTRY_TYPE_TIME_RANGE			((uint8_t)254)
#define ENTRY_TYPE_VERSION			((uint8_t)255)

/* best clock for my_gettime() */

#if defined(CLOCK_MONOTONIC_COARSE)
# define DNSTABLE__CLOCK_MONOTONIC CLOCK_MONOTONIC_COARSE
#elif defined(CLOCK_MONOTONIC)
# define DNSTABLE__CLOCK_MONOTONIC CLOCK_MONOTONIC
#else
# error Neither CLOCK_MONOTONIC nor CLOCK_MONOTONIC_COARSE are available.
#endif

/* triplet */

size_t
triplet_pack(uint8_t *, uint64_t, uint64_t, uint64_t);

dnstable_res
triplet_unpack(const uint8_t *, size_t, uint64_t *, uint64_t *, uint64_t *);

size_t
pair_pack(uint8_t *, uint64_t, uint64_t);

dnstable_res
pair_unpack(const uint8_t *, size_t, uint64_t *, uint64_t *);

/* misc */

static inline int
bytes_compare(const uint8_t *a, size_t len_a,
	      const uint8_t *b, size_t len_b)
{
	size_t len = len_a > len_b ? len_b : len_a;
	int ret = memcmp(a, b, len);
	if (ret == 0) {
		if (len_a < len_b) {
			return (-1);
		} else if (len_a == len_b) {
			return (0);
		} else if (len_a > len_b) {
			return (1);
		}
	}
	return (ret);
}

struct dnstable_iter *
dnstable_query_iter_fileset(struct dnstable_query *, struct mtbl_fileset *);

/*
 * The maximum number of rrtypes that can be in an rrtype bitmap index.
 * For safety due to degenerate cases in the actual DNS, allow *all*
 * possible RRtypes.  As an example, "boxun.com.cn." in 2017 had 111
 * unique RRtypes defined, many not standardized.
 */
#define MAX_RRTYPES_MAPPABLE 65535

typedef struct {
	uint16_t rrtypes[MAX_RRTYPES_MAPPABLE];
} rrtype_unpacked_set;

/*
 * rrtype_union_unpack: unpack a RRtype union into an array.
 * The results are guaranteed to be sorted by increasing value.
 *
 * See the dnstable-encoding.5 section "Key-value entry
 * types", "RRtype union" definition.

 * Limits how many rrtypes it will support by truncating what it returns.
 * In theory, there can be 2^16-1 bits set, since the rrtype values
 * allowed are not restricted to those in the DNS RFCs and Assigned
 * Numbers.
 *
 * Returns the number of rrtypes it unpacked.  This can be 0 if there
 * are no rrtypes to unpack.  Returns -1 if the encoding is corrupt or
 * if there are more rrtypes to unpack than will fit in rrtype_set.
 */
int
rrtype_union_unpack(const uint8_t *rrtype_map, size_t rrtype_map_size,
		    rrtype_unpacked_set *rrtype_set);

/*
 * Test if the RRtype is effectively set in this dnstable_entry, with
 * special handling by entry type.  An empty RRtype index is
 * interpreted as "no RRtypes are excluded by this index" for the
 * appropriate set of RRtypes.
 *
 * Return true if the bit is set, is handled specially, or the RRtype
 * index appears corrupt for this record (as a value of true will
 * necessarily force a lookup of the indicated rrtype).
 * Returns false otherwise.
 *
 * valid for entry types:
 *     DNSTABLE_ENTRY_TYPE_RRSET_NAME_FWD
 *     DNSTABLE_ENTRY_TYPE_RDATA_NAME_REV
 */
bool
rrtype_test(dnstable_entry_type e_type, uint16_t rrtype,
	    const uint8_t *rrtype_map, size_t rrtype_map_size);


/*
 * "Left join" two mtbl sources, where each key on source "left"
 * has its value merged with any corresponding key on the "right"
 * source.
 */
struct ljoin_mtbl;

struct ljoin_mtbl_stats {
	uint64_t entries;
	uint64_t merged;
	uint64_t seek;
};

struct ljoin_mtbl *
ljoin_mtbl_init(const struct mtbl_source *left,
		const struct mtbl_source *right,
		mtbl_merge_func merge_fn,
		void *merge_clos);

dnstable_res
ljoin_mtbl_get_counter(const struct ljoin_mtbl *, dnstable_stat_stage, uint64_t *);

const struct mtbl_source *
ljoin_mtbl_source(const struct ljoin_mtbl *);

void
ljoin_mtbl_destroy(struct ljoin_mtbl **);


/*
 * Filter a mtbl source, using a filter_mtbl_func which can pass
 * matching entries using *match, seek past non-matching entries using
 * seek_iter, or terminate iteration by returning mtbl_res_failure.
 */
struct filter_mtbl;

struct filter_mtbl_stats {
	uint64_t filtered;
	uint64_t seek;
};

typedef mtbl_res (*filter_mtbl_func)(
		void *user,
		struct mtbl_iter *seek_iter,
		const uint8_t *key, size_t len_key,
		const uint8_t *val, size_t len_val,
		bool *match);

struct filter_mtbl *
filter_mtbl_init(const struct mtbl_source *, filter_mtbl_func, void *);

dnstable_res
filter_mtbl_get_counter(const struct filter_mtbl *,
	   dnstable_stat_stage, uint64_t*);

const struct mtbl_source *
filter_mtbl_source(const struct filter_mtbl *);

void
filter_mtbl_destroy(struct filter_mtbl **);


/*
 * Enforce timeout when intermediate results are consumed by filters.
 * Returns using longjmp to the supplied jmp_buf after the deadline.
 */
struct timeout_mtbl;

struct timeout_mtbl *
timeout_mtbl_init(const struct mtbl_source *, const struct timespec *deadline, jmp_buf *);

const struct mtbl_source *
timeout_mtbl_source(const struct timeout_mtbl *);

void
timeout_mtbl_destroy(struct timeout_mtbl **);


/* Remove keys present in any source from the upstream source. */
struct remove_mtbl;

struct remove_mtbl *
remove_mtbl_init(void);

void
remove_mtbl_add_source(struct remove_mtbl *, const struct mtbl_source *);

void
remove_mtbl_set_upstream(struct remove_mtbl *, const struct mtbl_source *);

const struct mtbl_source *
remove_mtbl_source(struct remove_mtbl *);

void
remove_mtbl_destroy(struct remove_mtbl **);


#endif /* DNSTABLE_PRIVATE_H */
