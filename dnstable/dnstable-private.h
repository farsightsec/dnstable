/*
 * Copyright (c) 2012, 2014 by Farsight Security, Inc.
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
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <mtbl.h>
#include <wdns.h>

#include "dnstable.h"

#include "libmy/my_alloc.h"
#include "libmy/ubuf.h"

#define ENTRY_TYPE_RRSET			'\x00'
#define ENTRY_TYPE_RRSET_NAME_FWD		'\x01'
#define ENTRY_TYPE_RDATA			'\x02'
#define ENTRY_TYPE_RDATA_NAME_REV		'\x03'

#define STATS_INTERVAL				1000000

#define DNS_MTBL_BLOCK_SIZE			8192
#define DNSSEC_MTBL_BLOCK_SIZE			65536

/* triplet */

size_t
triplet_pack(uint8_t *, uint64_t, uint64_t, uint64_t);

dnstable_res
triplet_unpack(const uint8_t *, size_t, uint64_t *, uint64_t *, uint64_t *);

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

#endif /* DNSTABLE_PRIVATE_H */
