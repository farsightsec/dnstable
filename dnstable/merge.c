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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <mtbl.h>

#include "dnstable-private.h"

static size_t
pack_triplet(uint8_t *orig_buf, uint64_t val1, uint64_t val2, uint64_t val3)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	buf += mtbl_varint_encode64(buf, val3);
	return (buf - orig_buf);
}

static void
unpack_triplet(const uint8_t *buf, size_t len_buf, uint64_t *val1, uint64_t *val2, uint64_t *val3)
{
	size_t bytes_read = 0;
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val1);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val2);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val3);
	assert(bytes_read == len_buf);
}

void
dnstable_merge_func(void *clos,
		    const uint8_t *key, size_t len_key,
		    const uint8_t *val0, size_t len_val0,
		    const uint8_t *val1, size_t len_val1,
		    uint8_t **merged_val, size_t *len_merged_val)
{
	uint64_t time_first0, time_last0, count0;
	uint64_t time_first1, time_last1, count1;

	if (len_key && (key[0] == ENTRY_TYPE_RRSET ||
			key[0] == ENTRY_TYPE_RDATA))
	{
		assert(len_val0 && len_val1);

		unpack_triplet(val0, len_val0, &time_first0, &time_last0, &count0);
		unpack_triplet(val1, len_val1, &time_first1, &time_last1, &count1);

		time_first0 = (time_first0 < time_first1) ? time_first0 : time_first1;
		time_last0 = (time_last0 < time_last1) ? time_last0 : time_last1;
		count0 += count1;

		*merged_val = my_malloc(32);
		*len_merged_val = pack_triplet(*merged_val, time_first0, time_last0, count0);
	} else {
		*merged_val = my_calloc(1, 1);
		*len_merged_val = 0;
	}
}
