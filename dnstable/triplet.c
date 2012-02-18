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

size_t
triplet_pack(uint8_t *orig_buf, uint64_t val1, uint64_t val2, uint64_t val3)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	buf += mtbl_varint_encode64(buf, val3);
	return (buf - orig_buf);
}

void
triplet_unpack(const uint8_t *buf, size_t len_buf, uint64_t *val1, uint64_t *val2, uint64_t *val3)
{
	size_t bytes_read = 0;
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val1);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val2);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val3);
	assert(bytes_read == len_buf);
}
