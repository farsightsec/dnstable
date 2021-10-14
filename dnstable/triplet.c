/*
 * Copyright (c) 2012, 2014, 2021 by Farsight Security, Inc.
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

size_t
triplet_pack(uint8_t *orig_buf, uint64_t val1, uint64_t val2, uint64_t val3)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	buf += mtbl_varint_encode64(buf, val3);
	return (buf - orig_buf);
}

dnstable_res
triplet_unpack(const uint8_t *buf, size_t len_buf, uint64_t *val1, uint64_t *val2, uint64_t *val3)
{
	size_t bytes_read = 0;
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val1);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val2);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val3);
	if (bytes_read == len_buf)
		return (dnstable_res_success);
	return (dnstable_res_failure);
}

size_t
pair_pack(uint8_t *orig_buf, uint64_t val1, uint64_t val2)
{
	uint8_t *buf = orig_buf;
	buf += mtbl_varint_encode64(buf, val1);
	buf += mtbl_varint_encode64(buf, val2);
	return (buf - orig_buf);
}

dnstable_res
pair_unpack(const uint8_t *buf, size_t len_buf, uint64_t *val1, uint64_t *val2)
{
	size_t bytes_read = 0;
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val1);
	bytes_read += mtbl_varint_decode64(buf + bytes_read, val2);
	if (bytes_read == len_buf)
		return (dnstable_res_success);
	return (dnstable_res_failure);
}
