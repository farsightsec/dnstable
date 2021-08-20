/*
 * Copyright (c) 2012, 2021 by Farsight Security, Inc.
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

/*
 * Given two sorted arrays each of which has no duplicates,
 * return a sorted output array with duplicates removed.
 * Effectively, a union of two sorted sets.
 *
 * Returns the number of values in output, limited to max_output values
 * (excess values will be silently ignored).
 */
static int
sorted_merge_dedup(uint16_t *input1, int n_input1, uint16_t *input2, int n_input2, uint16_t *output, int max_output)
{
	uint16_t *orig_output = output;

	while (n_input1 > 0 || n_input2 > 0) {
		bool take_input1 = false;
		bool take_input2 = false;

		if (output - orig_output >= max_output)
			break; /* hit max; silently ignore any remaining values from inputs 1 or 2 */
		else if (n_input1 == 0 || (n_input2 > 0 && *input1 > *input2))
			take_input2 = true;
		else if (n_input2 == 0 || (n_input1 > 0 && *input1 < *input2))
			take_input1 = true;
		else /* equal values, remove from both arrays */
			take_input1 = take_input2 = true;

		if (take_input1) {
			*output = *input1++;
			n_input1--;
		}
		if (take_input2) {
			*output = *input2++;
			n_input2--;
		}
		output++;
	}

	return output - orig_output;
}


/*
 * During a merge of either RRSET_NAME_FWD or RDATA_NAME_REV entries,
 * if entry 1 has a non-empty rrtype bitmap and entry 2 has an empty
 * rrtype bitmap, the merge will be an empty bitmap.
 *
 * The logic is because merging "I only index these rrtypes" with "I
 * have no rrtype info: it could be any rrtype", the result should
 * reflect "it could be any rrtype".
 *
 * Note that to indicate an empty bitmap: we have to malloc a
 * non-empty value but return the length of the value as zero.
 * Otherwise, *len_merged_val should be equal to the size of the
 * malloced value we return.
 */
static uint8_t *
merge_rrtype_bitmaps(const uint8_t *val0, size_t len_val0,
		     const uint8_t *val1, size_t len_val1,
		     size_t *len_merged_val)
{
	uint8_t *res;
	rrtype_unpacked_set rrtype_set_1, rrtype_set_2, rrtype_set_merged;
	int count_rrtypes = 0, n_rrtypes1 = 0, n_rrtypes2 = 0;

	if (len_val0 == 0 || len_val1 == 0) {
		*len_merged_val = 0;
		res = my_malloc(1);
		*res = 0;	/* won't be used, but at least initialize it */
		return res;
	} else if (len_val0 == len_val1 && !memcmp(val0, val1, len_val0)) { /* identical values */
		*len_merged_val = len_val0;
		res = my_malloc(*len_merged_val);
		memcpy(res, val0, *len_merged_val);
		return res;
	} else if (len_val0 == 1 && len_val1 == 1) {
		rrtype_set_1.rrtypes[0] = (uint16_t)*val0;
		rrtype_set_2.rrtypes[0] = (uint16_t)*val1;
		n_rrtypes1 = 1;
		n_rrtypes2 = 1;
	} else if (len_val0 == 2 && len_val1 == 2) {
		rrtype_set_1.rrtypes[0] = (uint16_t)le16toh(*(uint16_t*)val0);
		rrtype_set_2.rrtypes[0] = (uint16_t)le16toh(*(uint16_t*)val1);
		n_rrtypes1 = 1;
		n_rrtypes2 = 1;
	} else {
		/* unpack both sides as possibly bitmaps, but they could be len 1 or 2 anyway. */
		n_rrtypes1 = rrtype_union_unpack(val0, len_val0, &rrtype_set_1);
		if (n_rrtypes1 == -1)
			return NULL; /* failed -- corrupt union or too many to unpack */

		n_rrtypes2 = rrtype_union_unpack(val1, len_val1, &rrtype_set_2);
		if (n_rrtypes2 == -1)
			return NULL; /* failed -- corrupt union or too many to unpack */
	}

	count_rrtypes = sorted_merge_dedup(rrtype_set_1.rrtypes, n_rrtypes1,
					   rrtype_set_2.rrtypes, n_rrtypes2,
					   rrtype_set_merged.rrtypes, MAX_RRTYPES_MAPPABLE);

	/* now form a new bitmap union */
	uint8_t bitmap[32];	/* 256 bits / 8 bits per byte */
	memset(bitmap, 0, sizeof(bitmap));
	uint8_t window_block = 0;
	uint8_t	bitmap_len = 0;
	uint8_t result_data[65536 / 8];
	uint16_t result_index = 0;

	for (int n = 0; n < count_rrtypes; n++) {
		uint16_t my_rrtype = rrtype_set_merged.rrtypes[n];
		uint8_t cur_window = my_rrtype / 256;

		if (cur_window != window_block) {
			/* Per RFC6840, do not write out an empty bitmap */
			if (bitmap_len > 0) {
				assert((result_index + sizeof(window_block) + sizeof(bitmap_len) + bitmap_len)
				       < sizeof(result_data)/sizeof(&result_data[0]));

				memcpy(&result_data[result_index], (const uint8_t*)&window_block,
				       sizeof(window_block));
				result_index += sizeof(window_block);

				memcpy(&result_data[result_index], (const uint8_t*)&bitmap_len,
				       sizeof(bitmap_len));
				result_index += sizeof(bitmap_len);

				memcpy(&result_data[result_index], (const uint8_t*)bitmap, bitmap_len);
				result_index += bitmap_len;

				bitmap_len = 0;
			}
			memset(bitmap, 0, sizeof(bitmap));
			window_block = cur_window;
		}

		uint8_t offset = my_rrtype % 256;
		uint8_t byte = offset / 8;
		uint8_t bit = offset % 8;

		bitmap[byte] |= 0x80 >> bit;
		bitmap_len = 1 + byte;
	}

	if (bitmap_len != 0) {
		assert((result_index + sizeof(window_block) + sizeof(bitmap_len) + bitmap_len)
		       < sizeof(result_data)/sizeof(&result_data[0]));

		memcpy(&result_data[result_index], (const uint8_t*)&window_block, sizeof(window_block));
		result_index += sizeof(window_block);

		memcpy(&result_data[result_index], (const uint8_t*)&bitmap_len, sizeof(bitmap_len));
		result_index += sizeof(bitmap_len);

		memcpy(&result_data[result_index], (const uint8_t*)bitmap, bitmap_len);
		result_index += bitmap_len;
	}

	*len_merged_val = result_index;
	res = my_malloc(*len_merged_val);
	memcpy(res, result_data, *len_merged_val);

	return res;
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
		dnstable_res res;

		res = triplet_unpack(val0, len_val0, &time_first0, &time_last0, &count0);
		assert(res == dnstable_res_success);
		res = triplet_unpack(val1, len_val1, &time_first1, &time_last1, &count1);
		assert(res == dnstable_res_success);

		time_first0 = (time_first0 < time_first1) ? time_first0 : time_first1;
		time_last0 = (time_last0 > time_last1) ? time_last0 : time_last1;
		count0 += count1;

		*merged_val = my_malloc(32);
		*len_merged_val = triplet_pack(*merged_val, time_first0, time_last0, count0);
	} else if (len_key && (key[0] == ENTRY_TYPE_RRSET_NAME_FWD ||
			       key[0] == ENTRY_TYPE_RDATA_NAME_REV)) {
		*merged_val = merge_rrtype_bitmaps(val0, len_val0, val1, len_val1, len_merged_val);
	} else if (len_key == 1 && (key[0] == ENTRY_TYPE_TIME_RANGE)) {
		dnstable_res res;

		if ((len_val0 == 0) || (len_val1 == 0)) {
			*merged_val = my_malloc(1);
			*len_merged_val = 0;
			return;
		}

		res = pair_unpack(val0, len_val0, &time_first0, &time_last0);
		assert(res == dnstable_res_success);
		res = pair_unpack(val1, len_val1, &time_first1, &time_last1);
		assert(res == dnstable_res_success);
		time_first0 = (time_first0 < time_first1) ? time_first0 : time_first1;
		time_last0 = (time_last0 > time_last1) ? time_last0 : time_last1;
		*merged_val = my_malloc(32);
		*len_merged_val = pair_pack(*merged_val, time_first0, time_last0);
	} else if (len_key == 2 && (key[0] == ENTRY_TYPE_VERSION)) {
		uint32_t vers0, vers1, minvers;
		size_t len;

		/*
		 * A zero-length value for a version entry indicates that the
		 * entry has been processed by a pre-versioning version of the
		 * dnstable merge function, or by a version of the dnstable
		 * merge function which does not support the version entry's
		 * type. In either case, we make the merged version value
		 * empty to preserve this indication.
		 */
		if ((len_val0 == 0) || (len_val1 == 0)) {
			*merged_val = my_calloc(1,1);
			*len_merged_val = 0;
			return;
		}

		switch(key[1]) {
		case ENTRY_TYPE_RRSET:
		case ENTRY_TYPE_RRSET_NAME_FWD:
		case ENTRY_TYPE_RDATA:
		case ENTRY_TYPE_RDATA_NAME_REV:
			break;
		default:
			*merged_val = my_calloc(1,1);
			*len_merged_val = 0;
			return;
		}

		len = mtbl_varint_decode32(val0, &vers0);
		assert(len == len_val0);
		len = mtbl_varint_decode32(val1, &vers1);
		assert(len == len_val1);
		minvers = (vers0 < vers1)?vers0:vers1;

		*len_merged_val = mtbl_varint_length(minvers);
		*merged_val = my_calloc(1, *len_merged_val);
		mtbl_varint_encode32(*merged_val, minvers);
	} else {
		*merged_val = my_calloc(1, 1);
		*len_merged_val = 0;
	}
}
