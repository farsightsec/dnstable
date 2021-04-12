/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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
