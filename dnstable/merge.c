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

                if (time_first0 == time_first1 && time_last0 == time_last1) {
                        /* if the time pairs are identical then use the maximum count */
                        if (count1 > count0)
                                count0 = count1;
                } else {
                        /* otherwise use the earliest of the first times,
                           the latest of the last times, and sum the counts */
                        time_first0 = (time_first0 < time_first1) ? time_first0 : time_first1;
                        time_last0 = (time_last0 > time_last1) ? time_last0 : time_last1;
                        count0 += count1;
                }

		*merged_val = my_malloc(32);
		*len_merged_val = triplet_pack(*merged_val, time_first0, time_last0, count0);
	} else {
		*merged_val = my_calloc(1, 1);
		*len_merged_val = 0;
	}
}
