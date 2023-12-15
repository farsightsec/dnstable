/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012-2015, 2017-2021 by Farsight Security, Inc.
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

static const char *stage_strs[] = {
	[DNSTABLE_STAT_STAGE_FILTER_SINGLE_LABEL] = "single label",
	[DNSTABLE_STAT_STAGE_FILTER_RRTYPE] = "rrtype",
	[DNSTABLE_STAT_STAGE_FILTER_BAILIWICK] = "bailiwick",
	[DNSTABLE_STAT_STAGE_FILTER_TIME_STRICT] = "time strict",
	[DNSTABLE_STAT_STAGE_REMOVE_STRICT] = "remove strict",
	[DNSTABLE_STAT_STAGE_LJOIN] = "left join",
	[DNSTABLE_STAT_STAGE_FILTER_TIME] = "time",
	[DNSTABLE_STAT_STAGE_FILTER_OFFSET] = "offset",
};

static const unsigned int stage_strs_size = sizeof(stage_strs) / sizeof(stage_strs[0]);

static const char *category_strs[] = {
	[DNSTABLE_STAT_CATEGORY_FILTERED] = "filtered",
	[DNSTABLE_STAT_CATEGORY_ENTRIES] = "entries",
	[DNSTABLE_STAT_CATEGORY_SEEK] = "seek",
	[DNSTABLE_STAT_CATEGORY_MERGED] = "merged"
};
static const unsigned int category_strs_size = sizeof(category_strs) / sizeof(category_strs[0]);

const char *
dnstable_stat_stage_to_str(dnstable_stat_stage stage)
{
	if (stage < 0 || stage >= stage_strs_size)
		return NULL;
	return stage_strs[stage];
}

dnstable_res
dnstable_stat_str_to_stage(const char *stage, dnstable_stat_stage *res)
{
	unsigned int i;
	if (res == NULL || stage == NULL || *stage == '\0')
		return dnstable_res_failure;

	for (i = 0; i < stage_strs_size; ++i) {
		if (!strcasecmp(stage_strs[i], stage)) {
			*res = (dnstable_stat_stage) i;
			return dnstable_res_success;
		}
	}
	return dnstable_res_failure;
}

const char *
dnstable_stat_category_to_str(dnstable_stat_category cat)
{
	if (cat < 0 || cat >= category_strs_size)
		return NULL;
	return category_strs[cat];
}

dnstable_res
dnstable_stat_str_to_category(const char *category, dnstable_stat_category *res)
{
	unsigned int i;
	if (res == NULL || category == NULL || *category == '\0')
		return dnstable_res_failure;

	for (i = 0; i < category_strs_size; ++i) {
		if (!strcasecmp(category_strs[i], category)) {
			*res = (dnstable_stat_category) i;
			return dnstable_res_success;
		}
	}
	return dnstable_res_failure;
}
