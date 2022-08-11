/*
 * Copyright 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

//==========================================================
// Includes.
//

#include <retry_strategy.h>


//==========================================================
// Public API.
//

void
retry_strategy_init(retry_strategy_t* strategy, uint64_t scale_factor,
		uint64_t max_retries)
{
	strategy->scale_factor = scale_factor;
	strategy->max_retries = max_retries;
}

void
retry_status_init(retry_status_t* status)
{
	status->attempts = 0;
}

int64_t
retry_status_next_delay(retry_status_t* status, const retry_strategy_t* strategy)
{
	if (status->attempts >= strategy->max_retries) {
		return -1;
	}
	else if (status->attempts == 0) {
		status->attempts++;
		return 0;
	}
	else {
		status->attempts++;
		return (int64_t) ((((uint64_t) 1) << (status->attempts - 2)) * strategy->scale_factor);
	}
}

