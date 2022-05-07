/*
 * Exponential-backoff Retry Strategy
 *
 * Copyright (c) 2008-2022 Aerospike, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

//==========================================================
// Includes.
//

#include <stdint.h>


//==========================================================
// Typedefs & constants.
//

/*
 * Global retry strategy struct, which all retry statuses reference.
 */
typedef struct retry_strategy {
	// retry delay is scale_factor * 2 ** (retry_attempts - 1), or 0 on the
	// first try
	uint64_t scale_factor;
	uint64_t max_retries;
} retry_strategy_t;

/*
 * Struct used to track retries of a transaction.
 */
typedef struct retry_status {
	uint32_t attempts;
} retry_status_t;


//==========================================================
// Public API.
//

void retry_strategy_init(retry_strategy_t*, uint64_t scale_factor,
		uint64_t max_retries);

void retry_status_init(retry_status_t*);

/*
 * Calculates the delay before retrying this transaction again, or -1 if the
 * transaction shouldn't retry any more and should fail.
 */
int64_t retry_status_next_delay(retry_status_t*, const retry_strategy_t*);

