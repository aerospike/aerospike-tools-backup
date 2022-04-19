/*
 * Aerospike Batch Uploader
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

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/aerospike_batch.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"

#include <utils.h>


//==========================================================
// Typedefs & constants.
//

/*
 * The batch uploader struct, which is used to manage the concurrent uploading
 * of batches of records to the Aerospike server.
 */
typedef struct batch_uploader {
	aerospike* as;
	uint32_t max_async;
	// Set whenever an error has occurred.
	bool error;
	// Set when batch writes are available.
	bool batch_enabled;

	// The current number of oustanding record batches.
	uint64_t async_calls;

	pthread_mutex_t async_lock;
	pthread_cond_t async_cond;
} batch_uploader_t;


//==========================================================
// Public API.
//

/*
 * Initializes the batch uploader, given the max async batch commands to be sent
 * to the server at a time, the aerospike instance, and the server version info
 * struct (in the case of backing up to pre-6.0 servers, the maximum number of
 * async commands is max_async * batch_size).
 */
int batch_uploader_init(batch_uploader_t*, uint32_t max_async, aerospike*,
		server_version_t*);

/*
 * Frees the batch uploader, blocking until all outstanding async calls have
 * completed.
 */
void batch_uploader_free(batch_uploader_t*);

/*
 * Blocks until all outstanding async batch calls have completed.
 */
void batch_uploader_await(batch_uploader_t*);

/*
 * Submits a batch of records for uploading, blocking if max_async commands are
 * still outstanding until this batch is able to be submitted for upload.
 *
 * Fails and returns false if any number of outstanding async calls have failed
 * for any reason at any point.
 */
bool batch_uploader_submit(batch_uploader_t*, as_vector* records);

