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

#include <priority_queue.h>
#include <restore_config.h>
#include <retry_strategy.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

// forward declare, as we can't include it in this file.
typedef struct restore_status restore_status_t;

typedef struct record_list_el {
	as_record record;
	bool should_retry;
} record_list_el_t;

typedef struct record_list {
	as_vector records;
} record_list_t;

/*
 * The struct to keep track of the status of a batch upload, both for multiple
 * key-put uploads and for batch-write uploads.
 */
typedef struct batch_status {
	// set to true if any of the transactions have failed.
	bool has_error;

	// The number of records ignored because of record level permanent error while
	// restoring, e.g RECORD_TOO_BIG. Enabled or disabled using
	// --ignore-record-error flag.
	uint64_t ignored_records;
	// The number of successfully restored records.
	uint64_t inserted_records;
	// The number of records dropped because they already existed in the
	// database.
	uint64_t existed_records;
	// The number of records dropped because the database already contained the
	// records with a higher generation count.
	uint64_t fresher_records;
} batch_status_t;

/*
 * Callback function made after a batch finishes uploading.
 *
 * parameters:
 *  - batch_status_t* status: the batch_status_t struct for the upload
 *        batch that just completed.
 *  - void* udata: the udata passed to batch_uploader_set_callback.
 */
typedef void (*upload_batch_callback)(batch_status_t*, void*);

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

	// Lock/condition variable pair used to access all shared resources in the
	// batch_uploader struct.
	pthread_mutex_t async_lock;
	pthread_cond_t async_cond;

	const restore_config_t* conf;

	// The retry strategy to be used by failed transactions.
	retry_strategy_t retry_strategy;
	// Queue to place transactions that are delaying before retrying.
	priority_queue_t retry_queue;

	union {
		// only one of the two will be used, depending on whether batch_enabled
		// is true.
		struct {
			as_policy_batch batch_policy;
			as_policy_batch_write batch_write_policy;
		};
		as_policy_write key_put_policy;
	};

	/*
	 * Callback to be made after a batch of records finishes uploading.
	 */
	upload_batch_callback upload_cb;
	// User-data to be passed to upload_batch_callback.
	void* udata;
} batch_uploader_t;


//==========================================================
// Public API.
//

/*
 * Initializes a record list struct given the initial capacity of records (will
 * resize beyond the initial capacity if necessary).
 */
void record_list_init(record_list_t*, uint32_t capacity);

void record_list_free(record_list_t*);

/*
 * Swaps the contents of two record_list's.
 */
void record_list_swap(record_list_t* a, record_list_t* b);

/*
 * Returns the number of records in the record list.
 */
uint32_t record_list_size(record_list_t*);

/*
 * Clears the contents of a record list without freeing any of the records
 * contained in it.
 */
void record_list_clear(record_list_t*);

/*
 * Inserts a record into the record list, transferring ownership of the record
 * to the record list.
 *
 * Returns false if inserting the record failed for any reason.
 */
bool record_list_append(record_list_t*, as_record* record);

/*
 * Returns a pointer to the record_list_el struct at the given index.
 */
record_list_el_t* record_list_get(record_list_t*, uint32_t idx);

/*
 * Initializes the batch_status_t struct to its default values.
 */
void batch_status_init(batch_status_t*);

/*
 * Initializes the batch uploader, given the aerospike client instance, config
 * struct, and batch_writes_enabled flag.
 *
 * note: with batch writes disabled, the maximum number of async
 *     commands is max_async * batch_size.
 */
int batch_uploader_init(batch_uploader_t*, aerospike* as,
		const restore_config_t*, bool batch_writes_enabled);

/*
 * Frees the batch uploader, blocking until all outstanding async calls have
 * completed.
 */
void batch_uploader_free(batch_uploader_t*);

/*
 * Sets the callback to make after a batch upload completes to cb with given
 * udata.
 */
void batch_uploader_set_callback(batch_uploader_t*, upload_batch_callback cb,
		void* udata);

/*
 * Blocks until all outstanding async batch calls have completed.
 *
 * Returns false if an error occurred on any of the transactions.
 */
bool batch_uploader_await(batch_uploader_t*);

/*
 * Submits a batch of records for uploading, blocking if max_async commands are
 * still outstanding until this batch is able to be submitted for upload.
 *
 * Fails and returns false if any number of outstanding async calls have failed
 * for any reason at any point. If false is returned, records will not have been
 * modified.
 */
bool batch_uploader_submit(batch_uploader_t*, record_list_t* records);
