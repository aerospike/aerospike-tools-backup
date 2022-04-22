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

#include <batch_uploader.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/aerospike_key.h>
#include <aerospike/as_record.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"


//==========================================================
// Typedefs & constants.
//

/*
 * Struct used to track the progress of async record writes when batch writes
 * aren't available.
 */
typedef struct record_batch_tracker {
	batch_uploader_t* uploader;
	// tracker for the current number of oustanding async aerospike_key_put_async calls
	uint64_t outstanding_calls;
} record_batch_tracker_t;

typedef struct batch_write_cb_args {
	batch_uploader_t* uploader;
	// ops array used to store all operations structs for a batch write call
	// sequentially in memory.
	as_operations* ops;
} batch_write_cb_args_t;


//==========================================================
// Forward Declarations.
//

static void _free_batch_records(as_batch_records* batch, as_operations* ops);
static void _await_async_calls(batch_uploader_t*);
static void _reserve_async_slot(batch_uploader_t*);
static void _release_async_slot(batch_uploader_t*);
static void _batch_submit_callback(as_error* ae, as_batch_records* records,
		void* udata, as_event_loop*);
static bool _submit_batch(batch_uploader_t*, as_vector* records);
static void _key_put_submit_callback(as_error* ae, void* udata, as_event_loop*);
static bool _submit_key_recs(batch_uploader_t*, as_vector* records);


//==========================================================
// Public API.
//

int
batch_uploader_init(batch_uploader_t* uploader, uint32_t max_async,
		aerospike* as, const server_version_t* version_info)
{
	if (pthread_mutex_init(&uploader->async_lock, NULL) != 0) {
		return -1;
	}

	if (pthread_cond_init(&uploader->async_cond, NULL) != 0) {
		pthread_mutex_destroy(&uploader->async_lock);
		return -1;
	}

	uploader->as = as;
	uploader->max_async = max_async;
	uploader->error = false;
	uploader->batch_enabled = server_has_batch_writes(version_info);
	uploader->async_calls = 0;

	return 0;
}

void
batch_uploader_free(batch_uploader_t* uploader)
{
	pthread_mutex_destroy(&uploader->async_lock);
	pthread_cond_destroy(&uploader->async_cond);
}

bool
batch_uploader_await(batch_uploader_t* uploader)
{
	_await_async_calls(uploader);
	return as_load_bool(&uploader->error);
}

bool
batch_uploader_submit(batch_uploader_t* uploader, as_vector* records)
{
	if (uploader->batch_enabled) {
		return _submit_batch(uploader, records);
	}
	else {
		return _submit_key_recs(uploader, records);
	}
}


//==========================================================
// Local helpers.
//

static void
_free_batch_records(as_batch_records* batch, as_operations* ops)
{
	for (uint32_t i = 0; i < batch->list.size; i++) {
		as_operations_destroy(&ops[i]);
	}
	cf_free(ops);

	as_batch_records_destroy(batch);
}

static void
_await_async_calls(batch_uploader_t* uploader)
{
	pthread_mutex_lock(&uploader->async_lock);
	while (as_load_uint64(&uploader->async_calls) != 0) {
		safe_wait(&uploader->async_cond, &uploader->async_lock);
	}
	pthread_mutex_unlock(&uploader->async_lock);
}

static void
_reserve_async_slot(batch_uploader_t* uploader)
{
	uint64_t max_async = (uint64_t) uploader->max_async;

	pthread_mutex_lock(&uploader->async_lock);
	while (as_load_uint64(&uploader->async_calls) == max_async) {
		safe_wait(&uploader->async_cond, &uploader->async_lock);
	}

	uploader->async_calls++;
	pthread_mutex_unlock(&uploader->async_lock);
}

static void
_release_async_slot(batch_uploader_t* uploader)
{
	pthread_mutex_lock(&uploader->async_lock);
	uploader->async_calls--;
	pthread_mutex_unlock(&uploader->async_lock);

	pthread_cond_broadcast(&uploader->async_cond);
}

static void
_batch_submit_callback(as_error* ae, as_batch_records* batch, void* udata,
		as_event_loop* event_loop)
{
	(void) event_loop;
	batch_write_cb_args_t* args = (batch_write_cb_args_t*) udata;
	batch_uploader_t* uploader = args->uploader;

	if (ae != NULL) {
		err("Error in aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae->code, ae->message, ae->file, ae->line);
		as_store_bool(&uploader->error, true);
	}

	_free_batch_records(batch, args->ops);

	_release_async_slot(uploader);
}

static bool
_submit_batch(batch_uploader_t* uploader, as_vector* records)
{
	as_error ae;
	as_status status;

	if (records->size == 0) {
		return true;
	}

	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (as_load_bool(&uploader->error)) {
		_release_async_slot(uploader);
		return false;
	}

	as_batch_records* batch = as_batch_records_create(records->size);

	as_operations* ops = cf_malloc(records->size * sizeof(as_operations));

	for (uint32_t i = 0; i < records->size; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);
		as_batch_write_record* batch_write = as_batch_write_reserve(batch);

		if (!as_key_move(&batch_write->key, &rec->key)) {
			_free_batch_records(batch, ops);
		}

		// write the record as a series of bin-ops on the key
		as_operations* op = &ops[i];
		as_operations_init(op, rec->bins.size);
		for (uint32_t bin_idx = 0; bin_idx < rec->bins.size; bin_idx++) {
			as_operations_add_write(op, rec->bins.entries[bin_idx].name,
					&rec->bins.entries[bin_idx].value);
		}

		batch_write->ops = op;
	}

	batch_write_cb_args_t* args =
		(batch_write_cb_args_t*) cf_malloc(sizeof(batch_write_cb_args_t*));
	args->uploader = uploader;
	args->ops = ops;

	status = aerospike_batch_write_async(uploader->as, &ae, NULL, batch,
			_batch_submit_callback, args, NULL);

	// free everything before checking for errors

	if (status != AEROSPIKE_OK) {
		err("Error while initiating aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae.code, ae.message, ae.file, ae.line);
		as_store_bool(&uploader->error, true);
		_free_batch_records(batch, ops);
		_release_async_slot(uploader);
		return false;
	}

	return true;
}

static void
_key_put_submit_callback(as_error* ae, void* udata, as_event_loop* event_loop)
{
	(void) event_loop;
	record_batch_tracker_t* batch_tracker = (record_batch_tracker_t*) udata;
	batch_uploader_t* uploader = batch_tracker->uploader;

	if (ae != NULL) {
		err("Error in aerospike_key_put_async call - "
				"code %d: %s at %s:%d",
				ae->code, ae->message, ae->file, ae->line);
		as_store_bool(&uploader->error, true);
	}

	if (as_aaf_uint64(&batch_tracker->outstanding_calls, -1lu) == 0) {
		cf_free(batch_tracker);
		_release_async_slot(uploader);
	}
}

static bool
_submit_key_recs(batch_uploader_t* uploader, as_vector* records)
{
	as_error ae;
	as_status status;

	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (as_load_bool(&uploader->error)) {
		_release_async_slot(uploader);
		return false;
	}

	uint32_t n_records = records->size;

	record_batch_tracker_t* batch_tracker =
		(record_batch_tracker_t*) cf_malloc(sizeof(record_batch_tracker_t));
	batch_tracker->uploader = uploader;
	batch_tracker->outstanding_calls = n_records;

	for (uint32_t i = 0; i < n_records; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);
		as_key* key = &rec->key;

		status = aerospike_key_put_async(uploader->as, &ae, NULL, key, rec,
				_key_put_submit_callback, batch_tracker, NULL, NULL);
		if (status != AEROSPIKE_OK) {
			err("Error while initiating aerospike_key_put_async call - "
					"code %d: %s at %s:%d",
					ae.code, ae.message, ae.file, ae.line);
			as_store_bool(&uploader->error, true);

			// Since there may have been some calls that succeeded before
			// this one, decrement the number of outstanding calls by the
			// number that failed to initialize (this one and all succeeding
			// ones). If we happen to decrease this value to 0, free the
			// batch_tracker and release our hold on an async batch slot.
			if (as_aaf_uint64(&batch_tracker->outstanding_calls,
						(uint64_t) -(n_records - i)) == 0) {
				cf_free(batch_tracker);
				_release_async_slot(uploader);
			}

			return false;
		}
	}

	return true;
}

