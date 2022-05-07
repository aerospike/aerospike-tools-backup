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

#include <restore_status.h>


//==========================================================
// Typedefs & constants.
//

/*
 * Struct used to track the progress of an async batch write.
 */
typedef struct batch_tracker {
	batch_uploader_t* uploader;
	// the vector of records uploaded in this batch write.
	record_list_t records;
	// ops array used to store all operations structs for a batch write call
	// sequentially in memory.
	as_operations* ops;
	// the retry_status struct that handles the retry delay logic for this
	// transaction.
	retry_status_t retry_status;
} batch_tracker_t;

/*
 * Struct used to track the progress of async record writes when batch writes
 * aren't being used.
 */
typedef struct record_batch_tracker {
	batch_uploader_t* uploader;
	// the vector of records uploaded in this batch write.
	record_list_t records;
	// tracker for the current number of oustanding async aerospike_key_put_async calls
	uint64_t outstanding_calls;
	// set if any sub transaction failed in a retriable manner.
	bool should_retry;
	// the batch_status_t struct that tracks the counts of record statuses
	// (inserted, failed, etc).
	batch_status_t status;
	// the retry_status struct that handles the retry delay logic for this
	// transaction.
	retry_status_t retry_status;
} record_batch_tracker_t;

typedef enum {
	WRITE_RESULT_OK,
	WRITE_RESULT_PERMFAIL,
	WRITE_RESULT_RETRY
} write_result_t;


//==========================================================
// Forward Declarations.
//

static void _init_policy(batch_uploader_t*);
static void _init_batch_write_policy(batch_uploader_t*);
static void _init_key_put_policy(batch_uploader_t*);
static write_result_t _categorize_write_result(as_error* ae, const restore_config_t* conf);
static bool _batch_status_submit(batch_status_t* status, as_status write_status,
		const restore_config_t* conf);
static void _free_batch_records(as_batch_records* batch, as_operations* ops);
static void _await_async_calls(batch_uploader_t*);
static void _reserve_async_slot(batch_uploader_t*);
static void _release_async_slot(batch_uploader_t*);
static void _batch_submit_callback(as_error* ae, as_batch_records* records,
		void* udata, as_event_loop*);
static bool _do_batch_write(batch_uploader_t* uploader, as_batch_records* batch,
		batch_tracker_t* tracker);
static bool _submit_batch(batch_uploader_t*, record_list_t* records);
static void _key_put_submit_callback(as_error* ae, void* udata, as_event_loop*);
static bool _submit_key_recs(batch_uploader_t*, record_list_t* records);


//==========================================================
// Public API.
//

void
record_list_init(record_list_t* record_list, uint32_t capacity)
{
	as_vector_init(&record_list->records, sizeof(record_list_el_t), capacity);
}

void
record_list_free(record_list_t* record_list)
{
	for (uint32_t i = 0; i < record_list->records.size; i++) {
		as_record* rec = (as_record*) as_vector_get(&record_list->records, i);
		as_key_destroy(&rec->key);
		as_record_destroy(rec);
	}

	as_vector_destroy(&record_list->records);
}

void
record_list_swap(record_list_t* a, record_list_t* b)
{
	as_vector_swap(&a->records, &b->records);
}

uint32_t
record_list_size(record_list_t* records)
{
	return records->records.size;
}

void
record_list_clear(record_list_t* records)
{
	as_vector_clear(&records->records);
}

bool
record_list_append(record_list_t* record_list, as_record* record)
{
	as_record* rec_ptr = (as_record*) as_vector_reserve(&record_list->records);
	if (!as_record_move(rec_ptr, record)) {
		err("Failed to move the contents of the as_record");
		return false;
	}

	return true;
}

record_list_el_t*
record_list_get(record_list_t* record_list, uint32_t idx)
{
	return (record_list_el_t*) as_vector_get(&record_list->records, idx);
}

void
batch_status_init(batch_status_t* status)
{
	memset(status, 0, sizeof(batch_status_t));
}

int
batch_uploader_init(batch_uploader_t* uploader, aerospike* as,
		const restore_config_t* conf, bool batch_writes_enabled)
{
	if (pthread_mutex_init(&uploader->async_lock, NULL) != 0) {
		return -1;
	}

	if (pthread_cond_init(&uploader->async_cond, NULL) != 0) {
		pthread_mutex_destroy(&uploader->async_lock);
		return -1;
	}

	// Initialize the priority queue with max_async_batches capacity, as we will
	// never have more than that many outstanding batch transactions.
	if (priority_queue_init(&uploader->retry_queue, conf->max_async_batches) != 0) {
		pthread_cond_destroy(&uploader->async_cond);
		pthread_mutex_destroy(&uploader->async_lock);
		return -1;
	}

	uploader->as = as;
	uploader->max_async = conf->max_async_batches;
	uploader->error = false;
	uploader->batch_enabled = batch_writes_enabled;
	uploader->async_calls = 0;
	uploader->conf = conf;
	// Default to 150ms and 5 retries max
	retry_strategy_init(&uploader->retry_strategy, 150000, 5);
	uploader->upload_cb = NULL;

	_init_policy(uploader);

	return 0;
}

void
batch_uploader_free(batch_uploader_t* uploader)
{
	pthread_mutex_destroy(&uploader->async_lock);
	pthread_cond_destroy(&uploader->async_cond);
	priority_queue_free(&uploader->retry_queue);
}

void
batch_uploader_set_callback(batch_uploader_t* uploader,
		upload_batch_callback cb, void* udata)
{
	uploader->upload_cb = cb;
	uploader->udata = udata;
}

bool
batch_uploader_await(batch_uploader_t* uploader)
{
	_await_async_calls(uploader);
	return as_load_bool(&uploader->error);
}

bool
batch_uploader_submit(batch_uploader_t* uploader, record_list_t* records)
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
_init_policy(batch_uploader_t* uploader)
{
	if (uploader->batch_enabled) {
		_init_batch_write_policy(uploader);
	}
	else {
		_init_key_put_policy(uploader);
	}
}

static void
_init_batch_write_policy(batch_uploader_t* uploader)
{
	const restore_config_t* conf = uploader->conf;
	as_policy_batch* batch_policy = &uploader->batch_policy;
	as_policy_batch_write* batch_write_policy = &uploader->batch_write_policy;

	as_policy_batch_init(batch_policy);
	as_policy_batch_write_init(batch_write_policy);

	if (conf->no_generation) {
		batch_write_policy->gen = AS_POLICY_GEN_IGNORE;
	}
	else {
		batch_write_policy->gen = AS_POLICY_GEN_GT;
	}

	if (conf->unique) {
		batch_write_policy->exists = AS_POLICY_EXISTS_CREATE;
	}
	else if (conf->replace) {
		batch_write_policy->exists = AS_POLICY_EXISTS_CREATE_OR_REPLACE;
	}
	else {
		batch_write_policy->exists = AS_POLICY_EXISTS_IGNORE;
	}
}

static void
_init_key_put_policy(batch_uploader_t* uploader)
{
	const restore_config_t* conf = uploader->conf;
	as_policy_write* policy = &uploader->key_put_policy;
	as_policy_write_init(policy);

	if (conf->no_generation) {
		policy->gen = AS_POLICY_GEN_IGNORE;
	}
	else {
		policy->gen = AS_POLICY_GEN_GT;
	}

	if (conf->unique) {
		policy->exists = AS_POLICY_EXISTS_CREATE;
	}
	else if (conf->replace) {
		policy->exists = AS_POLICY_EXISTS_CREATE_OR_REPLACE;
	}
	else {
		policy->exists = AS_POLICY_EXISTS_IGNORE;
	}
}

/*
 * To be called after each transaction completes (once per batch write, once per
 * key_put) to determine if/how the transaction failed.
 */
static write_result_t
_categorize_write_result(as_error* ae, const restore_config_t* conf)
{
	(void) conf;

	if (ae == NULL) {
		return WRITE_RESULT_OK;
	}

	switch (ae->code) {
		// Errors handled by _batch_status_submit:
		case AEROSPIKE_ERR_RECORD_TOO_BIG:
		case AEROSPIKE_ERR_RECORD_KEY_MISMATCH:
		case AEROSPIKE_ERR_BIN_NAME:
		case AEROSPIKE_ERR_ALWAYS_FORBIDDEN:
		case AEROSPIKE_ERR_RECORD_GENERATION:
		case AEROSPIKE_ERR_RECORD_EXISTS:

		// Cases that we don't treat as errors:
		case AEROSPIKE_BATCH_FAILED:
		case AEROSPIKE_OK:
			return WRITE_RESULT_OK;

		// Cases that we retry on:
		case AEROSPIKE_NO_RESPONSE:
		case AEROSPIKE_MAX_ERROR_RATE:
		case AEROSPIKE_ERR_ASYNC_QUEUE_FULL:
		case AEROSPIKE_ERR_CONNECTION:
		case AEROSPIKE_ERR_TLS_ERROR:
		case AEROSPIKE_ERR_INVALID_NODE:
		case AEROSPIKE_ERR_NO_MORE_CONNECTIONS:
		case AEROSPIKE_ERR_ASYNC_CONNECTION:
		case AEROSPIKE_ERR_INVALID_HOST:
		case AEROSPIKE_ERR_SERVER:
		case AEROSPIKE_ERR_CLUSTER_CHANGE:
		case AEROSPIKE_ERR_TIMEOUT:
		case AEROSPIKE_ERR_CLUSTER:
		case AEROSPIKE_ERR_RECORD_BUSY:
		case AEROSPIKE_ERR_DEVICE_OVERLOAD:
		case AEROSPIKE_LOST_CONFLICT:
		case AEROSPIKE_QUOTA_EXCEEDED:
		case AEROSPIKE_ERR_BATCH_QUEUES_FULL:
		case AEROSPIKE_ERR_INDEX:
			return WRITE_RESULT_RETRY;

		case AEROSPIKE_ERR_BATCH_DISABLED:
			err("Batch writes appear to be disabled, turn them off by passing "
					"--disable-batch-writes to asrestore");
			return WRITE_RESULT_PERMFAIL;

		default: 
			err("Error while storing record - code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			return WRITE_RESULT_PERMFAIL;
	}
}

/*
 * To be called for each record, determines which category of write the
 * transaction belongs to (inserted, ignored, etc.) and returns false if the
 * transaction errored.
 */
static bool
_batch_status_submit(batch_status_t* status,
		as_status write_status, const restore_config_t* conf)
{
	switch (write_status) {
		// Record specific error either ignored or restore
		// is aborted. retry is meaningless
		case AEROSPIKE_ERR_RECORD_TOO_BIG:
		case AEROSPIKE_ERR_RECORD_KEY_MISMATCH:
		case AEROSPIKE_ERR_BIN_NAME:
		case AEROSPIKE_ERR_ALWAYS_FORBIDDEN:
			as_incr_uint64(&status->ignored_records);

			if (!conf->ignore_rec_error) {
				err("Error while storing record");
				return false;
			}
			break;

		// Conditional error based on input config. No retries.
		case AEROSPIKE_ERR_RECORD_GENERATION:
			as_incr_uint64(&status->fresher_records);
			break;

		case AEROSPIKE_ERR_RECORD_EXISTS:
			as_incr_uint64(&status->existed_records);
			break;

		case AEROSPIKE_OK:
			as_incr_uint64(&status->inserted_records);
			break;

		default:
			err("Error while storing record");
			return false;
	}

	return true;
}

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
	batch_tracker_t* tracker = (batch_tracker_t*) udata;
	batch_uploader_t* uploader = tracker->uploader;
	record_list_t* records = &tracker->records;

	batch_status_t status;
	batch_status_init(&status);

	switch(_categorize_write_result(ae, uploader->conf)) {
		case WRITE_RESULT_PERMFAIL:
			err("Error in aerospike_batch_write_async call - "
					"code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			as_store_bool(&uploader->error, true);
			status.has_error = true;
			break;

		case WRITE_RESULT_RETRY:
			// FIXME delay if necessary.
			if (_do_batch_write(uploader, batch, tracker)) {
				// Don't mark the outstanding transaction as complete.
				return;
			}
			else {
				as_store_bool(&uploader->error, true);
				status.has_error = true;
			}
			break;

		case WRITE_RESULT_OK:
			// go through records and accumulate record statuses into the status
			// struct.
			for (uint32_t i = 0; i < record_list_size(records); i++) {
				as_batch_write_record* batch_write =
					(as_batch_write_record*) as_vector_get(&batch->list, i);
				if (!_batch_status_submit(&status, batch_write->result,
							uploader->conf)) {
					as_store_bool(&uploader->error, true);
					status.has_error = true;
				}
			}
			break;
	}

	_free_batch_records(batch, tracker->ops);

	for (uint32_t i = 0; i < record_list_size(records); i++) {
		record_list_el_t* el = record_list_get(records, i);
		as_record_destroy(&el->record);
	}
	record_list_free(records);

	free(tracker);

	if (uploader->upload_cb != NULL) {
		uploader->upload_cb(&status, uploader->udata);
	}

	_release_async_slot(uploader);
}

static bool
_do_batch_write(batch_uploader_t* uploader, as_batch_records* batch,
		batch_tracker_t* tracker)
{
	as_status status;
	as_error ae;

	status = aerospike_batch_write_async(uploader->as, &ae,
			&uploader->batch_policy, batch, _batch_submit_callback, tracker, NULL);

	if (status != AEROSPIKE_OK) {
		err("Error while initiating aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae.code, ae.message, ae.file, ae.line);
		as_store_bool(&uploader->error, true);
		return false;
	}

	return true;
}

static bool
_submit_batch(batch_uploader_t* uploader, record_list_t* records)
{
	uint32_t n_records = record_list_size(records);

	if (n_records == 0) {
		return true;
	}

	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (as_load_bool(&uploader->error)) {
		_release_async_slot(uploader);
		return false;
	}

	as_batch_records* batch = as_batch_records_create(n_records);

	as_operations* ops = cf_malloc(n_records * sizeof(as_operations));

	for (uint32_t i = 0; i < n_records; i++) {
		record_list_el_t* el = record_list_get(records, i);
		as_record* rec = &el->record;

		as_batch_write_record* batch_write = as_batch_write_reserve(batch);
		batch_write->policy = &uploader->batch_write_policy;

		if (!as_key_move(&batch_write->key, &rec->key)) {
			_free_batch_records(batch, ops);
			_release_async_slot(uploader);
			return false;
		}

		// write the record as a series of bin-ops on the key
		as_operations* op = &ops[i];
		as_operations_init(op, rec->bins.size);
		op->gen = rec->gen;
		for (uint32_t bin_idx = 0; bin_idx < rec->bins.size; bin_idx++) {
			as_operations_add_write(op, rec->bins.entries[bin_idx].name,
					rec->bins.entries[bin_idx].valuep);
			as_val_reserve(rec->bins.entries[bin_idx].valuep);
		}

		batch_write->ops = op;
	}

	batch_tracker_t* tracker =
		(batch_tracker_t*) cf_malloc(sizeof(batch_tracker_t));
	tracker->uploader = uploader;
	tracker->ops = ops;
	retry_status_init(&tracker->retry_status);

	// initialize args->records, then move the contents of records into it.
	record_list_init(&tracker->records, record_list_size(records));
	record_list_swap(&tracker->records, records);

	if (!_do_batch_write(uploader, batch, tracker)) {
		cf_free(tracker);

		// put records back and destroy the one made in this method.
		record_list_swap(&tracker->records, records);
		record_list_free(&tracker->records);

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
	record_batch_tracker_t* tracker = (record_batch_tracker_t*) udata;
	batch_uploader_t* uploader = tracker->uploader;

	switch (_categorize_write_result(ae, uploader->conf)) {
		case WRITE_RESULT_PERMFAIL:
			err("Error in aerospike_key_put_async call - "
					"code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			as_store_bool(&uploader->error, true);
			as_store_bool(&tracker->status.has_error, true);
			break;

		case WRITE_RESULT_RETRY:
			break;

		case WRITE_RESULT_OK:
			if (!_batch_status_submit(&tracker->status,
						ae == NULL ? AEROSPIKE_OK : ae->code,
						uploader->conf)) {
				as_store_bool(&uploader->error, true);
				as_store_bool(&tracker->status.has_error, true);
			}
			break;
	}

	if (as_aaf_uint64(&tracker->outstanding_calls, -1lu) == 0) {
		// if this is the last record, we can make the upload_batch callback.
		if (uploader->upload_cb != NULL) {
			uploader->upload_cb(&tracker->status, uploader->udata);
		}

		record_list_free(&tracker->records);
		cf_free(tracker);
		_release_async_slot(uploader);
	}
}

/*
 * Write all records using aerospike_key_put_async. If any transaction fails to
 * submit for any reason, this method does not catch the error. The caller may
 * assume this method always succeeds, and any errors will be caught by the
 * callback.
 */
static void
_do_key_recs_write(batch_uploader_t* uploader, record_batch_tracker_t* tracker)
{
	as_error ae;
	as_status status;

	record_list_t* records = &tracker->records;
	uint32_t n_records = record_list_size(records);

	for (uint32_t i = 0; i < n_records; i++) {
		record_list_el_t* el = record_list_get(records, i);
		as_record* rec = &el->record;
		as_key* key = &rec->key;

		status = aerospike_key_put_async(uploader->as, &ae,
				&uploader->key_put_policy, key, rec, _key_put_submit_callback,
				tracker, NULL, NULL);
		if (status != AEROSPIKE_OK) {
			err("Error while initiating aerospike_key_put_async call - "
					"code %d: %s at %s:%d",
					ae.code, ae.message, ae.file, ae.line);
			as_store_bool(&uploader->error, true);
			as_store_bool(&tracker->status.has_error, true);

			// Since there may have been some calls that succeeded before
			// this one, decrement the number of outstanding calls by the
			// number that failed to initialize (this one and all succeeding
			// ones). If we happen to decrease this value to 0, free the
			// tracker and release our hold on an async batch slot.
			if (as_aaf_uint64(&tracker->outstanding_calls,
						(uint64_t) -(n_records - i)) == 0) {
				// if this is the last record, we can make the upload_batch
				// callback.
				if (uploader->upload_cb != NULL) {
					uploader->upload_cb(&tracker->status, uploader->udata);
				}

				record_list_free(&tracker->records);
				cf_free(tracker);

				_release_async_slot(uploader);
			}

			return;
		}
	}
}

static bool
_submit_key_recs(batch_uploader_t* uploader, record_list_t* records)
{
	uint32_t n_records = record_list_size(records);

	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (as_load_bool(&uploader->error)) {
		_release_async_slot(uploader);
		return false;
	}

	record_batch_tracker_t* tracker =
		(record_batch_tracker_t*) cf_malloc(sizeof(record_batch_tracker_t));
	tracker->uploader = uploader;
	tracker->outstanding_calls = n_records;
	batch_status_init(&tracker->status);
	retry_status_init(&tracker->retry_status);

	// initialize args->records, then move the contents of records into it.
	record_list_init(&tracker->records, record_list_size(records));
	record_list_swap(&tracker->records, records);

	_do_key_recs_write(uploader, tracker);

	return true;
}
