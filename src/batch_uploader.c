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
 * Struct used to track the progress of async record writes when batch writes
 * aren't being used.
 */
typedef struct record_batch_tracker {
	batch_uploader_t* uploader;
	// tracker for the current number of oustanding async aerospike_key_put_async calls
	uint64_t outstanding_calls;
	// the batch_status_t struct that tracks the counts of record statuses
	// (inserted, failed, etc).
	batch_status_t status;
} record_batch_tracker_t;

/*
 * The arguments struct to be passed to the batch_submit complete callback
 */
typedef struct batch_write_cb_args {
	batch_uploader_t* uploader;
	// the vector of records uploaded in this batch write.
	as_vector records;
	// ops array used to store all operations structs for a batch write call
	// sequentially in memory.
	as_operations* ops;
} batch_write_cb_args_t;


//==========================================================
// Forward Declarations.
//

static void _init_policy(batch_uploader_t*);
static void _init_batch_write_policy(batch_uploader_t*);
static void _init_key_put_policy(batch_uploader_t*);
static bool _validate_write_result(as_error* ae, const restore_config_t* conf);
static bool _batch_status_submit(batch_status_t* status, as_status write_status,
		const restore_config_t* conf);
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

	uploader->as = as;
	uploader->max_async = conf->max_async_batches;
	uploader->error = false;
	uploader->batch_enabled = batch_writes_enabled;
	uploader->async_calls = 0;
	uploader->conf = conf;
	uploader->upload_cb = NULL;

	_init_policy(uploader);

	return 0;
}

void
batch_uploader_free(batch_uploader_t* uploader)
{
	pthread_mutex_destroy(&uploader->async_lock);
	pthread_cond_destroy(&uploader->async_cond);
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
 * key_put) to determine if the transaction failed.
 */
static bool
_validate_write_result(as_error* ae, const restore_config_t* conf)
{
	(void) conf;

	switch (ae->code) {
		// System level permanent errors. No point in continuing. Fail
		// immediately. The list is by no means complete, all missed cases
		// would fall into default and go through n_retries cycle and
		// eventually fail.
		case AEROSPIKE_ERR_SERVER_FULL:
		case AEROSPIKE_ROLE_VIOLATION:
			err("Error while storing record - code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			return false;

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
			return true;

		default: 
			err("Error while storing record - code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			return false;
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
	batch_write_cb_args_t* args = (batch_write_cb_args_t*) udata;
	batch_uploader_t* uploader = args->uploader;
	as_vector* records = &args->records;

	batch_status_t status;
	batch_status_init(&status);

	if (ae != NULL && !_validate_write_result(ae, uploader->conf)) {
		err("Error in aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae->code, ae->message, ae->file, ae->line);
		as_store_bool(&uploader->error, true);
		status.has_error = true;
	}
	else {
		// go through records and accumulate record statuses into the status
		// struct.
		for (uint32_t i = 0; i < records->size; i++) {
			as_batch_write_record* batch_write =
				(as_batch_write_record*) as_vector_get(&batch->list, i);
			if (!_batch_status_submit(&status, batch_write->result,
						uploader->conf)) {
				as_store_bool(&uploader->error, true);
				status.has_error = true;
			}
		}
	}

	_free_batch_records(batch, args->ops);

	for (uint32_t i = 0; i < records->size; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);
		as_record_destroy(rec);
	}
	as_vector_destroy(records);

	free(args);

	if (uploader->upload_cb != NULL) {
		uploader->upload_cb(&status, uploader->udata);
	}

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
		batch_write->policy = &uploader->batch_write_policy;

		if (!as_key_move(&batch_write->key, &rec->key)) {
			_free_batch_records(batch, ops);
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

	batch_write_cb_args_t* args =
		(batch_write_cb_args_t*) cf_malloc(sizeof(batch_write_cb_args_t));
	args->uploader = uploader;
	args->ops = ops;

	// initialize args->records vector, then move the contents of records into
	// it.
	as_vector_init(&args->records, records->item_size, records->size);
	as_vector_swap(&args->records, records);

	status = aerospike_batch_write_async(uploader->as, &ae,
			&uploader->batch_policy, batch, _batch_submit_callback, args, NULL);

	if (status != AEROSPIKE_OK) {
		err("Error while initiating aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae.code, ae.message, ae.file, ae.line);
		as_store_bool(&uploader->error, true);

		as_vector_swap(&args->records, records);
		as_vector_destroy(&args->records);

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

	if (ae != NULL && !_validate_write_result(ae, uploader->conf)) {
		err("Error in aerospike_key_put_async call - "
				"code %d: %s at %s:%d",
				ae->code, ae->message, ae->file, ae->line);
		as_store_bool(&uploader->error, true);
		as_store_bool(&batch_tracker->status.has_error, true);
	}
	else {
		if (!_batch_status_submit(&batch_tracker->status,
					ae == NULL ? AEROSPIKE_OK : ae->code,
					uploader->conf)) {
			as_store_bool(&uploader->error, true);
			as_store_bool(&batch_tracker->status.has_error, true);
		}
	}

	if (as_aaf_uint64(&batch_tracker->outstanding_calls, -1lu) == 0) {
		// if this is the last record, we can make the upload_batch callback.
		if (uploader->upload_cb != NULL) {
			uploader->upload_cb(&batch_tracker->status, uploader->udata);
		}

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
	batch_status_init(&batch_tracker->status);

	for (uint32_t i = 0; i < n_records; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);
		as_key* key = &rec->key;

		status = aerospike_key_put_async(uploader->as, &ae,
				&uploader->key_put_policy, key, rec, _key_put_submit_callback,
				batch_tracker, NULL, NULL);
		if (status != AEROSPIKE_OK) {
			err("Error while initiating aerospike_key_put_async call - "
					"code %d: %s at %s:%d",
					ae.code, ae.message, ae.file, ae.line);
			as_store_bool(&uploader->error, true);
			as_store_bool(&batch_tracker->status.has_error, true);

			// Since there may have been some calls that succeeded before
			// this one, decrement the number of outstanding calls by the
			// number that failed to initialize (this one and all succeeding
			// ones). If we happen to decrease this value to 0, free the
			// batch_tracker and release our hold on an async batch slot.
			if (as_aaf_uint64(&batch_tracker->outstanding_calls,
						(uint64_t) -(n_records - i)) == 0) {
				// if this is the last record, we can make the upload_batch
				// callback.
				if (uploader->upload_cb != NULL) {
					uploader->upload_cb(&batch_tracker->status, uploader->udata);
				}

				cf_free(batch_tracker);
				_release_async_slot(uploader);
			}

			for (; i < n_records; i++) {
				as_record* rec = (as_record*) as_vector_get(records, i);
				as_key_destroy(&rec->key);
				as_record_destroy(rec);
			}

			return false;
		}

		as_key_destroy(key);
		as_record_destroy(rec);
	}

	return true;
}

