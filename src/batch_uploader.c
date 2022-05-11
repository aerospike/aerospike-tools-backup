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
	as_vector records;
	// the as_batch_records struct used in the batch write call.
	as_batch_records* batch;
	// ops array used to store all operations structs for a batch write call
	// sequentially in memory.
	as_operations* ops;
	// the retry_status struct that handles the retry delay logic for this
	// transaction.
	retry_status_t retry_status;
} batch_tracker_t;

/*
 * Struct used to track the progress of a single async record write.
 */
typedef struct key_put_info {
	// the tracker tracking the progress of the batch of records this
	// transaction is a part of.
	struct record_batch_tracker* tracker;
	// set to true by the callback if the key_put failed and should be retried.
	bool should_retry;
} key_put_info_t;

/*
 * Struct used to track the progress of async record writes when batch writes
 * aren't being used.
 */
typedef struct record_batch_tracker {
	batch_uploader_t* uploader;
	// the vector of records uploaded in this batch write.
	as_vector records;
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

	// list of batch_size key_put_info structs to be used by the key_put
	// transactions, avoiding the need for dynamic memory allocation.
	key_put_info_t key_infos[];
} record_batch_tracker_t;

typedef enum {
	WRITE_RESULT_OK,
	WRITE_RESULT_PERMFAIL,
	WRITE_RESULT_RETRY
} write_result_t;


//==========================================================
// Forward Declarations.
//

static batch_tracker_t* _batch_tracker_alloc(batch_uploader_t* uploader,
		as_batch_records* batch, as_operations* ops, as_vector* records);
static void _batch_tracker_destroy(batch_tracker_t*);

static record_batch_tracker_t* _record_batch_tracker_alloc(
		batch_uploader_t* uploader, as_vector* records);
static void _record_batch_tracker_destroy(record_batch_tracker_t*);
static void _record_batch_tracker_reset(record_batch_tracker_t* tracker);

static void _init_policy(batch_uploader_t*);
static void _init_batch_write_policy(batch_uploader_t*);
static const as_policy_batch_write* _get_batch_write_policy(
		const batch_uploader_t*, bool key_send);
static void _init_key_put_policy(batch_uploader_t*);
static const as_policy_write* _get_key_put_policy(const batch_uploader_t*,
		bool key_send);

static uint64_t _queue_priority(const batch_uploader_t*,
		struct timespec* expiration_time);
static struct timespec _queue_priority_to_timespec(const batch_uploader_t*,
		uint64_t priority);
static bool _queue_batch_transaction(batch_uploader_t*,
		batch_tracker_t* tracker, uint64_t delay);
static bool _queue_key_rec_transactions(batch_uploader_t*,
		record_batch_tracker_t* tracker, uint64_t delay);
static struct timespec _queue_lowest_timeout(const batch_uploader_t*);
static bool _queue_submit_if_timeout(batch_uploader_t*);
static void _queue_clear(batch_uploader_t*);

static write_result_t _categorize_write_result(as_error* ae,
		const restore_config_t* conf);
static bool _batch_status_submit(batch_status_t* status, as_status write_status,
		const restore_config_t* conf);
static void _free_batch_records(as_batch_records* batch, as_operations* ops);
static void _await_async_calls(batch_uploader_t*);
static void _reserve_async_slot(batch_uploader_t*);
static void _release_async_slot(batch_uploader_t*);
static void _batch_submit_callback(as_error* ae, as_batch_records* records,
		void* udata, as_event_loop*);
static bool _do_batch_write(batch_uploader_t* uploader,
		batch_tracker_t* tracker);
static bool _submit_batch(batch_uploader_t*, as_vector* records);
static void _key_put_submit_callback(as_error* ae, void* udata, as_event_loop*);
static void _do_key_recs_write(batch_uploader_t* uploader,
		record_batch_tracker_t* tracker);
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
	uploader->retry_count = 0;
	uploader->async_calls = 0;
	uploader->conf = conf;
	get_current_time(&uploader->start_time);
	// Default to 150ms and 5 retries max
	retry_strategy_init(&uploader->retry_strategy, conf->retry_scale_factor,
			conf->max_retries);
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

uint64_t
batch_uploader_retry_count(const batch_uploader_t* uploader)
{
	return as_load_uint64(&uploader->retry_count);
}

bool
batch_uploader_has_error(const batch_uploader_t* uploader)
{
	return as_load_bool(&uploader->error);
}

void
batch_uploader_signal_error(batch_uploader_t* uploader)
{
	as_store_bool(&uploader->error, true);
	pthread_cond_broadcast(&uploader->async_cond);
}

bool
batch_uploader_await(batch_uploader_t* uploader)
{
	_await_async_calls(uploader);
	return !batch_uploader_has_error(uploader);
}

bool
batch_uploader_submit(batch_uploader_t* uploader, as_vector* records)
{
	if (records->size == 0) {
		return true;
	}

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

static batch_tracker_t*
_batch_tracker_alloc(batch_uploader_t* uploader, as_batch_records* batch,
		as_operations* ops, as_vector* records)
{
	batch_tracker_t* tracker =
		(batch_tracker_t*) cf_malloc(sizeof(batch_tracker_t));
	tracker->uploader = uploader;
	tracker->batch = batch;
	tracker->ops = ops;
	retry_status_init(&tracker->retry_status);

	// initialize args->records, then move the contents of records into it.
	as_vector_init(&tracker->records, records->item_size, records->size);
	as_vector_swap(&tracker->records, records);

	return tracker;
}

static void
_batch_tracker_destroy(batch_tracker_t* tracker)
{
	as_vector_destroy(&tracker->records);
	_free_batch_records(tracker->batch, tracker->ops);
	cf_free(tracker);
}

static record_batch_tracker_t*
_record_batch_tracker_alloc(batch_uploader_t* uploader, as_vector* records)
{
	uint32_t n_records = records->size;

	record_batch_tracker_t* tracker =
		(record_batch_tracker_t*) cf_malloc(sizeof(record_batch_tracker_t) +
				n_records * sizeof(key_put_info_t));
	tracker->uploader = uploader;
	tracker->outstanding_calls = n_records;
	tracker->should_retry = false;
	batch_status_init(&tracker->status);
	retry_status_init(&tracker->retry_status);

	// initialize args->records, then move the contents of records into it.
	as_vector_init(&tracker->records, records->item_size, n_records);
	as_vector_swap(&tracker->records, records);

	// initialize the key_put_info structs
	for (uint32_t i = 0; i < n_records; i++) {
		tracker->key_infos[i].tracker = tracker;
		// initialize to true on first pass so all transactions are triggered
		tracker->key_infos[i].should_retry = true;
	}

	return tracker;
}

static void
_record_batch_tracker_destroy(record_batch_tracker_t* tracker)
{
	as_vector_destroy(&tracker->records);
	cf_free(tracker);
}

/*
 * Resets the fields of the record batch tracker before retry.
 */
static void
_record_batch_tracker_reset(record_batch_tracker_t* tracker)
{
	as_store_bool(&tracker->should_retry, false);
	as_store_uint64(&tracker->outstanding_calls, tracker->records.size);
}

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

	batch_policy->base.socket_timeout = uploader->conf->socket_timeout;
	batch_policy->base.total_timeout = uploader->conf->total_timeout > 0 ?
		uploader->conf->total_timeout : uploader->conf->timeout;
	batch_write_policy->key = AS_POLICY_KEY_DIGEST;

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

	uploader->batch_write_policy_key_send = *batch_write_policy;
	uploader->batch_write_policy_key_send.key = AS_POLICY_KEY_SEND;
}

static const as_policy_batch_write*
_get_batch_write_policy(const batch_uploader_t* uploader, bool key_send)
{
	return key_send ? &uploader->batch_write_policy_key_send :
		&uploader->batch_write_policy;
}

static void
_init_key_put_policy(batch_uploader_t* uploader)
{
	const restore_config_t* conf = uploader->conf;
	as_policy_write* policy = &uploader->key_put_policy;
	as_policy_write_init(policy);

	policy->base.socket_timeout = uploader->conf->socket_timeout;
	policy->base.total_timeout = uploader->conf->total_timeout > 0 ?
		uploader->conf->total_timeout : uploader->conf->timeout;
	policy->key = AS_POLICY_KEY_DIGEST;

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

	uploader->key_put_policy_key_send = *policy;
	uploader->key_put_policy_key_send.key = AS_POLICY_KEY_SEND;
}

static const as_policy_write*
_get_key_put_policy(const batch_uploader_t* uploader, bool key_send)
{
	return key_send ? &uploader->key_put_policy_key_send :
		&uploader->key_put_policy;
}

static uint64_t
_queue_priority(const batch_uploader_t* uploader,
		struct timespec* expiration_time)
{
	uint64_t us_since_start = timespec_diff(&uploader->start_time,
			expiration_time);
	// We want highest priority transactions to be the ones that will time out
	// the soonest, so make the priority the additive inverse of us_since_start.
	return ~us_since_start;
}

/*
 * Converts a queue priority value back to a timespec, populating "ts".
 */
static struct timespec
_queue_priority_to_timespec(const batch_uploader_t* uploader, uint64_t priority)
{
	struct timespec ts = uploader->start_time;
	timespec_add_us(&ts, ~priority);
	return ts;
}

/*
 * Queues a batch transaction for retry in "delay" microseconds.
 */
static bool
_queue_batch_transaction(batch_uploader_t* uploader, batch_tracker_t* tracker,
		uint64_t delay)
{
	struct timespec exp_time;
	get_current_time(&exp_time);
	timespec_add_us(&exp_time, delay);

	pthread_mutex_lock(&uploader->async_lock);
	if (!priority_queue_push(&uploader->retry_queue, tracker,
			_queue_priority(uploader, &exp_time))) {
		pthread_mutex_unlock(&uploader->async_lock);
		err("Failed to queue batch transaction for later execution");
		return false;
	}
	pthread_mutex_unlock(&uploader->async_lock);

	pthread_cond_signal(&uploader->async_cond);
	return true;
}

/*
 * Queues a key-put batch transaction for retry in "delay" microseconds.
 */
static bool
_queue_key_rec_transactions(batch_uploader_t* uploader,
		record_batch_tracker_t* tracker, uint64_t delay)
{
	struct timespec exp_time;
	get_current_time(&exp_time);
	timespec_add_us(&exp_time, delay);

	pthread_mutex_lock(&uploader->async_lock);
	if (!priority_queue_push(&uploader->retry_queue, tracker,
			_queue_priority(uploader, &exp_time))) {
		pthread_mutex_unlock(&uploader->async_lock);
		err("Failed to queue write transactions for later execution");
		return false;
	}
	pthread_mutex_unlock(&uploader->async_lock);

	pthread_cond_signal(&uploader->async_cond);
	return true;
}

/*
 * Returns the timeout time of the soonest-expiring queued transaction for
 * retrying.
 *
 * This method has undefined behavior if the retry queue is empty.
 */
static struct timespec
_queue_lowest_timeout(const batch_uploader_t* uploader)
{
	pq_entry_t top_entry = priority_queue_peek(&uploader->retry_queue);
	return _queue_priority_to_timespec(uploader, top_entry.priority);
}

/*
 * Submits a single transaction from the retry queue, if any have timed out.
 *
 * Returns false if an error occurred.
 */
static bool
_queue_submit_if_timeout(batch_uploader_t* uploader)
{
	if (priority_queue_size(&uploader->retry_queue) == 0 ||
			batch_uploader_has_error(uploader)) {
		return true;
	}

	struct timespec now;
	get_current_time(&now);
	uint64_t now_priority = _queue_priority(uploader, &now);

	pq_entry_t pq_entry = priority_queue_peek(&uploader->retry_queue);
	if (pq_entry.priority > now_priority) {
		priority_queue_pop(&uploader->retry_queue);

		// The soonest-expiring queued transaction has timed out, execute that
		// now.
		if (uploader->batch_enabled) {
			batch_tracker_t* tracker = (batch_tracker_t*) pq_entry.udata;
			if (!_do_batch_write(uploader, tracker)) {
				return false;
			}
		}
		else {
			record_batch_tracker_t* tracker =
				(record_batch_tracker_t*) pq_entry.udata;
			_do_key_recs_write(uploader, tracker);
		}
	}

	return true;
}

/*
 * Immediately fails all jobs in the retry queue. This method must be called
 * while holding the async_lock.
 */
static void
_queue_clear(batch_uploader_t* uploader)
{
	// Free all async slots taken by the transactions in the retry queue.
	uploader->async_calls -= priority_queue_size(&uploader->retry_queue);

	while (priority_queue_size(&uploader->retry_queue) > 0) {
		if (uploader->batch_enabled) {
			batch_tracker_t* tracker =
				(batch_tracker_t*) priority_queue_pop(&uploader->retry_queue);

			batch_status_t status;
			batch_status_init(&status);
			status.has_error = true;

			if (uploader->upload_cb != NULL) {
				uploader->upload_cb(&status, uploader->udata);
			}

			_batch_tracker_destroy(tracker);
		}
		else {
			record_batch_tracker_t* tracker =
				(record_batch_tracker_t*) priority_queue_pop(&uploader->retry_queue);
			as_store_bool(&tracker->status.has_error, true);

			if (uploader->upload_cb != NULL) {
				uploader->upload_cb(&tracker->status, uploader->udata);
			}

			_record_batch_tracker_destroy(tracker);
		}
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
	struct timespec timeout;

	pthread_mutex_lock(&uploader->async_lock);
	while (as_load_uint64(&uploader->async_calls) != 0) {
		if (batch_uploader_has_error(uploader) &&
				priority_queue_size(&uploader->retry_queue) > 0) {
			_queue_clear(uploader);
			continue;
		}

		if (priority_queue_size(&uploader->retry_queue) > 0) {
			timeout = _queue_lowest_timeout(uploader);
		}
		else {
			// wait for at most one second if no transactions are queued.
			get_current_time(&timeout);
			timeout.tv_sec += 1lu;
		}

		int res = pthread_cond_timedwait(&uploader->async_cond,
				&uploader->async_lock, &timeout);
		if (res != 0 && res != ETIMEDOUT) {
			err_code("Error while waiting for condition");
			exit(EXIT_FAILURE);
		}

		// Try submitting a timed out transaction if one exists.
		_queue_submit_if_timeout(uploader);
	}
	pthread_mutex_unlock(&uploader->async_lock);
}

static void
_reserve_async_slot(batch_uploader_t* uploader)
{
	struct timespec timeout;
	uint64_t max_async = (uint64_t) uploader->max_async;

	pthread_mutex_lock(&uploader->async_lock);
	if (as_load_uint64(&uploader->async_calls) == max_async) {

		for (;;) {
			if (priority_queue_size(&uploader->retry_queue) > 0) {
				timeout = _queue_lowest_timeout(uploader);
			}
			else {
				// wait for at most one second if no transactions are queued.
				get_current_time(&timeout);
				timeout.tv_sec += 1lu;
			}

			int res = pthread_cond_timedwait(&uploader->async_cond,
					&uploader->async_lock, &timeout);
			if (res != 0 && res != ETIMEDOUT) {
				err_code("Error while waiting for condition");
				exit(EXIT_FAILURE);
			}

			if (as_load_uint64(&uploader->async_calls) != max_async) {
				break;
			}

			// Try submitting a timed out transaction if one exists.
			_queue_submit_if_timeout(uploader);
		}
	}

	// Try submitting a timed out transaction if one exists.
	_queue_submit_if_timeout(uploader);

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
	int64_t delay;
	batch_tracker_t* tracker = (batch_tracker_t*) udata;
	batch_uploader_t* uploader = tracker->uploader;
	as_vector* records = &tracker->records;

	// this shouldn't have changed, but just to be safe.
	tracker->batch = batch;

	batch_status_t status;
	batch_status_init(&status);

	switch(_categorize_write_result(ae, uploader->conf)) {
		case WRITE_RESULT_PERMFAIL:
			err("Error in aerospike_batch_write_async call - "
					"code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			batch_uploader_signal_error(uploader);
			status.has_error = true;
			break;

		case WRITE_RESULT_RETRY:
			as_incr_uint64(&uploader->retry_count);
			if (batch_uploader_has_error(uploader)) {
				break;
			}

			delay = retry_status_next_delay(&tracker->retry_status,
					&uploader->retry_strategy);
			if (delay > 0) {
				if (_queue_batch_transaction(uploader, tracker,
							(uint64_t) delay)) {
					// Don't mark the outstanding transaction as complete.
					return;
				}
				// If queueing the transaction failed, fall through to free the
				// tracker.
			}
			else if (delay == 0) {
				if (_do_batch_write(uploader, tracker)) {
					// Don't mark the outstanding transaction as complete.
					return;
				}
				// If queueing the transaction failed, fall through to free the
				// tracker.
			}
			else { // delay == -1
				err("Max batch-write retries exceeded (%" PRIu32 ")",
						tracker->retry_status.attempts);
			}

			batch_uploader_signal_error(uploader);
			status.has_error = true;
			break;

		case WRITE_RESULT_OK:
			// go through records and accumulate record statuses into the status
			// struct.
			for (uint32_t i = 0; i < records->size; i++) {
				as_batch_write_record* batch_write =
					(as_batch_write_record*) as_vector_get(&batch->list, i);
				if (!_batch_status_submit(&status, batch_write->result,
							uploader->conf)) {
					batch_uploader_signal_error(uploader);
					status.has_error = true;
				}
			}
			break;
	}

	if (uploader->upload_cb != NULL) {
		uploader->upload_cb(&status, uploader->udata);
	}

	_batch_tracker_destroy(tracker);
	_release_async_slot(uploader);
}

static bool
_do_batch_write(batch_uploader_t* uploader, batch_tracker_t* tracker)
{
	as_status status;
	as_error ae;

	status = aerospike_batch_write_async(uploader->as, &ae,
			&uploader->batch_policy, tracker->batch, _batch_submit_callback,
			tracker, NULL);

	if (status != AEROSPIKE_OK) {
		err("Error while initiating aerospike_batch_write_async call - "
				"code %d: %s at %s:%d",
				ae.code, ae.message, ae.file, ae.line);
		batch_uploader_signal_error(uploader);
		return false;
	}

	return true;
}

static bool
_submit_batch(batch_uploader_t* uploader, as_vector* records)
{
	uint32_t n_records = records->size;

	if (n_records == 0) {
		return true;
	}

	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (batch_uploader_has_error(uploader)) {
		_release_async_slot(uploader);
		return false;
	}

	as_batch_records* batch = as_batch_records_create(n_records);

	as_operations* ops = cf_malloc(n_records * sizeof(as_operations));

	for (uint32_t i = 0; i < n_records; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);

		as_batch_write_record* batch_write = as_batch_write_reserve(batch);
		batch_write->policy = _get_batch_write_policy(uploader,
				rec->key.valuep != NULL);

		if (!as_key_move(&batch_write->key, &rec->key)) {
			_free_batch_records(batch, ops);
			_release_async_slot(uploader);
			return false;
		}

		// write the record as a series of bin-ops on the key
		as_operations* op = &ops[i];
		as_operations_init(op, rec->bins.size);
		op->ttl = rec->ttl;
		op->gen = rec->gen;
		for (uint32_t bin_idx = 0; bin_idx < rec->bins.size; bin_idx++) {
			as_operations_add_write(op, rec->bins.entries[bin_idx].name,
					rec->bins.entries[bin_idx].valuep);
			as_val_reserve(rec->bins.entries[bin_idx].valuep);
		}

		batch_write->ops = op;
	}

	batch_tracker_t* tracker =
		_batch_tracker_alloc(uploader, batch, ops, records);

	if (!_do_batch_write(uploader, tracker)) {
		// put records back and destroy the one made in this method.
		as_vector_swap(&tracker->records, records);
		_batch_tracker_destroy(tracker);
		_release_async_slot(uploader);

		return false;
	}

	return true;
}

static void
_key_put_submit_callback(as_error* ae, void* udata, as_event_loop* event_loop)
{
	(void) event_loop;
	key_put_info_t* key_info = (key_put_info_t*) udata;
	record_batch_tracker_t* tracker = key_info->tracker;
	batch_uploader_t* uploader = tracker->uploader;

	switch (_categorize_write_result(ae, uploader->conf)) {
		case WRITE_RESULT_PERMFAIL:
			err("Error in aerospike_key_put_async call - "
					"code %d: %s at %s:%d",
					ae->code, ae->message, ae->file, ae->line);
			batch_uploader_signal_error(uploader);
			as_store_bool(&tracker->status.has_error, true);
			break;

		case WRITE_RESULT_RETRY:
			as_incr_uint64(&uploader->retry_count);
			as_store_bool(&tracker->should_retry, true);
			break;

		case WRITE_RESULT_OK:
			if (!_batch_status_submit(&tracker->status,
						ae == NULL ? AEROSPIKE_OK : ae->code,
						uploader->conf)) {
				batch_uploader_signal_error(uploader);
				as_store_bool(&tracker->status.has_error, true);
			}
			else {
				// now that the transaction has completely succeeded, we can
				// disable retries on it.
				as_store_bool(&key_info->should_retry, false);
			}
			break;
	}

	if (as_aaf_uint64(&tracker->outstanding_calls, -1lu) == 0) {
		if (!as_load_bool(&tracker->status.has_error) &&
				as_load_bool(&tracker->should_retry) &&
				!batch_uploader_has_error(uploader)) {

			_record_batch_tracker_reset(tracker);

			int64_t delay = retry_status_next_delay(&tracker->retry_status,
					&uploader->retry_strategy);
			if (delay > 0) {
				if (_queue_key_rec_transactions(uploader, tracker,
							(uint64_t) delay)) {
					// Don't mark the outstanding transaction as complete.
					return;
				}
				// If queueing the transaction failed, fall through to free the
				// tracker.
			}
			else if (delay == 0) {
				_do_key_recs_write(uploader, tracker);
				// Don't mark the outstanding transaction as complete.
				return;
			}
			else { // delay == -1
				err("Max key-put retries exceeded (%" PRIu32 ")",
						tracker->retry_status.attempts);
			}

			batch_uploader_signal_error(uploader);
			as_store_bool(&tracker->status.has_error, true);
		}

		// since this is the last record, we can make the upload_batch callback.
		if (uploader->upload_cb != NULL) {
			uploader->upload_cb(&tracker->status, uploader->udata);
		}

		_record_batch_tracker_destroy(tracker);
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

	as_vector* records = &tracker->records;
	uint32_t n_records = records->size;

	for (uint32_t i = 0; i < n_records; i++) {
		as_record* rec = (as_record*) as_vector_get(records, i);
		as_key* key = &rec->key;

		key_put_info_t* key_info = &tracker->key_infos[i];

		if (as_load_bool(&key_info->should_retry)) {
			const as_policy_write* policy = _get_key_put_policy(uploader,
					key->valuep != NULL);

			status = aerospike_key_put_async(uploader->as, &ae, policy, key,
					rec, _key_put_submit_callback, key_info, NULL, NULL);

			if (status != AEROSPIKE_OK) {
				err("Error while initiating aerospike_key_put_async call - "
						"code %d: %s at %s:%d",
						ae.code, ae.message, ae.file, ae.line);
				batch_uploader_signal_error(uploader);
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

					_record_batch_tracker_destroy(tracker);
					_release_async_slot(uploader);
				}

				return;
			}
		}
		else {
			if (as_aaf_uint64(&tracker->outstanding_calls, -1lu) == 0) {
				// if this is the last record, we can make the upload_batch
				// callback.
				if (uploader->upload_cb != NULL) {
					uploader->upload_cb(&tracker->status, uploader->udata);
				}

				_record_batch_tracker_destroy(tracker);
				_release_async_slot(uploader);
			}
		}
	}
}

static bool
_submit_key_recs(batch_uploader_t* uploader, as_vector* records)
{
	_reserve_async_slot(uploader);

	// If we see the error flag set, abort this transaction and fail.
	if (batch_uploader_has_error(uploader)) {
		_release_async_slot(uploader);
		return false;
	}

	record_batch_tracker_t* tracker =
		_record_batch_tracker_alloc(uploader, records);

	_do_key_recs_write(uploader, tracker);

	return true;
}

