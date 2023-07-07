/*
 * Aerospike Restore Status
 *
 * Copyright (c) 2022 Aerospike, Inc. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================
// Includes.
//

#include <batch_uploader.h>
#include <restore_config.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

/*
 * The restore_status_t struct is used to manage the status of a full restore job.
 */
typedef struct restore_status {
	// The Aerospike client.
	// NOTE this is NULL if validate is true
	aerospike* as;
	// Server version info struct.
	server_version_t version_info;

	// The file format decoder to be used for reading data from a backup file.
	backup_decoder_t decoder;

	// The shared batch uploader that manages all async batch upload calls.
	batch_uploader_t batch_uploader;

	// Set to true when batch writes can and should be used.
	bool batch_writes_enabled;
	// The true batch size to use in the run, which will be set to the default
	// if conf->batch_size is UNDEFINED.
	uint32_t batch_size;

	// true when asrestore is used with --validate
	// in this case no records are written, aerospike client (as) is NULL
	// and batch_uploader is not initialised
	bool validate;

	// The list of backup files to restore.
	as_vector file_vec;
	// The (optional) source and (also optional) target namespace to be
	// restored, as a vector of strings.
	as_vector ns_vec;
	// The bins to be restored, as a vector of bin name strings.
	as_vector bin_vec;
	// The sets to be restored, as a vector of set name strings.
	as_vector set_vec;
	// The indexes to be inserted, as a vector of index_param's
	as_vector index_vec;
	// The udfs to be inserted, as a vector of udf_param's
	as_vector udf_vec;

	// Mutex for exclusive access to index_vec/udf_vec
	pthread_mutex_t idx_udf_lock;

	// The total size of all backup files to be restored.
	off_t estimated_bytes;
	// The total number of bytes read from the backup file(s) so far.
	_Atomic(uint64_t) total_bytes;
	// The total number of records read from the backup file(s) so far.
	_Atomic(uint64_t) total_records;
	// The number of records dropped because they were expired.
	_Atomic(uint64_t) expired_records;
	// The number of records dropped because they didn't contain any of the
	// selected bins or didn't belong to any of the the selected sets.
	_Atomic(uint64_t) skipped_records;
	// The number of records ignored because of record level permanent error while
	// restoring. e.g RECORD_TOO_BIG Enabled or disabled using
	// --ignore-record-error flag.
	_Atomic(uint64_t) ignored_records;
	// The number of successfully restored records.
	_Atomic(uint64_t) inserted_records;
	// The number of records dropped because they already existed in the
	// database.
	_Atomic(uint64_t) existed_records;
	// The number of records dropped because the database already contained the
	// records with a higher generation count.
	_Atomic(uint64_t) fresher_records;
	// The current limit for total_bytes for throttling. This is periodically
	// increased by the counter thread to raise the limit according to the
	// bandwidth limit.
	volatile uint64_t bytes_limit;
	// The current limit for total_records for throttling.
	// This is periodically increased by the counter thread to raise the limit
	// according to the TPS limit.
	volatile uint64_t records_limit;
	// The number of successfully created secondary indexes.
	_Atomic(uint32_t) index_count;
	// counts of the number of inserted/skipped/matched/mismatched secondary indexes
	_Atomic(uint32_t) skipped_indexes;
	_Atomic(uint32_t) matched_indexes;
	_Atomic(uint32_t) mismatched_indexes;
	// The number of successfully stored UDF files.
	_Atomic(uint32_t) udf_count;

	// Set when the restore has finished running
	_Atomic(bool) finished;

	// Set when the restore has encountered an error and should stop.
	_Atomic(bool) stop;

	// Used when sleeping to ensure immediate awakening when the restore job
	// finishes.
	pthread_mutex_t stop_lock;
	pthread_cond_t stop_cond;

	// Used by threads when reading from one file to ensure mutual exclusion on access
	// to the file
	pthread_mutex_t file_read_mutex;

	// Used by the counter thread to signal newly available bandwidth or
	// transactions to the restore threads.
	pthread_mutex_t limit_mutex;
	pthread_cond_t limit_cond;
} restore_status_t;


//==========================================================
// Public API.
//

bool restore_status_init(restore_status_t*, const restore_config_t*);

void restore_status_destroy(restore_status_t*);

/*
 * Returns true if the program has finished.
 */
bool restore_status_has_finished(const restore_status_t*);

/*
 * Signals that the program has finished.
 */
void restore_status_finish(restore_status_t*);

/*
 * Returns true if the program has stoppped.
 */
bool restore_status_has_stopped(const restore_status_t*);

/*
 * Stops the program immediately.
 */
void restore_status_stop(restore_status_t*);

/*
 * Sleep on the stop condition, exiting from the sleep early when the program
 * finishes (or if it's stopped by an error and sleep_through_stop is false).
 */
void restore_status_sleep_for(restore_status_t* status, uint64_t n_secs,
		bool sleep_through_stop);

#ifdef __cplusplus
}
#endif

