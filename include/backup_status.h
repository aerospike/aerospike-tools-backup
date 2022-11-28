/*
 * Aerospike Backup Status
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

#include <stdatomic.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_node.h>
#include <aerospike/as_partition_filter.h>
#include <aerospike/as_scan.h>

#pragma GCC diagnostic pop

#include <backup_config.h>
#include <enc_text.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#define MAX_PARTITIONS 4096

// If backup_state is set to this, the backup has been aborted and should not
// be saved.
#define BACKUP_STATE_ABORTED ((backup_state_t*) -0x1LU)

/*
 * The backup_status_t struct is used to manage the status of a full backup job.
 */
typedef struct backup_status {
	node_spec* node_specs;
	uint32_t n_node_specs;

	// The Aerospike client to be used for the node scans.
	aerospike *as;
	// The scan policy to be used for the node scans.
	as_policy_scan *policy;
	// The set to be backed up, if backing up a single set, otherwise "".
	as_set set;
	// If doing multi-set backup, the expression to use to select for the
	// desired sets.
	exp_component_t set_list_expr;

	// The file format encoder to be used for writing data to a backup file.
	backup_encoder_t encoder;
	// The number of objects to be backed up. This can change during the backup,
	// so it's just treated as an estimate.
	uint64_t rec_count_estimate;
	// The total number of records backed up so far.
	_Atomic(uint64_t) rec_count_total;
	// The total number of bytes written to the backup file(s) so far.
	_Atomic(uint64_t) byte_count_total;
	// When backing up to a directory, counts the number of backup files
	// created
	_Atomic(uint64_t) file_count;

	// The total number of records backed up in files that have already been
	// written and closed.
	_Atomic(uint64_t) rec_count_total_committed;
	// The total number of bytes backed up in files that have already been
	// written and closed.
	_Atomic(uint64_t) byte_count_total_committed;
	// The current limit for byte_count_total for throttling. This is
	// periodically increased by the counter thread to raise the limit according
	// to the bandwidth limit.
	_Atomic(uint64_t) byte_count_limit;
	// The number of secondary indexes backed up.
	volatile uint32_t index_count;
	// The number of UDF files backed up.
	volatile uint32_t udf_count;

	// List of partition filters (as_partition_filter)
	as_vector partition_filters;

	// Set when the backup has started running. Before this point, any attempts
	// to interrupt the backup will just abort the backup.
	_Atomic(bool) started;

	// Set when the backup has finished running.
	_Atomic(bool) finished;

	// Set when the backup has encountered an error and should stop, causes all
	// threads to immediately exit and backup state saving to begin.
	_Atomic(bool) stop;

	// Used when sleeping to ensure immediate awakening when the backup job
	// finishes.
	pthread_mutex_t stop_lock;
	pthread_cond_t stop_cond;

	// The backup state struct to save the backup state to. Initialized if this
	// backup job fails.
	_Atomic(backup_state_t*) backup_state;

	// Indicates that the one-time work (secondary indexes and UDF files) is complete.
	// This variable shares the stop lock/condvar so that stop() calls will interrupt
	// threads waiting on the one shot condition.
	_Atomic(bool) one_shot_done;

	// Used by threads when initializing a file. This ensures that no file names
	// will be skipped, and that file_count always equals the total number of
	// successfully opened files.
	pthread_mutex_t dir_file_init_mutex;
	// Used by threads when writing to one file to ensure mutual exclusion on access
	// to the file
	pthread_mutex_t file_write_mutex;
	// Used by the counter thread to signal newly available bandwidth to the backup
	// threads.
	pthread_mutex_t bandwidth_mutex;
	pthread_cond_t bandwidth_cond;

	// Used when reading/updating rec_count_total_committed/byte_count_total_committed
	// in the global backup_config_t, since these values must always be read/updated
	// together
	pthread_mutex_t committed_count_mutex;

	// Used when running an estimate, is a list of the record sizes collected
	// over the course of the estimate.
	uint64_t header_size;
	uint64_t* estimate_samples;
	// Cumulative total number of samples collected.
	uint32_t n_estimate_samples;
} backup_status_t;


//==========================================================
// Public API.
//

bool backup_status_init(backup_status_t*, backup_config_t*);

void backup_status_destroy(backup_status_t*);

void backup_status_set_n_threads(backup_status_t*,
		const backup_config_t* conf, uint32_t n_tasks, uint32_t n_threads);

/*
 * Returns true if the backup has started running and is interruptable.
 */
bool backup_status_has_started(backup_status_t* status);

/*
 * Indicates the start of the backup. From this point onward, the backup is
 * interruptable.
 */
void backup_status_start(backup_status_t* status);

/*
 * Called when the one-time work (secondary indexes and UDF files) is complete
 * to release all other threads waiting.
 */
bool backup_status_one_shot_done(const backup_status_t* status);

/*
 * Waits until the one-time work (secondary indexes and UDF files) is complete.
 */
void backup_status_wait_one_shot(backup_status_t* status);

/*
 * Signals that the one-time work (secondary indexes and UDF files) is complete.
 */
void backup_status_signal_one_shot(backup_status_t* status);

/*
 * Returns true if the backup job has stoppped.
 */
bool backup_status_has_stopped(const backup_status_t* status);

/*
 * Stops the backup job. This does not grab any locks, so it is safe to call in
 * interrupt contexts.
 */
void backup_status_stop(const backup_config_t* conf, backup_status_t* status);

/*
 * Returns true if the backup job has finished.
 */
bool backup_status_has_finished(const backup_status_t* status);

/*
 * Ends the backup job successfully, to be called once all worker threads have
 * finished to halt all other threads.
 */
void backup_status_finish(backup_status_t* status);

/*
 * Aborts the backup without saving the backup state to a file. This should only
 * be called if the backup state file would have been corrupted/an error
 * occurred that caused the backup state to be unrecoverable.
 */
void backup_status_abort_backup(backup_status_t* status);

/*
 * Sets the backup state to BACKUP_STATE_ABORTED without checking what it was
 * before. Only to be used outside multi-threaded contexts.
 */
void backup_status_abort_backup_unsafe(backup_status_t* status);

/*
 * Sleep on the stop condition, exiting from the sleep early if the program is
 * stopped
 */
void backup_status_sleep_for(backup_status_t* status, uint64_t n_secs);

/*
 * Initializes the backup state file to save the current scan status of all
 * running backup jobs to be continued in another run.
 *
 * This method should be called while holding the stop_lock, but it is thread
 * safe so it isn't necessary to be holding the stop_lock.
 */
bool backup_status_init_backup_state_file(const char* backup_state_path,
		backup_status_t* status);

/*
 * Returns a pointer to the backup state struct.
 */
backup_state_t* backup_status_get_backup_state(backup_status_t* status);

/*
 * Saves the scan state of the given scan object to the backup state file.
 */
void backup_status_save_scan_state(backup_status_t* status,
		const as_partitions_status* parts);

#ifdef __cplusplus
}
#endif

