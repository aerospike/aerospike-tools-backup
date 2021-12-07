/*
 * Aerospike Backup
 *
 * Copyright (c) 2008-2021 Aerospike, Inc. All rights reserved.
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

#include <dirent.h>
#include <getopt.h>
#include <libgen.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/cf_atomic.h>
#include <citrusleaf/cf_b64.h>
#include <citrusleaf/cf_queue.h>
#include <aerospike/aerospike_info.h>
#include <aerospike/as_partition_filter.h>
#include <aerospike/as_scan.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"

#include <io_proxy.h>
#include <encode.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#define MAX_PARTITIONS 4096

// Number of samples to take for the record size estimate.
#define NUM_SAMPLES 10000

// By default, start a new backup file when the current backup file crosses this
// size in MiB.
#define DEFAULT_FILE_LIMIT 250

// By default, do this many parallel scans simultaneously
#define DEFAULT_PARALLEL 1
#define DEFAULT_NODE_BACKUP_PARALLEL 16

// The max number of parallel scan calls made at any one time
#define MAX_PARALLEL 100

// The maximal number of UDF files that we can backup.
#define MAX_UDF_FILES 1000

/*
 * The global backup configuration and stats shared by all backup threads and the counter thread.
 */
typedef struct backup_config {

	char *host;
	int32_t port;
	bool use_services_alternate;
	char *user;
	char *password;

	as_namespace ns;
	bool no_bins;

	// If resuming a backup, the state file being resumed from.
	char* state_file;
	// The path to the directory/file in which to place the backup state if one
	// needs to be made.
	char* state_file_dst;

	as_vector set_list;
	char* bin_list;
	char* node_list;
	int64_t mod_after;
	int64_t mod_before;
	bool  ttl_zero;

	// C client socket timeout/retry policies.
	uint32_t socket_timeout;
	uint32_t total_timeout;
	uint32_t max_retries;
	uint32_t retry_delay;

	char* tls_name;
	as_config_tls tls;

	// When true, delete any files in the directory being backed up if in
	// directory mode, or delete the file being backed up to if it already
	// exists
	bool remove_files;
	// The backup directory. `NULL`, when backing up to a single file.
	char *directory;
	// The backup file. `NULL`, when backing up to a directory.
	char *output_file;
	// Prefix to the name of the files when using directory
	char *prefix;
	// Disables base-64 encoding for BLOB bin values.
	bool compact;
	// The max number of parallel scan calls to be made at once
	int32_t parallel;
	// The compression mode to be used (default is none)
	compression_opt compress_mode;
	// The encryption mode to be used (default is none)
	encryption_opt encrypt_mode;
	// The encryption key given by the user
	encryption_key_t* pkey;
	// The path for the machine-readable output.
	char *machine;
	// Requests an estimate of the average record size instead of a real backup.
	bool estimate;
	// The B/s cap for throttling.
	uint64_t bandwidth;
	// The number of records to back up.
	uint64_t max_records;
	// Records-per-second bandwidth limiting.
	uint32_t records_per_second;
	// Excludes records from the backup.
	bool no_records;
	// Excludes secondary indexes from the backup.
	bool no_indexes;
	// Excludes UDF files from the backup.
	bool no_udfs;
	// Start a new backup file when the current backup file crosses this size.
	uint64_t file_limit;
	// Authentication mode
	char *auth_mode;

	// String containing partition range
	char *partition_list;
	// String containing digest filter.
	char *after_digest;

	// custom b64-encoded filter expression to use in the scan calls
	char *filter_exp;
} backup_config_t;

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
	uint64_t rec_count_total;
	// The total number of bytes written to the backup file(s) so far.
	uint64_t byte_count_total;
	// When backing up to a directory, counts the number of backup files
	// created
	uint64_t file_count;

	// The total number of records backed up in files that have already been
	// written and closed.
	uint64_t rec_count_total_committed;
	// The total number of bytes backed up in files that have already been
	// written and closed.
	uint64_t byte_count_total_committed;
	// The current limit for byte_count_total for throttling. This is
	// periodically increased by the counter thread to raise the limit according
	// to the bandwidth limit.
	uint64_t byte_count_limit;
	// The number of secondary indexes backed up.
	volatile uint32_t index_count;
	// The number of UDF files backed up.
	volatile uint32_t udf_count;

	// List of partition filters (as_partition_filter)
	as_vector partition_filters;
} backup_status_t;

/*
 * The per partition filter information pushed to the job queue and picked up
 * by the backup threads.
 */
typedef struct backup_thread_args {
	// The global backup configuration.
	const backup_config_t *conf;
	// The global backup stats.
	backup_status_t *status;
	// Partition ranges/digest to be backed up. 
	as_partition_filter filter;

	// A queue of all completed backup jobs
	cf_queue* complete_queue;

	union {
		// When backing up to a single file, the file descriptor of that file.
		io_write_proxy_t* shared_fd;

		// When backing up to a directory, the queue of backup files which have
		// not been completely filled yet
		cf_queue* file_queue;
	};
	// This is the first job in the job queue. It'll take care of backing up
	// secondary indexes and UDF files.
	bool first;
	// When estimating the average records size, the array that receives the
	// record size samples.
	uint64_t *samples;
	// The number of record size samples that fit into the samples array.
	uint32_t *n_samples;
} backup_thread_args_t;

/*
 * The context for information about the currently processed partition. Each backup
 * thread creates one of these for each scan call that it makes.
 */
typedef struct backup_job_context {
	// Task description. 
	char desc[128];
	// The global backup configuration.
	const backup_config_t *conf;
	// The global backup stats. Copied from backup_thread_args.status.
	backup_status_t *status;
	// The scan configuration to be used.
	as_scan scan;
	// Set if the backup job terminated a scan early for any reason.
	bool interrupted;

	union {
		// When backing up to a single file, the file descriptor of that file.
		// Copied from backup_thread_args.shared_fd.
		io_write_proxy_t* shared_fd;

		// When backing up to a directory, the queue of backup files which have
		// not been completely filled yet
		cf_queue* file_queue;
	};

	// The file descriptor of the current backup file for the current job.
	io_write_proxy_t* fd;
	// The name of the file opened in fd.
	char* file_name;

	// When backing up to a directory, counts the number of records in the
	// current backup file for the current job.
	uint64_t rec_count_file;
	// When backing up to a directory, tracks the size of the current backup
	// file for the currently processed partition filter.
	uint64_t byte_count_file;
	// Counts the number of records read from the currently processed partition
	// filter.
	uint64_t rec_count_job;
	// Counts the number of bytes written to all backup files for the current
	// job.
	uint64_t byte_count_job;
	// When estimating the average record size, the array that receives the
	// record size samples. Copied from backup_thread_args.samples.
	uint64_t *samples;
	// The number of record size samples that fit into the samples array. Copied
	// from backup_thread_args.n_samples.
	uint32_t *n_samples;
} backup_job_context_t;


/*
 * The struct used to maintain state information about a backup file which was
 * not completely filled from a backup task
 */
typedef struct queued_backup_fd {
	io_write_proxy_t* fd;
	char* file_name;
	uint64_t rec_count_file;
	uint64_t byte_count_file;
} queued_backup_fd_t;


//==========================================================
// Public API.
//

extern int32_t backup_main(int32_t argc, char **argv);
extern void backup_config_default(backup_config_t*);
extern void backup_config_destroy(backup_config_t*);

extern bool backup_status_init(backup_status_t*, const backup_config_t*);
extern void backup_status_destroy(backup_status_t*);
extern void backup_status_set_n_threads(backup_status_t*,
		const backup_config_t* conf, uint32_t n_tasks, uint32_t n_threads);

