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

#include <io_proxy.h>
#include <shared.h>

// Number of samples to take for the record size estimate.
#define NUM_SAMPLES 10000

// By default, start a new backup file when the current backup file crosses this
// size in MiB.
#define DEFAULT_FILE_LIMIT 250

// By default, do this many parallel scans simultaneously
#define DEFAULT_PARALLEL 1

// The max number of parallel scan calls made at any one time
#define MAX_PARALLEL 100

// The maximal number of UDF files that we can backup.
#define MAX_UDF_FILES 1000

/*
 * The interface exposed by the backup file format encoder.
 */
typedef struct backup_encoder {
	/*
	 * Writes a record to the backup file.
	 * @param fd       The file descriptor of the backup file.
	 * @param compact  If true, don't use base-64 encoding on BLOB bin values.
	 * @param rec      The record to be written.
	 *
	 * @result         `true`, if successful.
	 */
	bool (*put_record)(io_write_proxy_t *fd, bool compact, const as_record *rec);

	/*
	 * Writes a UDF file to the backup file.
	 *
	 * @param fd     The file descriptor of the backup file.
	 * @param file   The UDF file to be written.
	 *
	 * @result       `true`, if successful.
	 */
	bool (*put_udf_file)(io_write_proxy_t *fd, const as_udf_file *file);

	/*
	 * Writes the specification of a secondary index to the backup file.
	 *
	 * @param fd     The file descriptor of the backup file.
	 * @param index  The index specification to be written.
	 *
	 * @result       `true`, if successful.
	 */
	bool (*put_secondary_index)(io_write_proxy_t *fd, const index_param *index);
} backup_encoder_t;

/*
 * The global backup configuration and stats shared by all backup threads and the counter thread.
 */
typedef struct backup_config {

	char *host;
	int32_t port;
	bool use_services_alternate;
	char *user;
	char *password;

	as_vector set_list;
	char* bin_list;
	char* node_list;
	int64_t mod_after;
	int64_t mod_before;
	bool  ttl_zero;

	as_config_tls tls;
	char* tls_name;

	// The Aerospike client to be used for the node scans.
	aerospike *as;
	// The scan policy to be used for the node scans.
	as_policy_scan *policy;
	// The scan configuration to be used for the node scans.
	as_scan *scan;
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
	// Excludes records from the backup.
	bool no_records;
	// Excludes secondary indexes from the backup.
	bool no_indexes;
	// Excludes UDF files from the backup.
	bool no_udfs;
	// Start a new backup file when the current backup file crosses this size.
	uint64_t file_limit;
	// The file format encoder to be used for writing data to a backup file.
	backup_encoder_t *encoder;
	// The number of objects to be backed up. This can change during the backup,
	// so it's just treated as an estimate.
	uint64_t rec_count_estimate;
	// The total number of records backed up so far.
	cf_atomic64 rec_count_total;
	// The total number of bytes written to the backup file(s) so far.
	cf_atomic64 byte_count_total;
	// When backing up to a directory, counts the number of backup files
	// created
	uint64_t file_count;

	// The total number of records backed up in files that have already been
	// written and closed.
	cf_atomic64 rec_count_total_committed;
	// The total number of bytes backed up in files that have already been
	// written and closed.
	cf_atomic64 byte_count_total_committed;
	// The current limit for byte_count_total for throttling. This is
	// periodically increased by the counter thread to raise the limit according
	// to the bandwidth limit.
	volatile uint64_t byte_count_limit;
	// The number of secondary indexes backed up.
	volatile uint32_t index_count;
	// The number of UDF files backed up.
	volatile uint32_t udf_count;
	// Authentication mode
	char *auth_mode;

	// String containing partition range
	char *partition_list;
	// String containing digest filter.
	char *after_digest;

	// custom b64-encoded filter expression to use in the scan calls
	char *filter_exp;

	// List of partition range filters (partition_range)
	as_vector partition_ranges;
	// List of digest filters (as_digest)
	as_vector digests;
} backup_config_t;

/*
 * The per partition filter information pushed to the job queue and picked up
 * by the backup threads.
 */
typedef struct backup_thread_args {
	// The global backup configuration and stats.
	backup_config_t *conf;
	// Partition ranges/digest to be backed up. 
	as_partition_filter filter;

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
	// The global backup configuration and stats. Copied from
	// backup_thread_args.conf.
	backup_config_t *conf;

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
	uint64_t rec_count_file;
	uint64_t byte_count_file;
} queued_backup_fd_t;


extern int32_t backup_main(int32_t argc, char **argv);
extern void backup_config_default(backup_config_t*);
extern void backup_config_destroy(backup_config_t*);

