/*
 * Aerospike Backup
 *
 * Copyright (c) 2008-2015 Aerospike, Inc. All rights reserved.
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

#include <shared.h>

#define NUM_SAMPLES 10000                           ///< Number of samples to take for the record
                                                    ///  size estimate.

#define DEFAULT_FILE_LIMIT 250                      ///< By default, start a new backup file when
                                                    ///  the current backup file crosses this size
                                                    ///  in MiB.
#define DEFAULT_PARALLEL 10                         ///< By default, backup up to this many nodes in
                                                    ///  parallel.
#define MAX_PARALLEL 100                            ///< Allow up to this many nodes to be backed up
                                                    ///  in parallel.
#define MAX_UDF_FILES 1000                          ///< The maximal number of UDF files that we can
                                                    ///  backup.

///
/// The interface exposed by the backup file format encoder.
///
typedef struct {
	///
	/// Writes a record to the backup file.
	///
	/// @param bytes    The number of bytes written to the backup file.
	/// @param fd       The file descriptor of the backup file.
	/// @param compact  If true, don't use base-64 encoding on BLOB bin values.
	/// @param rec      The record to be written.
	///
	/// @result         `true`, if successful.
	///
	bool (*put_record)(uint64_t *bytes, FILE *fd, bool compact, const as_record *rec);

	///
	/// Writes a UDF file to the backup file.
	///
	/// @param bytes  The number of bytes written to the backup file.
	/// @param fd     The file descriptor of the backup file.
	/// @param file   The UDF file to be written.
	///
	/// @result       `true`, if successful.
	///
	bool (*put_udf_file)(uint64_t *bytes, FILE *fd, const as_udf_file *file);

	///
	/// Writes the specification of a secondary index to the backup file.
	///
	/// @param bytes  The number of bytes written to the backup file.
	/// @param fd     The file descriptor of the backup file.
	/// @param index  The index specification to be written.
	///
	/// @result       `true`, if successful.
	///
	bool (*put_secondary_index)(uint64_t *bytes, FILE *fd, const index_param *index);
} backup_encoder;

///
/// The global backup configuration and stats shared by all backup threads and the counter thread.
///
typedef struct {

	char *host;
	bool use_services_alternate;
	int32_t port;
	char *user;
	char *password;
	bool remove_files;
	char *bin_list;
	char *node_list;
	int64_t mod_after;
	int64_t mod_before;
    bool  ttl_zero;
	
	as_config_tls tls;

	aerospike *as;                      ///< The Aerospike client to be used for the node scans.
	as_policy_scan *policy;             ///< The scan policy to be used for the node scans.
	as_scan *scan;                      ///< The scan configuration to be used for the node scans.
	char *directory;                    ///< The backup directory. `NULL`, when backing up to a
	                                    ///  single file.
	char *output_file;                  ///< The backup file. `NULL`, when backing up to a
	                                    ///  directory.
	char *prefix;                       ///< Prefix to the name of the files when using directory
	bool compact;                       ///< Disables base-64 encoding for BLOB bin values.
	int32_t parallel;                   ///< The maximal number of cluster nodes scanned in
	                                    ///  parallel.
	char *machine;                      ///< The path for the machine-readable output.
	bool estimate;                      ///< Requests an estimate of the average record size instead
	                                    ///  of a real backup.
	uint64_t bandwidth;                 ///< The B/s cap for throttling.
	bool no_records;                    ///< Excludes records from the backup.
	bool no_indexes;                    ///< Excludes secondary indexes from the backup.
	bool no_udfs;                       ///< Excludes UDF files from the backup.
	uint64_t file_limit;                ///< Start a new backup file when the current backup file
	                                    ///  crosses this size.
	backup_encoder *encoder;            ///< The file format encoder to be used for writing data to
	                                    ///  a backup file.
	uint64_t rec_count_estimate;        ///< The number of objects to be backed up. This can change
	                                    ///  during the backup, so it's just treated as an estimate.
	uint64_t rec_num_max;				///< number of maximum records to export (limit).
	cf_atomic64 rec_count_total;        ///< The total number of records backed up so far.
	cf_atomic64 byte_count_total;       ///< The total number of bytes written to the backup file(s)
	                                    ///  so far.
	volatile uint64_t byte_count_limit; ///< The current limit for byte_count_total for throttling.
	                                    ///  This is periodically increased by the counter thread to
	                                    ///  raise the limit according to the bandwidth limit.
	volatile uint32_t index_count;      ///< The number of secondary indexes backed up.
	volatile uint32_t udf_count;        ///< The number of UDF files backed up.
	char *auth_mode;					///< Authentication mode
} backup_config;


///
/// The per-node information pushed to the job queue and picked up by the backup threads.
///
typedef struct {
	backup_config *conf;                ///< The global backup configuration and stats.
	char node_name[AS_NODE_NAME_SIZE];  ///< The node ID of the cluster node to be backed up.
	FILE *shared_fd;                    ///< When backing up to a single file, the file descriptor
	                                    ///  of that file.
	uint64_t bytes;                     ///< When backing up to a single file, the number of bytes
	                                    ///  that were written when open_file() created that file
	                                    ///  (version header, meta data).
	bool first;                         ///< This is the first job in the job queue. It'll take care
	                                    ///  of backing up secondary indexes and UDF files.
	uint64_t *samples;                  ///< When estimating the average records size, the array
	                                    ///  that receives the record size samples.
	uint32_t *n_samples;                ///< The number of record size samples that fit into the
	                                    ///  samples array.
} backup_thread_args;

///
/// The per-node context for information about the currently processed cluster node. Each backup
/// thread creates one of these for each node that it scans.
///
typedef struct {
	char node_name[AS_NODE_NAME_SIZE];  ///< The node ID of the currently processed cluster node.
	backup_config *conf;                ///< The global backup configuration and stats. Copied from
	                                    ///  backup_thread_args.conf.
	FILE *shared_fd;                    ///< When backing up to a single file, the file descriptor
	                                    ///  of that file. Copied from backup_thread_args.shared_fd.
	FILE *fd;                           ///< The file descriptor of the current backup file for the
	                                    ///  currently processed cluster node.
	void *fd_buf;                       ///< When backing up to a directory, the I/O buffer
	                                    ///  associated with the current backup file descriptor.
	uint32_t file_count;                ///< When backing up to a directory, counts the number of
	                                    ///  backup files created for the currently processed
	                                    ///  cluster node.
	uint64_t rec_count_file;            ///< When backing up to a directory, counts the number of
	                                    ///  records in the current backup file for the currently
	                                    ///  processed cluster node.
	uint64_t byte_count_file;           ///< When backing up to a directory, tracks the size of the
	                                    ///  current backup file for the currently processed cluster
	                                    ///  node.
	uint64_t rec_count_node;            ///< Counts the number of records read from the currently
	                                    ///  processed cluster node.
	uint64_t byte_count_node;           ///< Counts the number of bytes written to all backup files
	                                    ///  for the currently processed cluster node.
	uint64_t *samples;                  ///< When estimating the average record size, the array that
	                                    ///  receives the record size samples. Copied from
	                                    ///  backup_thread_args.samples.
	uint32_t *n_samples;                ///< The number of record size samples that fit into the
	                                    ///  samples array. Copied from
	                                    ///  backup_thread_args.n_samples.
} per_node_context;
