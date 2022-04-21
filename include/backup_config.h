/*
 * Aerospike Backup Configuration
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

//==========================================================
// Includes.
//

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_scan.h>
#include <aerospike/as_tls.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"

#include <io_proxy.h>


//==========================================================
// Typedefs & constants.
//

#define BACKUP_CONFIG_INIT_FAILURE -1

// to be returned by backup_config_init when the program should immediately exit
// with success error code
#define BACKUP_CONFIG_INIT_EXIT -2

// By default, start a new backup file when the current backup file crosses this
// size in MiB.
#define DEFAULT_FILE_LIMIT 250

// Default number of samples to take for the record size estimate.
#define DEFAULT_ESTIMATE_SAMPLES 10000

// By default, do this many parallel scans simultaneously
#define DEFAULT_PARALLEL 1
#define DEFAULT_NODE_BACKUP_PARALLEL 16

// The max number of parallel scan calls made at any one time
#define MAX_PARALLEL 100

/*
 * The global backup configuration and stats shared by all backup threads and the counter thread.
 */
typedef struct backup_config {

	char *host;
	int32_t port;
	bool use_services_alternate;
	char *user;
	char *password;

	// The region to use for S3.
	char* s3_region;
	// The profile to use for AWS credentials.
	char* s3_profile;
	// An alternative endpoint for S3 compatible storage to send all S3 requests to.
	char* s3_endpoint_override;
	// A user override of the minimum part size to use for S3 Multipart Uplaod parts.
	uint64_t s3_min_part_size;
	// Max simultaneous download requests from S3 allowed at a time.
	uint32_t s3_max_async_downloads;
	// Max simultaneous upload requests from S3 allowed at a time.
	uint32_t s3_max_async_uploads;

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
	// When true, perform the functionality of --remove-files without performing
	// a backup.
	bool remove_artifacts;
	// The number of samples to take when running an estimate.
	uint32_t n_estimate_samples;
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
	// The compression level to use (or -1 if unspecified)
	int32_t compression_level;
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


//==========================================================
// Public API.
//

/*
 * Parses command line arguments from argv and populates/initializes the
 * backup_config_t struct.
 *
 * The backup_config_t struct returned by this method is always destroyable (and
 * should be destroyed) regardless of the return value
 */
int backup_config_init(int argc, char* argv[], backup_config_t* conf);

void backup_config_default(backup_config_t* conf);

void backup_config_destroy(backup_config_t* conf);

/*
 * Allocates another backup config and clones all fields from conf into it.
 */
backup_config_t* backup_config_clone(backup_config_t* conf);

/*
 * Prints the inf message
 * "Starting backup of <ns> (namespace: <ns>, set: [<set>], bins: <bins>, "
 * "after: <mod-after>, before: <mod-before>, no ttl only: <T/F>, limit <bandwidth>) "
 * "to <backup directory/file>"
 */
bool backup_config_log_start(const backup_config_t* conf);

/*
 * Returns true if the backup config is interruptable/resumable.
 */
bool backup_config_can_resume(const backup_config_t* conf);

