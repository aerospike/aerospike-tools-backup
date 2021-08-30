/*
 * Aerospike Restore
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

// The default number of restore threads.
#define DEFAULT_THREADS 20

// Maximal number of tries for each record put.
#define MAX_TRIES 10
// Initial backoff delay (in ms) between tries when overloaded; doubled after
// each try.
#define INITIAL_BACKOFF 10

// The interval for logging per-thread timing stats.
#define STAT_INTERVAL 10

/*
 * Encapsulates a UDF file.
 */
typedef struct {
	// The language of the UDF file.
	as_udf_type type;
	// The name of the UDF file.
	char *name;
	// The size of the UDF file.
	uint32_t size;
	// The content of the UDF file.
	void *data;
} udf_param;

/*
 * The result codes for the backup file format decoder.
 */
typedef enum {
	// A record was read and is returned.
	DECODER_RECORD,
	// Secondary index information was read and is returned.
	DECODER_INDEX,
	// A UDF file was read and is returned.
	DECODER_UDF,
	// The end of the backup file was encountered.
	DECODER_EOF,
		// An error occurred.
	DECODER_ERROR
} decoder_status;

/*
 * The interface exposed by the backup file format decoder.
 */
typedef struct backup_decoder {
	/*
	 * Reads, parses, and returns the next entity from a backup file descriptor.
	 *
	 * @param fd        The file descriptor.
	 * @param legacy    Indicates a version 3.0 backup file.
	 * @param ns_vec    The (optional) source and (also optional) target namespace to be restored.
	 * @param bin_vec   The bins to be restored, as a vector of strings.
	 * @param line_no   The current line number.
	 * @param rec       The returned record. Only valid, if the result is
	 *                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	 * @param extra_ttl Extra-ttl to be added to expirable records.
	 * @param expired   Indicates that an expired record was read. Only valid, if the result is
	 *                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	 * @param index     The returned secondary index information. Only valid, if the result is
	 *                  [DECODER_INDEX](@ref decoder_status::DECODER_INDEX).
	 * @param udf       The returned UDF file. Only valid, if the result is
	 *                  [DECODER_UDF](@ref decoder_status::DECODER_UDF).
	 *
	 * @result          See @ref decoder_status.
	 */
	decoder_status (*parse)(io_read_proxy_t *fd, bool legacy, as_vector *ns_vec,
			as_vector *bin_vec, uint32_t *line_no, as_record *rec,
			int32_t extra_ttl, bool *expired, index_param *index,
			udf_param *udf);
} backup_decoder_t;

/*
 * The global restore configuration and stats shared by all restore threads and the counter thread.
 */
typedef struct restore_config {

	char *host;
	int32_t port;
	bool use_services_alternate;
	char *user;
	char *password;
	uint32_t parallel;
	char *nice_list;
	bool no_records;
	bool no_indexes;
	bool indexes_last;
	bool no_udfs;
	bool wait;
	// timeout for Aerospike commands.
	uint32_t timeout;

	as_config_tls tls;
	char* tls_name;

	// The Aerospike client.
	aerospike *as;
	// The (optional) source and (also optional) target namespace to be restored.
	char *ns_list;
	// The directory to restore from. `NULL`, when restoring from a single file.
	char *directory;
	// The file to restore from. `NULL`, when restoring from a directory.
	char *input_file;
	// The path for the machine-readable output.
	char *machine;
	// The bins to be restored.
	char *bin_list;
	// The sets to be restored.
	char *set_list;
	// The encryption key given by the user
	encryption_key_t* pkey;
	// The compression mode to be used (default is none)
	compression_opt compress_mode;
	// The encryption mode to be used (default is none)
	encryption_opt encrypt_mode;
	// Indicates that existing records shouldn't be touched.
	bool unique;
	// Indicates that existing records should be replaced instead of updated.
	bool replace;
	// Ignore record specific errors.
	bool ignore_rec_error;
	// Indicates that the generation count of existing records should be ignored.
	bool no_generation;
	// Amount of extra time-to-live to add to records that have expirable
	// void-times.
	int32_t extra_ttl;
	// The B/s cap for throttling.
	uint64_t bandwidth;
	// The TPS cap for throttling.
	uint32_t tps;
	// The file format decoder to be used for reading data from a backup file.
	backup_decoder_t *decoder;
	// The total size of all backup files to be restored.
	off_t estimated_bytes;
	// The total number of bytes read from the backup file(s) so far.
	cf_atomic64 total_bytes;
	// The total number of records read from the backup file(s) so far.
	cf_atomic64 total_records;
	// The number of records dropped because they were expired.
	cf_atomic64 expired_records;
	// The number of records dropped because they didn't contain any of the
	// selected bins or didn't belong to any of the the selected sets.
	cf_atomic64 skipped_records;
	// The number of records ignored because of record level permanent error while
	// restoring. e.g RECORD_TOO_BIG Enabled or disabled using
	// --ignore-record-error flag.
	cf_atomic64 ignored_records;
	// The number of successfully restored records.
	cf_atomic64 inserted_records;
	// The number of records dropped because they already existed in the
	// database.
	cf_atomic64 existed_records;
	// The number of records dropped because the database already contained the
	// records with a higher generation count.
	cf_atomic64 fresher_records;
	// How often we backed off due to server overload.
	cf_atomic64 backoff_count;
	// The current limit for total_bytes for throttling. This is periodically
	// increased by the counter thread to raise the limit according to the
	// bandwidth limit.
	volatile uint64_t bytes_limit;
	// The current limit for total_records for throttling.
	// This is periodically increased by the counter thread to raise the limit
	// according to the TPS limit.
	volatile uint64_t records_limit;
	// The number of successfully created secondary indexes.
	volatile uint32_t index_count;
	// The number of successfully stored UDF files.
	volatile uint32_t udf_count;
	// Authentication mode.
	char *auth_mode;
} restore_config_t;


/*
 * The backup file information pushed to the job queue and picked up by the restore threads.
 */
typedef struct {
	// The global restore configuration and stats.
	restore_config_t *conf;
	// The backup file to be restored.
	char *path;
	// When restoring from a single file, the file descriptor of that file.
	io_read_proxy_t* shared_fd;
	// The current line number.
	uint32_t *line_no;
	// The (optional) source and (also optional) target namespace to be
	// restored, as a vector of strings.
	as_vector *ns_vec;
	// The bins to be restored, as a vector of bin name strings.
	as_vector *bin_vec;
	// The sets to be restored, as a vector of set name strings.
	as_vector *set_vec;
	// Indicates a version 3.0 backup file.
	bool legacy;
} restore_thread_args;

/*
 * The per-thread context for information about the currently processed backup file. Each restore
 * thread creates one of these for each backup file that it reads.
 */
typedef struct per_thread_context {
	// The global restore configuration and stats.
	restore_config_t *conf;
	// The backup file to be restored. Copied from restore_thread_args.path.
	char *path;
	// When restoring from a single file, the file descriptor of that file.
	// Copied from restore_thread_args.shared_fd.
	io_read_proxy_t* shared_fd;
	// The current line number. Copied from restore_thread_args.line_no.
	uint32_t *line_no;
	// The file descriptor of the currently processed backup file.
	io_read_proxy_t* fd;
	// The (optional) source and (also optional) target namespace to be restored,
	// as a vector of strings. Copied from restore_thread_args.ns_vec.
	as_vector *ns_vec;
	// The bins to be restored, as a vector of bin name strings.
	// Copied from restore_thread_args.bin_vec.
	as_vector *bin_vec;
	// The sets to be restored, as a vector of set name strings.
	// Copied from restore_thread_args.set_vec.
	as_vector *set_vec;
	// Indicates a version 3.0 backup file. Copied from
	// restore_thread_args.legacy.
	bool legacy;
	// The total number of bytes read from the current file
	uint64_t byte_count_file;
	// The number of records for which we have collected timing stats.
	uint64_t stat_records;
	// The time spent on reading records on this thread.
	cf_clock read_time;
	// The time spent on storing records on this thread.
	cf_clock store_time;
	// The exponential moving average of read latencies.
	uint32_t read_ema;
	// The exponential moving average of store latencies.
	uint32_t store_ema;
} per_thread_context_t;

/*
 * Indicates, whether a secondary index exists and matches a given secondary index specification.
 */
typedef enum {
	// Invalid.
	INDEX_STATUS_INVALID,
	// The secondary index does not exist.
	INDEX_STATUS_ABSENT,
	// The secondary index exists and it matches the given specification.
	INDEX_STATUS_SAME,
	// The secondary index exists, but it does not match the given specification.
	INDEX_STATUS_DIFFERENT
} index_status;

extern int32_t restore_main(int32_t argc, char **argv);
extern void restore_config_default(restore_config_t *conf);
extern void restore_config_destroy(restore_config_t *conf);

