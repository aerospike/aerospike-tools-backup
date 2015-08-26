/*
 * Aerospike Restore
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

#define VERY_LONG_LDT_TIMEOUT 600000    ///< Writing LDT elements can take a while; use this very
                                        ///  long timeout for that.

#define DEFAULT_THREADS 20              ///< The default number of restore threads.
#define DEFAULT_LDT_BATCH_SIZE 100      ///< By default, split LDT updates into chunks of this size
                                        ///  in MiB.
#define MAX_LDT_BATCH_SIZE 100          ///< Allow LDT updates to be split into chunks of this size
                                        ///  in MiB at maximum.

#define MAX_TRIES 10                    ///< Maximal number of tries for each record put.
#define INITIAL_BACKOFF 10              ///< Initial backoff delay (in ms) between tries when
                                        ///  overloaded; doubled after each try.

///
/// Encapsulates a UDF file.
///
typedef struct {
	as_udf_type type;   ///< The language of the UDF file.
	char *name;         ///< The name of the UDF file.
	uint32_t size;      ///< The size of the UDF file.
	void *data;         ///< The content of the UDF file.
} udf_param;

///
/// The result codes for LDT record preparation.
///
typedef enum {
	PREPARE_INVALID,    ///< Invalid.
	PREPARE_OK,         ///< The record should be restored.
	PREPARE_ERROR,      ///< Something went wrong.
	PREPARE_EXISTS,     ///< The record exists and we aren't supposed to overwrite existing records.
	PREPARE_FRESHER     ///< The record exists and it beats our generation number.
} prepare_result;

///
/// The callback invoked by the backup file format decoder to add values to an LDT bin.
///
/// @param context   The opaque user-specified context.
/// @param bytes     The number of bytes read since the beginning of this record.
/// @param rec       The record containing the LDT bin.
/// @param bin_name  The name of the LDT bin.
/// @param value     The value to be added to the LDT bin. `NULL` to indicate completion.
/// @param expired   Indicates that the record is expired.
///
/// @result          `true`, if successful.
///
typedef bool (*ldt_callback)(void *context, int64_t bytes, as_record *rec, const char *bin_name,
		as_val *value, bool *expired);

///
/// The result codes for the backup file format decoder.
///
typedef enum {
	DECODER_RECORD, ///< A record was read and is returned.
	DECODER_INDEX,  ///< Secondary index information was read and is returned.
	DECODER_UDF,    ///< A UDF file was read and is returned.
	DECODER_EOF,    ///< The end of the backup file was encountered.
	DECODER_ERROR   ///< An error occurred.
} decoder_status;

///
/// The interface exposed by the backup file format decoder.
///
typedef struct {
	///
	/// Reads, parses, and returns the next entity from a backup file descriptor.
	///
	/// @param fd        The file descriptor.
	/// @param legacy    Indicates a version 3.0 backup file.
	/// @param ns_vec    The (optional) source and (also optional) target namespace to be restored.
	/// @param bin_vec   The bins to be restored, as a vector of strings.
	/// @param line_no   The current line number.
	/// @param total     Increased by the number of bytes read from the file descriptor.
	/// @param rec       The returned record. Only valid, if the result is
	///                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	/// @param expired   Indicates that an expired record was read. Only valid, if the result is
	///                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	/// @param callback  The callback to be invoked to add values to an LDT bin.
	/// @param context   The opaque user-specified context to be passed to the callback.
	/// @param index     The returned secondary index information. Only valid, if the result is
	///                  [DECODER_INDEX](@ref decoder_status::DECODER_INDEX).
	/// @param udf       The returned UDF file. Only valid, if the result is
	///                  [DECODER_UDF](@ref decoder_status::DECODER_UDF).
	///
	/// @result          See @ref decoder_status.
	///
	decoder_status (*parse)(FILE *fd, bool legacy, as_vector *ns_vec, as_vector *bin_vec,
			uint32_t *line_no, cf_atomic64 *total, as_record *rec, bool *expired,
			ldt_callback callback, void *context, index_param *index, udf_param *udf);
} backup_decoder;

///
/// The global restore configuration and stats shared by all restore threads and the counter thread.
///
typedef struct {
	aerospike *as;                  ///< The Aerospike client.
	char *ns_list;                  ///< The (optional) source and (also optional) target namespace
	                                ///  to be restored.
	char *directory;                ///< The directory to restore from. `NULL`, when restoring from
	                                ///  a single file.
	char *input_file;               ///< The file to restore from. `NULL`, when restoring from a
	                                ///  directory.
	char *machine;                  ///< The path for the machine-readable output.
	char *bin_list;                 ///< The bins to be restored.
	char *set_list;                 ///< The sets to be restored.
	bool unique;                    ///< Indicates that existing records shouldn't be touched.
	bool replace;                   ///< Indicates that existing records should be replaced instead
	                                ///  of updated.
	bool no_generation;             ///< Indicates that the generation count of existing records
	                                ///  should be ignored.
	bool keep_ldt;                  ///< Indicates that LDT bins should be kept, i.e., their content
	                                ///  merged, not replaced.
	uint64_t batch_size;            ///< The maximal serialized size of a batch of LDT elements when
	                                ///  writing LDT bins.
	uint64_t bandwidth;             ///< The B/s cap for throttling.
	uint32_t tps;                   ///< The TPS cap for throttling.
	backup_decoder *decoder;        ///< The file format decoder to be used for reading data from a
	                                ///  backup file.
	off_t estimated_bytes;          ///< The total size of all backup files to be restored.
	cf_atomic64 total_bytes;        ///< The total number of bytes read from the backup file(s) so
	                                ///  far.
	cf_atomic64 total_records;      ///< The total number of records read from the backup file(s) so
	                                ///  far.
	cf_atomic64 expired_records;    ///< The number of records dropped because they were expired.
	cf_atomic64 skipped_records;    ///< The number of records dropped because they didn't contain
	                                ///  any of the selected bins or didn't belong to any of the the
	                                ///  selected sets.
	cf_atomic64 inserted_records;   ///< The number of successfully restored records.
	cf_atomic64 existed_records;    ///< The number of records dropped because they already existed
	                                ///  in the database.
	cf_atomic64 fresher_records;    ///< The number of records dropped because the database already
	                                ///  contained the records with a higher generation count.
	cf_atomic64 backoff_count;      ///< How often we backed off due to server overload.
	volatile uint64_t bytes_limit;  ///< The current limit for total_bytes for throttling. This is
	                                ///  periodically increased by the counter thread to raise the
	                                ///  limit according to the bandwidth limit.
	volatile uint64_t records_limit;    ///< The current limit for total_records for throttling.
	                                    ///  This is periodically increased by the counter thread to
	                                    ///  raise the limit according to the TPS limit.
	volatile uint32_t index_count;  ///< The number of successfully created secondary indexes.
	volatile uint32_t udf_count;    ///< The number of successfully stored UDF files.
} restore_config;

///
/// The arguments passed to the counter thread.
///
typedef struct {
	restore_config *conf;                       ///< The global restore configuration and stats.
	char (*node_names)[][AS_NODE_NAME_SIZE];    ///< The cluster nodes to be backed up.
	uint32_t n_node_names;                      ///< The number of cluster nodes to be backed up.
	FILE *mach_fd;                              ///< The file descriptor for the machine-readable
	                                            ///< output.
} counter_thread_args;

///
/// The backup file information pushed to the job queue and picked up by the restore threads.
///
typedef struct {
	restore_config *conf;   ///< The global restore configuration and stats.
	char *path;             ///< The backup file to be restored.
	FILE *shared_fd;        ///< When restoring from a single file, the file descriptor of that
	                        ///  file.
	uint32_t *line_no;      ///< The current line number.
	as_vector *ns_vec;      ///< The (optional) source and (also optional) target namespace to be
	                        ///  restored, as a vector of strings.
	as_vector *bin_vec;     ///< The bins to be restored, as a vector of bin name strings.
	as_vector *set_vec;     ///< The sets to be restored, as a vector of set name strings.
	bool legacy;            ///< Indicates a version 3.0 backup file.
} restore_thread_args;

///
/// The per-thread context for information about the currently processed backup file. Each restore
/// thread creates one of these for each backup file that it reads.
///
typedef struct {
	restore_config *conf;       ///< The global restore configuration and stats.
	char *path;                 ///< The backup file to be restored. Copied from
	                            ///  restore_thread_args.path.
	FILE *shared_fd;            ///< When restoring from a single file, the file descriptor of that
	                            ///  file. Copied from restore_thread_args.shared_fd.
	uint32_t *line_no;          ///< The current line number. Copied from
	                            ///  restore_thread_args.line_no.
	FILE *fd;                   ///< The file descriptor of the currently processed backup file.
	void *fd_buf;               ///< When restoring from a directory, the I/O buffer associated with
	                            ///  the current backup file descriptor.
	as_vector *ns_vec;          ///< The (optional) source and (also optional) target namespace to
	                            ///  be restored, as a vector of strings. Copied from
	                            ///  restore_thread_args.ns_vec.
	as_vector *bin_vec;         ///< The bins to be restored, as a vector of bin name strings.
	                            ///  Copied from restore_thread_args.bin_vec.
	as_vector *set_vec;         ///< The sets to be restored, as a vector of set name strings.
	                            ///  Copied from restore_thread_args.set_vec.
	bool legacy;                ///< Indicates a version 3.0 backup file. Copied from
	                            ///  restore_thread_args.legacy.
	cf_clock ldt_now;           ///< The time when processing of the current LDT bin began.
	as_ldt *ldt_list;           ///< The LDT list used by the @ref ldt_callback function to write
	                            ///  LDT bins.
	as_arraylist *ldt_batch;    ///< The list of LDT elements used by the @ref ldt_callback function
	                            ///  to collect a batch of LDT elements to be written.
	int64_t ldt_bytes;          ///< The number of bytes read since the start of the record. Used by
	                            ///  the @ref ldt_callback function to estimate the current
	                            ///  serialized size of the batch in @ref ldt_batch.
	prepare_result ldt_prepare; ///< Status of LDT record preparation.
	bool has_ldts;              ///< Indicates that the @ref ldt_callback function was invoked and
	                            ///  wrote LDT data.
	bool ldt_cleared;           ///< Indicates that we have cleared the current LDT bin.
} per_thread_context;
