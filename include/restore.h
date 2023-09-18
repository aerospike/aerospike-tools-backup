/*
 * Aerospike Restore
 *
 * Copyright (c) 2008-2022 Aerospike, Inc. All rights reserved.
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

#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/cf_queue.h>
#include <aerospike/aerospike_info.h>
#include <aerospike/aerospike_key.h>
#include <aerospike/as_partition_filter.h>
#include <aerospike/as_record.h>
#include <aerospike/as_scan.h>

#pragma GCC diagnostic pop

#include <encode.h>
#include <io_proxy.h>
#include <record_uploader.h>
#include <restore_config.h>
#include <restore_status.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

// The interval for logging per-thread timing stats.
#define STAT_INTERVAL 10
#define RUN_RESTORE_FAILURE ((void*) -1lu)

/*
 * The backup file information pushed to the job queue and picked up by the restore threads.
 */
typedef struct restore_thread_args {
	// The global restore configuration.
	restore_config_t *conf;
	// The global resture stats.
	restore_status_t *status;
	// The backup file to be restored.
	char *path;
	// When restoring from a single file, the file descriptor of that file.
	io_read_proxy_t* shared_fd;
	// The current line number.
	uint32_t *line_no;

	// Indicates a version 3.0 backup file.
	bool legacy;
} restore_thread_args_t;

/*
 * The per-thread context for information about the currently processed backup file. Each restore
 * thread creates one of these for each backup file that it reads.
 */
typedef struct per_thread_context {
	// The global restore configuration and stats.
	restore_config_t *conf;
	// The global resture stats.
	restore_status_t *status;
	// The record uploader to be used for this job.
	record_uploader_t* record_uploader;
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


//==========================================================
// Public API.
//

int32_t restore_main(int32_t argc, char **argv);
restore_status_t* restore_run(restore_config_t *conf);

#ifdef __cplusplus
}
#endif

