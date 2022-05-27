/*
 * Aerospike Backup
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
#include <libgen.h>
#include <math.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/statvfs.h>
#include <sys/stat.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/cf_b64.h>
#include <citrusleaf/cf_queue.h>
#include <aerospike/aerospike_info.h>
#include <aerospike/as_partition_filter.h>
#include <aerospike/as_scan.h>

#pragma GCC diagnostic pop

#include <backup_config.h>
#include <backup_status.h>
#include <conf.h>
#include <io_proxy.h>
#include <encode.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

// The maximal number of UDF files that we can backup.
#define MAX_UDF_FILES 1000

// Estimate total backup file sizes with 99.9% confidence.
#define BACKUP_FILE_ESTIMATE_CONFIDENCE_LEVEL 0.999

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


//==========================================================
// Public API.
//

int32_t backup_main(int32_t argc, char **argv);

/*
 * Returns the backup config/status struct being used by the currently running
 * backup job.
 */
backup_config_t* get_g_backup_conf(void);
backup_status_t* get_g_backup_status(void);

#ifdef __cplusplus
}
#endif

