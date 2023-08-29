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

#define RUN_BACKUP_SUCCESS ((void*) 0)
#define RUN_BACKUP_FAILURE ((void*) -1lu)

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
backup_status_t* backup_run(backup_config_t* conf);

/*
 * Returns the backup config/status struct being used by the currently running
 * backup job.
 */
backup_config_t* get_g_backup_conf(void);
backup_status_t* get_g_backup_status(void);

#ifdef __cplusplus
}
#endif

