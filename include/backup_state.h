/*
 * Aerospike Backup State
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

#include <stdio.h>

#include <aerospike/as_key.h>

#include <backup.h>
#include <io_proxy.h>


//==========================================================
// Typedefs & constants.
//

#define DEFAULT_BACKUP_FILE_LIST_SIZE 8

#define BACKUP_STATE_STATUS_NONE           0x0
#define BACKUP_STATE_STATUS_COMPLETE       0x1
#define BACKUP_STATE_STATUS_INCOMPLETE     0x2
#define BACKUP_STATE_STATUS_NOT_STARTED    0x3
#define BACKUP_STATE_STATUS_COMPLETE_EMPTY 0x4
#define BACKUP_STATE_STATUS_BITS 3
#define BACKUP_STATE_STATUS_MASK ((1lu << BACKUP_STATE_STATUS_BITS) - 1)

#define BACKUP_STATE_PARTS_PER_INT ((8 * sizeof(uint64_t)) / BACKUP_STATE_STATUS_BITS)
#define BACKUP_STATE_PARTS_STATUS_SIZE \
	((MAX_PARTITIONS + BACKUP_STATE_PARTS_PER_INT - 1) / BACKUP_STATE_PARTS_PER_INT)

typedef struct backup_state_file {
	io_proxy_t* io_proxy;
	uint64_t rec_count_file;
} backup_state_file_t;

typedef struct backup_state_partitions {
	uint64_t status[BACKUP_STATE_PARTS_STATUS_SIZE];

	as_digest_value digests[MAX_PARTITIONS];
} backup_state_partitions_t;

typedef struct backup_global_status {
	uint64_t file_count;
	uint32_t index_count;
	uint32_t udf_count;
	uint32_t user_count;
	uint64_t rec_count_total;
	uint64_t byte_count_total;
	uint64_t rec_count_total_committed;
	uint64_t byte_count_total_committed;
} backup_global_status_t;

typedef struct backup_state {
	/*
	 * The file the backup state will be written to.
	 */
	file_proxy_t* file;

	backup_state_partitions_t partitions;

	backup_global_status_t backup_global_status;

	/*
	 * A list of backup_state_file_t's in use at close that haven't been filled
	 * to --file-limit.
	 *
	 * To claim ownership of the entries of the vector, remove those entries
	 * from the vector (otherwise they will be freed when the backup_state is
	 * freed).
	 */
	as_vector files;
	// Flag to be set when files is sorted. Unset when files are added to the
	// list, set again when a file is queried from the list.
	bool files_sorted;
} backup_state_t;


/*
 * Initializes a backup_state struct to be written to the file at "path".
 *
 * Returns 0 on success, nonzero on failure.
 */
int backup_state_init(backup_state_t*, const char* path);

/*
 * Loads a backup state struct from a file, populating the fields of the
 * backup state.
 *
 * Returns 0 on success, nonzero on failure.
 */
int backup_state_load(backup_state_t*, const char* path);

/*
 * Saves the backup state to the file it was opened with.
 *
 * Returns 0 on success, nonzero on failure.
 */
int backup_state_save(backup_state_t*);

/*
 * Frees resources associated with the backup state.
 */
void backup_state_free(backup_state_t*);

/*
 * Returns true if every partition in the backup state is marked
 * BACKUP_STATE_STATUS_COMPLETE.
 */
bool backup_state_is_complete(const backup_state_t*);

/*
 * Returns the status of the given partition id, setting the value to the last
 * digest backed up if the status is BACKUP_STATE_STATUS_INCOMPLETE.
 */
uint8_t backup_state_get_status(const backup_state_t*, uint16_t partition_id,
		uint8_t* digest_value);

/*
 * Marks the partition_id as cleared, i.e. having no backup state.
 */
void backup_state_clear_partition(backup_state_t*, uint16_t partition_id);

/*
 * Marks the given partition_id as complete, which can be useful when clearing
 * out the partitions that have been processed from a file.
 *
 * This method needs the last_digest because scan resumption requires the
 * last_digest of each partition, even completed ones.
 *
 * If last_digest is NULL, this means the partition has been scanned, but no
 * records were found (i.e. the partition is empty).
 */
void backup_state_mark_complete(backup_state_t*, uint16_t partition_id,
		const uint8_t* last_digest);

/*
 * Marks the given partition_id as incomplete, where last_digest was the last
 * record digest to have been recorded in the backup.
 */
void backup_state_mark_incomplete(backup_state_t*, uint16_t partition_id,
		const uint8_t* last_digest);

/*
 * Marks the given partition_id as not started, meaning no records from this
 * partition have been backed up yet.
 */
void backup_state_mark_not_started(backup_state_t*, uint16_t partition_id);

/*
 * Saves global bookkeeping data from the backup config.
 */
void backup_state_set_global_status(backup_state_t*,
		const backup_status_t* status);

/*
 * Loads the global bookkeeping data from the backup state to conf.
 */
void backup_state_load_global_status(const backup_state_t*,
		backup_status_t* status);

/*
 * Serializes an io_proxy to the backup state.
 *
 * This transfers ownership of the io_proxy to the backup state, so the passed
 * io_proxy should not be used or closed/freed after this call. The io_proxy
 * passed to this method must be heap-allocated.
 */
bool backup_state_save_file(backup_state_t*, io_proxy_t* file,
		uint64_t rec_count_file);

/*
 * Checks whether the given file_name is in the list of files in the backup
 * state.
 */
bool backup_state_contains_file(backup_state_t*, const char* file_name);

#ifdef __cplusplus
}
#endif

