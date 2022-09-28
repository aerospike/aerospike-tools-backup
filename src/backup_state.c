/*
 * Copyright 2021-2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

//==========================================================
// Includes.
//

#include <backup_state.h>

#include <errno.h>
#include <stdlib.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_atomic.h>
#include <aerospike/as_partition.h>

#pragma GCC diagnostic pop

#include <utils.h>


//==========================================================
// Forward Declarations.
//

static uint8_t _get_status(const backup_state_partitions_t* cont,
		uint16_t part_id);
static void _set_status(backup_state_partitions_t*, uint16_t part_id,
		uint8_t status);
static void _clear_status(backup_state_partitions_t*, uint16_t part_id);
static bool _validate_backup_state(const backup_state_t*);

static bool _write_backup_state(const backup_state_t* state);
static bool _write_backup_global_status(file_proxy_t* fd, const backup_global_status_t* g_status);
static bool _write_backup_files(file_proxy_t* fd, const as_vector* files);

static bool _load_backup_global_status(file_proxy_t* fd, backup_global_status_t* g_status);
static bool _load_backup_files(file_proxy_t* fd, as_vector* files);
static int _file_name_sort_comparator(const void*, const void*);
static int _file_name_bsearch_comparator(const void* key, const void*);


//==========================================================
// Public API.
//

int
backup_state_init(backup_state_t* state, const char* path)
{
	file_proxy_t* fd = cf_malloc(sizeof(file_proxy_t));
	if (fd == NULL) {
		err("Unable to allocate %lu bytes for file proxy", sizeof(file_proxy_t));
		return -1;
	}

	if (file_proxy_write_init(fd, path, 0) != 0) {
		err("Unable to open file %s for writing", path);
		cf_free(fd);
		return -1;
	}

	state->file = fd;
	memset(&state->partitions, 0, sizeof(backup_state_partitions_t));
	memset(&state->backup_global_status, 0, sizeof(backup_global_status_t));
	as_vector_init(&state->files, sizeof(backup_state_file_t),
			DEFAULT_BACKUP_FILE_LIST_SIZE);
	state->files_sorted = false;
	return 0;
}

int
backup_state_load(backup_state_t* state, const char* path)
{
	file_proxy_t fd;
	if (file_proxy_read_init(&fd, path) != 0) {
		err("Unable to open file %s for reading", path);
		return -1;
	}

	state->file = NULL;
	size_t n_bytes = file_proxy_read(&fd, &state->partitions,
			sizeof(backup_state_partitions_t));
	if (n_bytes < sizeof(backup_state_partitions_t)) {
		err("Unable to read all data from the backup state file");
		file_proxy_close(&fd);
		return -1;
	}

	if (!_load_backup_global_status(&fd, &state->backup_global_status)) {
		file_proxy_close(&fd);
		return -1;
	}

	as_vector_init(&state->files, sizeof(backup_state_file_t),
			DEFAULT_BACKUP_FILE_LIST_SIZE);

	if (!_load_backup_files(&fd, &state->files)) {
		file_proxy_close(&fd);
		backup_state_free(state);
		return -1;
	}
	state->files_sorted = false;

	file_proxy_close(&fd);

	if (!_validate_backup_state(state)) {
		backup_state_free(state);
		return -1;
	}

	return 0;
}

int
backup_state_save(backup_state_t* state)
{
	if (state->file == NULL) {
		return -1;
	}

	if (file_proxy_truncate(state->file) != 0) {
		err("Unable to truncate backup state file");
		// don't treat this as a critical error
	}

	// commit the backup state to the file
	if (!_write_backup_state(state)) {
		return -1;
	}

	if (file_proxy_flush(state->file) == EOF) {
		err("Error while flushing backup state file.");
		return -1;
	}

	if (file_proxy_close2(state->file, FILE_PROXY_EOF) != 0) {
		err("Error while closing backup state file.");
		return -1;
	}
	cf_free(state->file);
	state->file = NULL;

	int res = 0;
	for (uint32_t i = 0; i < state->files.size; i++) {
		backup_state_file_t* file =
			(backup_state_file_t*) as_vector_get(&state->files, i);
		// we need to mark all open write proxies as continue, or ABORT if we
		// are aborting the backup
		if (io_proxy_close2(file->io_proxy,
					res == 0 ? FILE_PROXY_CONTINUE : FILE_PROXY_ABORT) != 0) {
			err("Error while closing backup file %s.",
					io_proxy_file_path(file->io_proxy));
			res = -1;
		}

		cf_free(file->io_proxy);
	}
	as_vector_clear(&state->files);

	return res;
}

void
backup_state_free(backup_state_t* state)
{
	if (state->file != NULL) {
		file_proxy_close2(state->file, FILE_PROXY_EOF);
		cf_free(state->file);
	}

	for (uint32_t i = 0; i < state->files.size; i++) {
		backup_state_file_t* file =
			(backup_state_file_t*) as_vector_get(&state->files, i);
		// we need to mark all open write proxies as continue, and read proxies
		// ignore the mode argument
		io_proxy_close2(file->io_proxy, FILE_PROXY_CONTINUE);

		cf_free(file->io_proxy);
	}
	as_vector_destroy(&state->files);
}

bool
backup_state_is_complete(const backup_state_t* state)
{
	const backup_state_partitions_t* parts = &state->partitions;

	for (uint16_t i = 0; i < MAX_PARTITIONS; i++) {
		uint8_t status = _get_status(parts, i);
		if (status != BACKUP_STATE_STATUS_NONE &&
				status != BACKUP_STATE_STATUS_COMPLETE &&
				status != BACKUP_STATE_STATUS_COMPLETE_EMPTY) {
			return false;
		}
	}

	return true;
}

uint8_t
backup_state_get_status(const backup_state_t* state, uint16_t partition_id,
		uint8_t* digest_value)
{
	const backup_state_partitions_t* cont = &state->partitions;

	uint8_t status = _get_status(cont, partition_id);
	if (status == BACKUP_STATE_STATUS_INCOMPLETE ||
			status == BACKUP_STATE_STATUS_COMPLETE) {
		memcpy(digest_value, cont->digests[partition_id], sizeof(as_digest_value));
	}
	return status;
}

void
backup_state_clear_partition(backup_state_t* state, uint16_t partition_id)
{
	backup_state_partitions_t* cont = &state->partitions;

	_clear_status(cont, partition_id);
}

void
backup_state_mark_complete(backup_state_t* state, uint16_t partition_id,
		const uint8_t* last_digest)
{
	backup_state_partitions_t* cont = &state->partitions;

	if (last_digest == NULL) {
		_set_status(cont, partition_id, BACKUP_STATE_STATUS_COMPLETE_EMPTY);
	}
	else {
		_set_status(cont, partition_id, BACKUP_STATE_STATUS_COMPLETE);
		memcpy(cont->digests[partition_id], last_digest, sizeof(as_digest_value));
	}
}

void
backup_state_mark_incomplete(backup_state_t* state, uint16_t partition_id,
		const uint8_t* last_digest)
{
	backup_state_partitions_t* cont = &state->partitions;

	_set_status(cont, partition_id, BACKUP_STATE_STATUS_INCOMPLETE);
	memcpy(cont->digests[partition_id], last_digest, sizeof(as_digest_value));
}

void
backup_state_mark_not_started(backup_state_t* state, uint16_t partition_id)
{
	backup_state_partitions_t* cont = &state->partitions;

	_set_status(cont, partition_id, BACKUP_STATE_STATUS_NOT_STARTED);
}

void
backup_state_set_global_status(backup_state_t* state,
		const backup_status_t* status)
{
	state->backup_global_status.index_count = status->index_count;
	state->backup_global_status.udf_count = status->udf_count;
	state->backup_global_status.user_count = status->user_count;

	state->backup_global_status.file_count = as_load_uint64(&status->file_count);
	state->backup_global_status.rec_count_total =
		as_load_uint64(&status->rec_count_total);
	state->backup_global_status.byte_count_total =
		as_load_uint64(&status->byte_count_total);
	state->backup_global_status.rec_count_total_committed =
		as_load_uint64(&status->rec_count_total_committed);
	state->backup_global_status.byte_count_total_committed =
		as_load_uint64(&status->byte_count_total_committed);
}

void
backup_state_load_global_status(const backup_state_t* state,
		backup_status_t* status)
{
	status->index_count = state->backup_global_status.index_count;
	status->udf_count = state->backup_global_status.udf_count;
	status->user_count = state->backup_global_status.user_count;

	as_store_uint64(&status->file_count, state->backup_global_status.file_count);
	as_store_uint64(&status->rec_count_total, state->backup_global_status.rec_count_total);
	as_store_uint64(&status->byte_count_total, state->backup_global_status.byte_count_total);
	as_store_uint64(&status->rec_count_total_committed,
			state->backup_global_status.rec_count_total_committed);
	as_store_uint64(&status->byte_count_total_committed,
			state->backup_global_status.byte_count_total_committed);
}

bool
backup_state_save_file(backup_state_t* state, io_proxy_t* file,
		uint64_t rec_count_file)
{
	backup_state_file_t data = {
		.io_proxy = file,
		.rec_count_file = rec_count_file
	};

	as_vector_append(&state->files, &data);
	state->files_sorted = false;

	return true;
}

bool
backup_state_contains_file(backup_state_t* state, const char* file_name)
{
	if (!state->files_sorted) {
		qsort(state->files.list, state->files.size, state->files.item_size,
				_file_name_sort_comparator);
		state->files_sorted = true;
	}

	return bsearch(file_name, state->files.list, state->files.size,
			state->files.item_size, _file_name_bsearch_comparator) != NULL;
}


//==========================================================
// Local helpers.
//

static uint8_t
_get_status(const backup_state_partitions_t* cont, uint16_t part_id)
{
	uint64_t idx = part_id / BACKUP_STATE_PARTS_PER_INT;
	uint64_t bitv_idx = part_id % BACKUP_STATE_PARTS_PER_INT;

	uint64_t bitv = cont->status[idx];
	return (uint8_t) ((bitv >> (BACKUP_STATE_STATUS_BITS * bitv_idx)) &
			BACKUP_STATE_STATUS_MASK);
}

static void
_set_status(backup_state_partitions_t* cont, uint16_t part_id, uint8_t status)
{
	uint64_t idx = part_id / BACKUP_STATE_PARTS_PER_INT;
	uint64_t bitv_idx = part_id % BACKUP_STATE_PARTS_PER_INT;

	uint64_t bitv = cont->status[idx];
	bitv |= (((uint64_t) status) << (BACKUP_STATE_STATUS_BITS * bitv_idx));
	cont->status[idx] = bitv;
}

static void
_clear_status(backup_state_partitions_t* cont, uint16_t part_id)
{
	uint64_t idx = part_id / BACKUP_STATE_PARTS_PER_INT;
	uint64_t bitv_idx = part_id % BACKUP_STATE_PARTS_PER_INT;

	uint64_t bitv = cont->status[idx];
	bitv &= ~(BACKUP_STATE_STATUS_MASK << (BACKUP_STATE_STATUS_BITS * bitv_idx));
	cont->status[idx] = bitv;
}

static bool
_validate_backup_state(const backup_state_t* state)
{
	static const as_digest_value zero_digest = { 0 };

	const backup_state_partitions_t* cont = &state->partitions;

	for (uint16_t pid = 0; pid < MAX_PARTITIONS; pid++) {
		uint8_t status = _get_status(cont, pid);
		const as_digest_value* digest;
		uint32_t digest_pid;

		switch (status) {
			case BACKUP_STATE_STATUS_NONE:
			case BACKUP_STATE_STATUS_NOT_STARTED:
			case BACKUP_STATE_STATUS_COMPLETE_EMPTY:
				if (memcmp(cont->digests[pid], zero_digest,
							sizeof(as_digest_value)) != 0) {
					err("Expected zero-valued digest at partition id %u (%u)", pid, status);
					return false;
				}
				break;

			case BACKUP_STATE_STATUS_COMPLETE:
			case BACKUP_STATE_STATUS_INCOMPLETE:
				digest = &cont->digests[pid];
				digest_pid = as_partition_getid(*digest, MAX_PARTITIONS);
				if (digest_pid != pid) {
					err("Digest for partition id %u belongs to partition %u",
							pid, digest_pid);
					return false;
				}
				break;

			default:
				err("Unexpected backup state status 0x%02x", status);
				return false;
		}
	}

	return true;
}

static bool
_write_backup_state(const backup_state_t* state)
{
	if (file_proxy_write(state->file, &state->partitions, sizeof(backup_state_partitions_t)) !=
			sizeof(backup_state_partitions_t)) {
		err("Error while writing backup state partitions to file");
		return false;
	}

	if (!_write_backup_global_status(state->file, &state->backup_global_status)) {
		return false;
	}

	if (!_write_backup_files(state->file, &state->files)) {
		return false;
	}

	return true;
}

static bool
_write_backup_global_status(file_proxy_t* fd, const backup_global_status_t* g_status)
{
	if (!write_int64(g_status->file_count, fd)) {
		err("Error while writing file count to backup state");
		return false;
	}

	if (!write_int32(g_status->index_count, fd)) {
		err("Error while writing index count to backup state");
		return false;
	}

	if (!write_int32(g_status->udf_count, fd)) {
		err("Error while writing udf count to backup state");
		return false;
	}

	if (!write_int64(g_status->rec_count_total, fd)) {
		err("Error while writing record count total to backup state");
		return false;
	}

	if (!write_int64(g_status->byte_count_total, fd)) {
		err("Error while writing byte count total to backup state");
		return false;
	}

	if (!write_int64(g_status->rec_count_total_committed, fd)) {
		err("Error while writing record count total committed to backup state");
		return false;
	}

	if (!write_int64(g_status->byte_count_total_committed, fd)) {
		err("Error while writing byte count total committed to backup state");
		return false;
	}

	return true;
}

static bool
_write_backup_files(file_proxy_t* fd, const as_vector* files)
{

	if (!write_int64(files->size, fd)) {
		err("Failed to write number of backup files to the backup state file");
		return false;
	}

	for (uint32_t i = 0; i < files->size; i++) {
		const backup_state_file_t* f =
			(const backup_state_file_t*) as_vector_get((as_vector*) files, i);

		if (io_proxy_serialize(f->io_proxy, fd) != 0) {
			err("Error serializing io proxy for \"%s\" to backup state file",
					io_proxy_file_path(f->io_proxy));
			return false;
		}

		if (!write_int64(f->rec_count_file, fd)) {
			err("Error writing file record count to backup state file \"%s\"",
					io_proxy_file_path(f->io_proxy));
			return false;
		}
	}

	return true;
}

static bool
_load_backup_global_status(file_proxy_t* fd, backup_global_status_t* g_status)
{
	if (!read_int64(&g_status->file_count, fd)) {
		err("Error while reading file count from backup state");
		return false;
	}

	if (!read_int32(&g_status->index_count, fd)) {
		err("Error while reading index count from backup state");
		return false;
	}

	if (!read_int32(&g_status->udf_count, fd)) {
		err("Error while reading udf count from backup state");
		return false;
	}

	if (!read_int64(&g_status->rec_count_total, fd)) {
		err("Error while reading record count total from backup state");
		return false;
	}

	if (!read_int64(&g_status->byte_count_total, fd)) {
		err("Error while reading byte count total from backup state");
		return false;
	}

	if (!read_int64(&g_status->rec_count_total_committed, fd)) {
		err("Error while reading record count total committed from backup state");
		return false;
	}

	if (!read_int64(&g_status->byte_count_total_committed, fd)) {
		err("Error while reading byte count total committed from backup state");
		return false;
	}

	return true;
}

static bool
_load_backup_files(file_proxy_t* fd, as_vector* files)
{
	io_write_proxy_t* io_proxy;
	uint64_t rec_count_file;

	uint64_t expected_n_files;

	if (!read_int64(&expected_n_files, fd)) {
		err("Failed to read the number of backup files from the backup state file");
		return false;
	}

	for (uint64_t i = 0; i < expected_n_files; i++ ) {

		io_proxy = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
		if (io_proxy == NULL) {
			err("Unable to malloc file_name/io for backup state");
			goto cleanup_loop;
		}

		if (io_proxy_deserialize(io_proxy, fd) != 0) {
			err("Unable to deserialize io_proxy");
			goto cleanup_loop;
		}

		if (!read_int64(&rec_count_file, fd)) {
			err("Failed to read rec_count_file from backup state file");
			goto cleanup_loop;
		}

		backup_state_file_t f = {
			.io_proxy = io_proxy,
			.rec_count_file = rec_count_file
		};

		as_vector_append(files, &f);

		continue;

cleanup_loop:
		cf_free(io_proxy);
		return false;
	}

	return true;
}

static int
_file_name_sort_comparator(const void* _f1, const void* _f2)
{
	const backup_state_file_t* file1 = (const backup_state_file_t*) _f1;
	const backup_state_file_t* file2 = (const backup_state_file_t*) _f2;
	return strcmp(io_proxy_file_path(file1->io_proxy), io_proxy_file_path(file2->io_proxy));
}

static int
_file_name_bsearch_comparator(const void* key, const void* _f)
{
	const backup_state_file_t* file = (const backup_state_file_t*) _f;
	return strcmp((const char*) key, io_proxy_file_path(file->io_proxy));
}

