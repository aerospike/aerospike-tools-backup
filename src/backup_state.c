/*
 * Copyright 2015-2021 Aerospike, Inc.
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

#include <aerospike/as_partition.h>

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
static bool _write_backup_global_status(FILE* fd, const backup_global_status_t* g_state);
static bool _write_backup_files(FILE* fd, const as_vector* files);

static bool _load_backup_global_status(FILE* fd, backup_global_status_t* g_state);
static bool _load_backup_files(FILE* fd, as_vector* files);


//==========================================================
// Public API.
//

int
backup_state_init(backup_state_t* state, const char* path)
{
	FILE* fd = fopen(path, "w");
	if (fd == NULL) {
		err("Unable to open file %s for writing, reason: %s", path,
				strerror(errno));
		return -1;
	}

	state->fd = fd;
	memset(&state->partitions, 0, sizeof(backup_state_partitions_t));
	memset(&state->backup_global_status, 0, sizeof(backup_global_status_t));
	as_vector_init(&state->files, sizeof(backup_state_file_t),
			DEFAULT_BACKUP_FILE_LIST_SIZE);
	return 0;
}

int
backup_state_load(backup_state_t* state, const char* path)
{
	FILE* state_file = fopen(path, "r");
	if (state_file == NULL) {
		err("Unable to open file %s for reading, reason: %s", path,
				strerror(errno));
		return -1;
	}

	state->fd = NULL;
	size_t n_bytes = fread(&state->partitions, 1, sizeof(backup_state_partitions_t), state_file);
	if (n_bytes < sizeof(backup_state_partitions_t)) {
		err("Unable to read all data from the backup state file, reason: %s",
				strerror(errno));
		fclose(state_file);
		return -1;
	}

	if (!_load_backup_global_status(state_file, &state->backup_global_status)) {
		fclose(state_file);
		return -1;
	}

	as_vector_init(&state->files, sizeof(backup_state_file_t),
			DEFAULT_BACKUP_FILE_LIST_SIZE);

	if (!_load_backup_files(state_file, &state->files)) {
		fclose(state_file);
		backup_state_free(state);
		return -1;
	}

	fclose(state_file);

	if (!_validate_backup_state(state)) {
		backup_state_free(state);
		return -1;
	}

	return 0;
}

int
backup_state_save(const backup_state_t* state)
{
	if (state->fd == NULL) {
		return -1;
	}

	int32_t fno = fileno(state->fd);
	if (fno < 0) {
		err_code("Error while retrieving native file descriptor of backup "
				"state file.");
		return -1;
	}

	if (ftruncate(fno, 0) != 0) {
		err_code("Unable to truncate backup state file, reason: %s. This may "
				"render the backup file unusable, but will attempt to write to "
				"it anyway.",
				strerror(errno));
		// don't treat this as a critical error
	}

	// commit the backup state to the file
	if (!_write_backup_state(state)) {
		return -1;
	}

	if (fflush(state->fd) == EOF) {
		err_code("Error while flushing backup state file.");
		return -1;
	}

	return 0;
}

void
backup_state_free(backup_state_t* state)
{
	if (state->fd != NULL) {
		if (fclose(state->fd) == EOF) {
			err_code("Error while closing backup state file.");
		}
	}

	for (uint32_t i = 0; i < state->files.size; i++) {
		backup_state_file_t* file =
			(backup_state_file_t*) as_vector_get(&state->files, i);
		FILE* fd = file->io_proxy->fd;
		io_proxy_free(file->io_proxy);
		if (fd != NULL) {
			fclose(fd);
		}

		cf_free(file->io_proxy);
		cf_free(file->file_name);
	}
	as_vector_destroy(&state->files);
}

bool
backup_state_complete(const backup_state_t* state)
{
	const backup_state_partitions_t* parts = &state->partitions;

	for (uint16_t i = 0; i < MAX_PARTITIONS; i++) {
		uint8_t status = _get_status(parts, i);
		if (status != BACKUP_STATE_STATUS_NONE &&
				status != BACKUP_STATE_STATUS_COMPLETE) {
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

	_set_status(cont, partition_id, BACKUP_STATE_STATUS_COMPLETE);
	memcpy(cont->digests[partition_id], last_digest, sizeof(as_digest_value));
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

	state->backup_global_status.file_count = cf_atomic64_get(status->file_count);
	state->backup_global_status.rec_count_total =
		cf_atomic64_get(status->rec_count_total);
	state->backup_global_status.byte_count_total =
		cf_atomic64_get(status->byte_count_total);
	state->backup_global_status.rec_count_total_committed =
		cf_atomic64_get(status->rec_count_total_committed);
	state->backup_global_status.byte_count_total_committed =
		cf_atomic64_get(status->byte_count_total_committed);
}

void
backup_state_load_global_status(const backup_state_t* state,
		backup_status_t* status)
{
	status->index_count = state->backup_global_status.index_count;
	status->udf_count = state->backup_global_status.udf_count;

	cf_atomic64_set(&status->file_count, state->backup_global_status.file_count);
	cf_atomic64_set(&status->rec_count_total, state->backup_global_status.rec_count_total);
	cf_atomic64_set(&status->byte_count_total, state->backup_global_status.byte_count_total);
	cf_atomic64_set(&status->rec_count_total_committed,
			state->backup_global_status.rec_count_total_committed);
	cf_atomic64_set(&status->byte_count_total_committed,
			state->backup_global_status.byte_count_total_committed);
}

bool
backup_state_save_file(backup_state_t* state, const char* file_name, io_proxy_t* file,
		uint64_t rec_count_file)
{
	backup_state_file_t data = {
		.io_proxy = file,
		.file_name = safe_strdup(file_name),
		.rec_count_file = rec_count_file
	};

	if (data.file_name == NULL) {
		err("Unable to duplicate file name string");
		return false;
	}

	as_vector_append(&state->files, &data);

	return true;
}


//==========================================================
// Local helpers.
//

static uint8_t
_get_status(const backup_state_partitions_t* cont, uint16_t part_id)
{
	uint64_t idx = part_id / (8 / BACKUP_STATE_STATUS_BITS);
	uint8_t bitv_idx = part_id % (8 / BACKUP_STATE_STATUS_BITS);

	uint8_t bitv = cont->status[idx];
	return (uint8_t) ((bitv >> (BACKUP_STATE_STATUS_BITS * bitv_idx)) &
			((1u << BACKUP_STATE_STATUS_BITS) - 1));
}

static void
_set_status(backup_state_partitions_t* cont, uint16_t part_id, uint8_t status)
{
	uint64_t idx = part_id / (8 / BACKUP_STATE_STATUS_BITS);
	uint8_t bitv_idx = part_id % (8 / BACKUP_STATE_STATUS_BITS);

	uint8_t bitv = cont->status[idx];
	bitv |= (uint8_t) (status << (BACKUP_STATE_STATUS_BITS * bitv_idx));
	cont->status[idx] = bitv;
}

static void
_clear_status(backup_state_partitions_t* cont, uint16_t part_id)
{
	uint64_t idx = part_id / (8 / BACKUP_STATE_STATUS_BITS);
	uint8_t bitv_idx = part_id % (8 / BACKUP_STATE_STATUS_BITS);

	uint8_t bitv = cont->status[idx];
	bitv &= (uint8_t)
		~(BACKUP_STATE_STATUS_MASK << (BACKUP_STATE_STATUS_BITS * bitv_idx));
	cont->status[idx] = bitv;
}

static bool
_validate_backup_state(const backup_state_t* state)
{
	static const as_digest_value zero_digest = { 0 };

	const backup_state_partitions_t* cont = &state->partitions;
	const as_vector* files = &state->files;

	for (uint16_t pid = 0; pid < MAX_PARTITIONS; pid++) {
		uint8_t status = _get_status(cont, pid);
		const as_digest_value* digest;
		uint32_t digest_pid;

		switch (status) {
			case BACKUP_STATE_STATUS_NONE:
			case BACKUP_STATE_STATUS_NOT_STARTED:
				if (memcmp(cont->digests[pid], zero_digest,
							sizeof(as_digest_value)) != 0) {
					err("Expected zero-valued digest at partition id %u", pid);
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
				}
				break;

			default:
				err("Unexpected backup state status 0x%02x", status);
				return false;
		}
	}

	for (uint32_t i = 0; i < files->size; i++) {
		const backup_state_file_t* file =
			(const backup_state_file_t*) as_vector_get((as_vector*) files, i);

		if (file->io_proxy->fd != stdout) {
			uint64_t pos = (uint64_t) ftell(file->io_proxy->fd);
			if (pos == -1UL) {
				err("Unable to read file pos from backup file %s", file->file_name);
				return false;
			}

			if (pos != file->io_proxy->byte_cnt) {
				err("File pos (%" PRIu64 ") and byte count (%" PRIu64 ") do not "
						"match in %s",
						pos, file->io_proxy->byte_cnt, file->file_name);
				return false;
			}
		}
	}

	return true;
}

static bool
_write_backup_state(const backup_state_t* state)
{
	if (fwrite(&state->partitions, 1, sizeof(backup_state_partitions_t), state->fd) !=
			sizeof(backup_state_partitions_t)) {
		err_code("Error while writing backup state partitions to file");
		return false;
	}

	if (!_write_backup_global_status(state->fd, &state->backup_global_status)) {
		return false;
	}

	if (!_write_backup_files(state->fd, &state->files)) {
		return false;
	}

	return true;
}

static bool
_write_backup_global_status(FILE* fd, const backup_global_status_t* g_state)
{
	if (!write_int64(g_state->file_count, fd)) {
		err_code("Error while writing file count to backup state");
		return false;
	}

	if (!write_int32(g_state->index_count, fd)) {
		err_code("Error while writing index count to backup state");
		return false;
	}

	if (!write_int32(g_state->udf_count, fd)) {
		err_code("Error while writing udf count to backup state");
		return false;
	}

	if (!write_int64(g_state->rec_count_total, fd)) {
		err_code("Error while writing record count total to backup state");
		return false;
	}

	if (!write_int64(g_state->byte_count_total, fd)) {
		err_code("Error while writing byte count total to backup state");
		return false;
	}

	if (!write_int64(g_state->rec_count_total_committed, fd)) {
		err_code("Error while writing record count total committed to backup state");
		return false;
	}

	if (!write_int64(g_state->byte_count_total_committed, fd)) {
		err_code("Error while writing byte count total committed to backup state");
		return false;
	}

	return true;
}

static bool
_write_backup_files(FILE* fd, const as_vector* files)
{
	for (uint32_t i = 0; i < files->size; i++) {
		const backup_state_file_t* f =
			(const backup_state_file_t*) as_vector_get((as_vector*) files, i);

		uint64_t name_len = strlen(f->file_name);

		if (!write_int64(name_len, fd)) {
			err_code("Error writing file name \"%s\" length to backup state file",
					f->file_name);
			return false;
		}

		if (fwrite(f->file_name, 1, name_len, fd) != name_len) {
			err_code("Error writing file name \"%s\" to backup state file",
					f->file_name);
			return false;
		}

		if (io_proxy_serialize(f->io_proxy, fd) != 0) {
			err_code("Error serializing io proxy for \"%s\" to backup state file",
					f->file_name);
			return false;
		}

		if (!write_int64(f->rec_count_file, fd)) {
			err_code("Error writing file record count to backup state file \"%s\"",
					f->file_name);
			return false;
		}
	}

	return true;
}

static bool
_load_backup_global_status(FILE* fd, backup_global_status_t* g_state)
{
	if (!read_int64(&g_state->file_count, fd)) {
		err_code("Error while reading file count from backup state");
		return false;
	}

	if (!read_int32(&g_state->index_count, fd)) {
		err_code("Error while reading index count from backup state");
		return false;
	}

	if (!read_int32(&g_state->udf_count, fd)) {
		err_code("Error while reading udf count from backup state");
		return false;
	}

	if (!read_int64(&g_state->rec_count_total, fd)) {
		err_code("Error while reading record count total from backup state");
		return false;
	}

	if (!read_int64(&g_state->byte_count_total, fd)) {
		err_code("Error while reading byte count total from backup state");
		return false;
	}

	if (!read_int64(&g_state->rec_count_total_committed, fd)) {
		err_code("Error while reading record count total committed from backup state");
		return false;
	}

	if (!read_int64(&g_state->byte_count_total_committed, fd)) {
		err_code("Error while reading byte count total committed from backup state");
		return false;
	}

	return true;
}

static bool
_load_backup_files(FILE* fd, as_vector* files)
{
	char* file_name;
	io_write_proxy_t* io_proxy;
	FILE* io_fd;
	uint64_t file_name_len;
	uint64_t rec_count_file;

	while (read_int64(&file_name_len, fd)) {
		file_name = cf_malloc((file_name_len + 1) * sizeof(char));
		io_proxy = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
		io_fd = NULL;

		if (file_name == NULL || io_proxy == NULL) {
			err("Unable to malloc file_name/io for backup state");
			goto cleanup_loop;
		}

		if (fread(file_name, 1, file_name_len, fd) != file_name_len) {
			err("Unable to read entire file name from backup state file");
			goto cleanup_loop;
		}
		file_name[file_name_len] = '\0';

		if (strcmp(file_name, "-") == 0) {
			io_fd = stdout;
		}
		else {
			io_fd = fopen(file_name, "a");
			if (io_fd == NULL) {
				err("Unable to open %s in append mode", file_name);
				goto cleanup_loop;
			}
		}

		if (io_proxy_deserialize(io_proxy, io_fd, fd) != 0) {
			err("Unable to deserialize io_proxy");
			goto cleanup_loop;
		}

		if (!read_int64(&rec_count_file, fd)) {
			err("Failed to read rec_count_file from backup state file");
			goto cleanup_loop;
		}

		backup_state_file_t f = {
			.io_proxy = io_proxy,
			.file_name = file_name,
			.rec_count_file = rec_count_file
		};

		as_vector_append(files, &f);

		continue;

cleanup_loop:
		if (io_fd != NULL) {
			fclose(io_fd);
		}
		cf_free(file_name);
		cf_free(io_proxy);
		return false;
	}

	return true;
}

