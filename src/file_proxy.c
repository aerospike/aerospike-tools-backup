/*
 * Copyright 2022 Aerospike, Inc.
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

#include <file_proxy.h>

#include <backup.h>
#include <backup_state.h>
#include <utils.h>


//==========================================================
// Forward Declarations.
//

/*
 * Defined in file_proxy_s3.cc
 */
extern void file_proxy_s3_shutdown();

extern off_t s3_get_file_size(const char* path);
extern bool s3_delete_object(const char* path);
extern bool s3_delete_directory(const char* path);

extern bool s3_prepare_output_file(const backup_config_t* conf,
		const char* path);
extern bool s3_scan_directory(const backup_config_t* conf,
		const backup_status_t* status, backup_state_t* backup_state,
		const char* path);
extern bool s3_get_backup_files(const char* path, as_vector* file_vec);

extern int file_proxy_s3_write_init(file_proxy_t*, const char* path,
		uint64_t max_file_size);
extern int file_proxy_s3_read_init(file_proxy_t*, const char* path);
extern int file_proxy_s3_close(file_proxy_t*, uint8_t mode);
extern int file_proxy_s3_serialize(const file_proxy_t*, file_proxy_t* dst);
extern int file_proxy_s3_deserialize(file_proxy_t*, file_proxy_t* src,
		const char* path);
extern ssize_t file_proxy_s3_get_size(file_proxy_t*);
extern int file_proxy_s3_putc(file_proxy_t*, int c);
extern size_t file_proxy_s3_write(file_proxy_t*, const void* buf, size_t count);
extern int file_proxy_s3_truncate(file_proxy_t*);
extern int file_proxy_s3_flush(file_proxy_t*);
extern int file_proxy_s3_getc(file_proxy_t*);
extern int file_proxy_s3_getc_unlocked(file_proxy_t*);
extern int file_proxy_s3_peekc_unlocked(file_proxy_t*);
extern size_t file_proxy_s3_read(file_proxy_t*, void* buf, size_t count);
extern int file_proxy_s3_eof(file_proxy_t*);

static int _file_proxy_local_write_init(file_proxy_t* f, const char* name,
		uint64_t max_file_size);
static int _file_proxy_local_read_init(file_proxy_t* f, const char* name);
static int _file_proxy_local_init_continue(file_proxy_t* f, const char* name,
		uint8_t mode, uint64_t expected_fpos);
static bool _write_mode(const file_proxy_t* f);
static bool _read_mode(const file_proxy_t* f);


//==========================================================
// Public API.
//

void
file_proxy_cloud_shutdown()
{
	file_proxy_s3_shutdown();
}

off_t
get_file_size(const char* path)
{
	off_t size;
	uint8_t file_proxy_type = (uint8_t) file_proxy_path_type(path);
	struct stat stat_buf;

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			size = s3_get_file_size(path);
			break;
		case FILE_PROXY_TYPE_LOCAL:
			if (stat(path, &stat_buf) != 0) {
				err_code("Failed to get stats of file %s", path);
				return -1;
			}

			size = stat_buf.st_size;
			break;
	}

	return size;
}

bool
file_proxy_delete_file(const char* file_path)
{
	bool res = true;
	uint8_t file_proxy_type = (uint8_t) file_proxy_path_type(file_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			res = s3_delete_object(file_path);
			break;

		case FILE_PROXY_TYPE_LOCAL:
			if (remove(file_path) < 0) {
				err_code("Error while deleting local file %s", file_path);
				return false;
			}
			break;
	}

	return res;
}

bool
file_proxy_delete_directory(const char* dir_path)
{
	bool res = true;
	uint8_t file_proxy_type = (uint8_t) file_proxy_path_type(dir_path);
	DIR* dir;
	struct dirent *entry;
	bool no_remaining_files = true;

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			res = s3_delete_directory(dir_path);
			break;

		case FILE_PROXY_TYPE_LOCAL:
			dir = opendir(dir_path);
			if (dir == NULL) {
				err_code("Error while opening local directory %s for deleting",
						dir_path);
				return false;
			}

			while ((entry = readdir(dir)) != NULL) {
				if (file_proxy_is_backup_file_path(entry->d_name)) {
					char file_path[PATH_MAX];

					if ((size_t) snprintf(file_path, sizeof(file_path), "%s/%s",
								dir_path, entry->d_name) >= sizeof(file_path)) {
						err("File path too long (%s/%s)", dir_path,
								entry->d_name);
						closedir(dir);
						return false;
					}

					if (!file_proxy_delete_file(file_path)) {
						closedir(dir);
						return false;
					}
				}
				else if (strcmp(entry->d_name, ".") != 0 &&
						strcmp(entry->d_name, "..") != 0) {
					// found an entry that we won't be deleting, so don't
					// attempt to delete the directory afterward.
					no_remaining_files = false;
				}
			}

			if (closedir(dir) < 0) {
				err_code("Error while closing directory handle for %s", dir_path);
				return false;
			}

			if (no_remaining_files && rmdir(dir_path) < 0) {
				err_code("Error while removing empty directory %s", dir_path);
			}
			break;
	}

	return res;
}

int
file_proxy_write_init(file_proxy_t* f, const char* full_path,
		uint64_t max_file_size)
{
	int res;
	uint8_t file_proxy_type = (uint8_t) file_proxy_path_type(full_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			res = file_proxy_s3_write_init(f, full_path, max_file_size);
			break;

		case FILE_PROXY_TYPE_LOCAL:
			res = _file_proxy_local_write_init(f, full_path, max_file_size);
			break;
	}

	if (res == 0) {
		f->file_path = safe_strdup(full_path);
		f->flags = file_proxy_type | FILE_PROXY_WRITE_MODE;
		f->fpos = 0;
	}

	return res;
}

int
file_proxy_read_init(file_proxy_t* f, const char* full_path)
{
	int res;
	uint8_t file_proxy_type = (uint8_t) file_proxy_path_type(full_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			res = file_proxy_s3_read_init(f, full_path);
			break;

		case FILE_PROXY_TYPE_LOCAL:
			res = _file_proxy_local_read_init(f, full_path);
			break;
	}

	if (res == 0) {
		f->file_path = safe_strdup(full_path);
		f->flags = file_proxy_type | FILE_PROXY_READ_MODE;
		f->fpos = 0;
	}

	return res;
}

int
file_proxy_close(file_proxy_t* f)
{
	uint8_t mode = FILE_PROXY_EOF;

	if (file_proxy_get_mode(f) != FILE_PROXY_READ_MODE) {
		err("Can only close read file proxies without specifying the mode to "
				"close it in");
		return -1;
	}

	return file_proxy_close2(f, mode);
}

int
file_proxy_close2(file_proxy_t* f, uint8_t mode)
{
	int ret;
	int32_t fno;

	if (f->fpos == 0 && mode == FILE_PROXY_EOF) {
		// don't save empty files
		mode = FILE_PROXY_ABORT;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			if (file_proxy_is_std_path(f->file_path)) {
				return 0;
			}

			fno = fileno(f->local.fd);

			if (fno < 0) {
				err("Error while retrieving native file descriptor");
				return EOF;
			}

			// errno = EINVAL happens when "/dev/null" is the output file, which
			// doesn't support synchronization
			if (fsync(fno) < 0 && errno != EINVAL) {
				err("Error while flushing kernel buffers");
				return EOF;
			}

			ret = fclose(f->local.fd);

			if (mode == FILE_PROXY_ABORT) {
				unlink(f->file_path);
			}
			break;
		case FILE_PROXY_TYPE_S3:
			ret = file_proxy_s3_close(f, mode);
			break;
		default:
			err("Unknown file proxy type %u", file_proxy_get_type(f));
			return EOF;
	}

	if (ret == 0) {
		cf_free(f->file_path);
	}

	return ret;
}

int
file_proxy_serialize(const file_proxy_t* f, file_proxy_t* dst)
{
	file_proxy_serial_t data = {
		.fpos = htobe64(f->fpos),
		.flags = f->flags
	};
	uint64_t file_name_len = strlen(f->file_path);

	if (file_proxy_is_std_path(f->file_path)) {
		data.fpos = 0;
	}

	if (file_proxy_write(dst, &data, sizeof(data)) != sizeof(data)) {
		err("Failed to write serialized metadata for file proxy");
	}

	if (!write_int64(file_name_len, dst)) {
		err("Failed to write file name length for serialized file proxy");
		return -1;
	}

	if (file_proxy_write(dst, f->file_path, file_name_len) != file_name_len) {
		err("Failed to write file name for serialized file proxy");
		return -1;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			return 0;

		case FILE_PROXY_TYPE_S3:
			return file_proxy_s3_serialize(f, dst);

		default:
			err("Unknown file proxy type %u", file_proxy_get_type(f));
			return -1;
	}
}

int
file_proxy_deserialize(file_proxy_t* f, file_proxy_t* src)
{
	int res;

	file_proxy_serial_t data;
	uint64_t fpos;
	char* file_name;
	uint64_t file_name_len;

	if (file_proxy_read(src, &data, sizeof(data)) != sizeof(data)) {
		err("Failed to read serialized metadata for io proxy");
		return -1;
	}
	fpos = be64toh(data.fpos);

	if (!read_int64(&file_name_len, src)) {
		err("Failed to read file name length for serialized io proxy");
		return -1;
	}

	file_name = cf_malloc((file_name_len + 1) * sizeof(char));
	if (file_name == NULL) {
		err("Failed to allocate %" PRIu64 " bytes for deserialized file_proxy "
				"file name",
				file_name_len);
		return -1;
	}

	if (file_proxy_read(src, file_name, file_name_len) != file_name_len) {
		err("Unable to read file name of serialized io proxy");
		cf_free(file_name);
		return -1;
	}
	file_name[file_name_len] = '\0';

	// fully initialize the base file_proxy_t before initializing the specific
	// type, so the specific constructors may use fields in the base
	// file_proxy_t
	f->file_path = file_name;
	f->flags = data.flags;
	f->fpos = fpos;

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = _file_proxy_local_init_continue(f, file_name,
					FILE_PROXY_WRITE_MODE, fpos);
			break;

		case FILE_PROXY_TYPE_S3:
			res = file_proxy_s3_deserialize(f, src, file_name);
			break;

		default:
			err("Unknown file proxy type %u", file_proxy_get_type(f));
			cf_free(file_name);
			return -1;
	}

	if (res != 0) {
		cf_free(file_name);
	}

	return res;
}

uint8_t
file_proxy_get_type(const file_proxy_t* f)
{
	return f->flags & FILE_PROXY_TYPE_MASK;
}

uint8_t
file_proxy_get_mode(const file_proxy_t* f)
{
	return f->flags & FILE_PROXY_MODE_MASK;
}

int64_t
file_proxy_tellg(const file_proxy_t* f)
{
	return (int64_t) f->fpos;
}

const char*
file_proxy_path(const file_proxy_t* f)
{
	return f->file_path;
}

ssize_t
file_proxy_get_size(file_proxy_t* f)
{
	struct stat stat_buf;
	ssize_t size;

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			if (stat(f->file_path, &stat_buf) < 0) {
				err_code("Error while determining backup file size for %s",
						f->file_path);
				size = -1;
			}
			else {
				size = stat_buf.st_size;
			}
			break;

		case FILE_PROXY_TYPE_S3:
			size = file_proxy_s3_get_size(f);
			break;

		default:
			err("Unknown file proxy type %u", file_proxy_get_type(f));
			return -1;
	}

	return size;
}

int
file_proxy_putc(file_proxy_t* f, int c)
{
	int res;

	if (UNLIKELY(!_write_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = putc(c, f->local.fd);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
	f->fpos += (res != EOF) ? 1 : 0;
	return res;
}

int
file_proxy_putc_unlocked(file_proxy_t* f, int c)
{
	int res;

	if (UNLIKELY(!_write_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = putc_unlocked(c, f->local.fd);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
	f->fpos += (res != EOF) ? 1 : 0;
	return res;
}

size_t
file_proxy_write(file_proxy_t* f, const void* buf, size_t count)
{
	size_t bytes_written;

	if (UNLIKELY(!_write_mode(f))) {
		err("not in write mode");
		return 0;
	}

	ver_code("file_proxy_write attempting fwrite of %zu bytes", count);

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			bytes_written = fwrite(buf, 1, count, f->local.fd);
			break;
		case FILE_PROXY_TYPE_S3:
			bytes_written = file_proxy_s3_write(f, buf, count);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return 0;
	}
	
	ver_code("file_proxy_write bytes written: %zu", bytes_written);
	f->fpos += bytes_written;
	return bytes_written;
}

int
file_proxy_truncate(file_proxy_t* f)
{
	int ret;
	int32_t fno;

	if (UNLIKELY(!_write_mode(f))) {
		return -1;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			fno = fileno(f->local.fd);
			if (fno < 0) {
				err("Error while retrieving native file descriptor");
				return -1;
			}
			ret = ftruncate(fno, 0);
			break;
		case FILE_PROXY_TYPE_S3:
			ret = file_proxy_s3_truncate(f);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return 0;
	}

	if (ret == 0) {
		f->fpos = 0;
	}
	return ret;
}

int
file_proxy_flush(file_proxy_t* f)
{
	int ret;
	if (UNLIKELY(!_write_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			ret = fflush(f->local.fd);
			break;
		case FILE_PROXY_TYPE_S3:
			ret = file_proxy_s3_flush(f);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
<<<<<<< Updated upstream
=======

	ver_code("file_proxy_flush fflush returned: %d", ret);
>>>>>>> Stashed changes
	return ret;
}

/*
 * Each of the following functions are only implemented for local file proxies.
 */
int
file_proxy_getc(file_proxy_t* f)
{
	int res;

	if (UNLIKELY(!_read_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = getc(f->local.fd);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
	f->fpos += (res != EOF) ? 1 : 0;
	return res;
}

int
file_proxy_getc_unlocked(file_proxy_t* f)
{
	int res;

	if (UNLIKELY(!_read_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = getc_unlocked(f->local.fd);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
	f->fpos += (res != EOF) ? 1 : 0;
	return res;
}

int
file_proxy_peekc_unlocked(file_proxy_t* f)
{
	int res;

	if (UNLIKELY(!_read_mode(f))) {
		return EOF;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			res = getc_unlocked(f->local.fd);
			ungetc(res, f->local.fd);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return EOF;
	}
	return res;
}

size_t
file_proxy_read(file_proxy_t* f, void* buf, size_t count)
{
	size_t bytes_read;

	if (UNLIKELY(!_read_mode(f))) {
		return 0;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			bytes_read = fread(buf, 1, count, f->local.fd);
			break;
		case FILE_PROXY_TYPE_S3:
			bytes_read = file_proxy_s3_read(f, buf, count);
			break;
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return 0;
	}
	f->fpos += bytes_read;
	return bytes_read;
}

int
file_proxy_eof(file_proxy_t* f)
{
	if (UNLIKELY(!_read_mode(f))) {
		// EOF is never reached for files in write mode.
		return 0;
	}

	switch (file_proxy_get_type(f)) {
		case FILE_PROXY_TYPE_LOCAL:
			return feof(f->local.fd);
		case FILE_PROXY_TYPE_S3:
			return file_proxy_s3_eof(f);
		default:
			err("Unknown file type %u", file_proxy_get_type(f));
			return 0;
	}
}

char*
gen_backup_state_file_path(const backup_config_t* conf)
{
	const char* prefix;
	int32_t prefix_len;
	char* backup_state_file;
	uint8_t file_proxy_type;
	
	if (conf->output_file != NULL) {
		file_proxy_type = file_proxy_path_type(conf->output_file);
	}
	else if (conf->directory != NULL) {
		file_proxy_type = file_proxy_path_type(conf->directory);
	}
	else {
		err("Cannot generate backup state file name if not backing up to "
				"directory/output file");
		return NULL;
	}

	if (conf->prefix != NULL) {
		prefix = conf->prefix;
		prefix_len = (int32_t) strlen(prefix);
	}
	else {
		prefix = conf->ns;
		prefix_len = (int32_t) strnlen(conf->ns, sizeof(as_namespace));
	}

	if (conf->state_file_dst != NULL) {
		if (file_proxy_path_type(conf->state_file_dst) != FILE_PROXY_TYPE_LOCAL) {
			// no need to verify anything if the state file dst is on the cloud
			backup_state_file = safe_strdup(conf->state_file_dst);
		}
		else {
			// for local state_file_dst, check if it is a directory
			DIR *dir = opendir(conf->state_file_dst);

			if (dir == NULL) {
				// this is not a path to an existing directory, assume it is a path
				// to a new file and verify that it can be created or already exists
				int fd = open(conf->state_file_dst, O_WRONLY | O_CREAT | O_EXCL,
						S_IRUSR | S_IWUSR);

				if (fd == -1) {
					// if the file already exists, this is no problem, we will just
					// overwrite it. Check for any other kind of error
					if (errno != EEXIST) {
						err("Failed to open state file \"%s\", reason: %s",
								conf->state_file_dst, strerror(errno));
						return NULL;
					}

					// we still need to try opening the file to see if we have
					// permission to overwrite it
					fd = open(conf->state_file_dst, O_WRONLY);

					if (fd == -1) {
						err("Failed to open state file \"%s\", reason: %s",
								conf->state_file_dst, strerror(errno));
						return NULL;
					}

					close(fd);
				}
				else {
					close(fd);
					unlink(conf->state_file_dst);
				}

				backup_state_file = safe_strdup(conf->state_file_dst);
			}
			else {
				// state_file_dst points to a directory, so generate a path to a
				// file in this directory that we will write the backup state to
				closedir(dir);

				backup_state_file = dyn_sprintf("%s/%.*s.asb.state",
						conf->state_file_dst, prefix_len, prefix);
			}
		}
	}
	else if (file_proxy_type != FILE_PROXY_TYPE_LOCAL) {
		backup_state_file = dyn_sprintf("%.*s.asb.state", prefix_len, prefix);
	}
	else {
		if (conf->directory != NULL) {
			backup_state_file = dyn_sprintf("%s/%.*s.asb.state",
					conf->directory, prefix_len, prefix);
		}
		else if (conf->output_file != NULL) {
			if (file_proxy_is_std_path(conf->output_file)) {
				backup_state_file = dyn_sprintf("%.*s.asb.state", prefix_len,
						prefix);
			}
			else {
				backup_state_file = dyn_sprintf("%s.state", conf->output_file);
			}
		}
		else {
			// running in estimate mode, no need to save the backup state
			return NULL;
		}
	}

	return backup_state_file;
}

bool
prepare_output_file(const backup_config_t* conf)
{
	const char* file_path = conf->output_file;

	uint8_t file_proxy_type = file_proxy_path_type(file_path);
	struct stat buf;

	ver("Checking output file %s", file_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			if (!s3_prepare_output_file(conf, file_path)) {
				return false;
			}
			break;

		case FILE_PROXY_TYPE_LOCAL:
			if (file_proxy_is_std_path(file_path)) {
				return true;
			}

			if (stat(file_path, &buf) < 0) {
				if (errno == ENOENT) {
					return true;
				}

				err_code("Error while checking output file %s", file_path);
				return false;
			}

			if (!conf->remove_files) {
				err("Output file %s already exists; use -r to remove", file_path);
				return false;
			}

			if (!file_proxy_delete_file(file_path)) {
				return false;
			}
			break;
	}

	return true;
}

bool
prepare_directory(const backup_config_t* conf)
{
	const char* dir_path = conf->directory;

	uint8_t file_proxy_type = file_proxy_path_type(dir_path);
	DIR* dir;

	ver("Preparing backup directory %s", dir_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			// a noop for S3, no such concept as a "directory"
			break;

		case FILE_PROXY_TYPE_LOCAL:
			dir = opendir(dir_path);

			if (dir == NULL) {
				if (errno != ENOENT) {
					err_code("Error while opening directory %s", dir_path);
					return false;
				}

				inf("Directory %s does not exist, creating", dir_path);

				if (mkdir(dir_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
					err_code("Error while creating directory %s", dir_path);
					return false;
				}
			}
			else if (closedir(dir) < 0) {
				err_code("Error while closing directory handle for %s", dir_path);
				return false;
			}
			break;
	}

	inf("Directory %s prepared for backup", dir_path);
	return true;
}

bool
scan_directory(const backup_config_t* conf, const backup_status_t* status,
		backup_state_t* backup_state)
{
	const char* dir_path = conf->directory;

	uint8_t file_proxy_type = file_proxy_path_type(dir_path);
	DIR* dir;
	struct dirent *entry;
	uint64_t file_count = 0;
	uint64_t incomplete_file_count = 0;

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			if (!s3_scan_directory(conf, status, backup_state, dir_path)) {
				return false;
			}
			break;

		case FILE_PROXY_TYPE_LOCAL:
			dir = opendir(dir_path);
			if (dir == NULL) {
				err_code("Error while opening directory %s for scanning/clearing",
						dir_path);
				return false;
			}

			while ((entry = readdir(dir)) != NULL) {
				if (file_proxy_is_backup_file_path(entry->d_name)) {
					char file_path[PATH_MAX];

					if ((size_t) snprintf(file_path, sizeof(file_path), "%s/%s",
								dir_path, entry->d_name) >= sizeof(file_path)) {
						err("File path too long (%s/%s)", dir_path,
								entry->d_name);
						closedir(dir);
						return false;
					}

					if (conf->remove_files) {
						if (remove(file_path) < 0) {
							err_code("Error while removing existing backup file %s",
									file_path);
							closedir(dir);
							return false;
						}
					}
					else if (conf->state_file != NULL) {
						size_t full_path_len = strlen(conf->directory) + 1 +
							strlen(entry->d_name) + 1;
						char* full_path = (char*) cf_malloc(full_path_len);

						if (full_path == NULL) {
							err("Failed to malloc %zu bytes for full path",
									full_path_len);
							return false;
						}

						snprintf(full_path, full_path_len, "%s/%s",
								conf->directory, entry->d_name);

						if (backup_state_contains_file(backup_state,
									full_path)) {
							incomplete_file_count++;
						}

						cf_free(full_path);
						file_count++;
					}
					else {
						err("Directory %s seems to contain an existing backup; "
								"use -r to clear directory", dir_path);
						closedir(dir);
						return false;
					}
				}
			}

			if (conf->state_file != NULL) {
				if (incomplete_file_count != backup_state->files.size) {
					err("Expected %u incomplete backup files per the backup "
							"state, but found %" PRIu64,
							backup_state->files.size, incomplete_file_count);
					return false;
				}

				if (file_count != status->file_count) {
					err("Expected %" PRIu64 " backup files, but found %" PRIu64,
							status->file_count, file_count);
					return false;
				}
			}

			if (closedir(dir) < 0) {
				err_code("Error while closing directory handle for %s", dir_path);
				return false;
			}
			break;
	}

	return true;
}

uint64_t
disk_space_remaining(const char *dir)
{
	uint8_t file_proxy_type = file_proxy_path_type(dir);
	struct statvfs buf;

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			// There is no limit to how much storage space you can use in S3.
			return ULONG_MAX;

		case FILE_PROXY_TYPE_LOCAL:
			ver("Checking disk space on %s", dir);

			if (statvfs(dir, &buf) < 0) {
				err_code("Error while getting file system info for %s", dir);
				return 0;
			}

#ifdef __APPLE__
			size_t available = buf.f_bavail * buf.f_frsize;
#else
			size_t available = buf.f_bavail * buf.f_bsize;
#endif /* __APPLE__ */

			return available;

		default:
			// this isn't possible
			return 0;
	}
}

bool
get_backup_files(const char *dir_path, as_vector *file_vec)
{
	uint8_t file_proxy_type = file_proxy_path_type(dir_path);
	bool res;
	DIR* dir;
	struct dirent* entry;

	ver("Listing backup files in %s", dir_path);

	switch (file_proxy_type) {
		case FILE_PROXY_TYPE_S3:
			res = s3_get_backup_files(dir_path, file_vec);
			break;

		case FILE_PROXY_TYPE_LOCAL:
			res = false;
			dir = opendir(dir_path);

			if (dir == NULL) {
				if (errno == ENOENT) {
					err("Directory %s does not exist", dir_path);
					return false;
				}

				err_code("Error while opening directory %s", dir_path);
				return false;
			}

			while ((entry = readdir(dir)) != NULL) {
				if (file_proxy_is_backup_file_path(entry->d_name)) {
					char file_path[PATH_MAX];
					size_t length;

					if ((length = (size_t)snprintf(file_path, sizeof(file_path),
									"%s/%s", dir_path, entry->d_name)) >= sizeof(file_path)) {
						err("File path too long (%s, %s)", dir_path, entry->d_name);
						goto cleanup;
					}

					char *elem = safe_malloc(length + 1);
					if (elem == NULL) {
						err("Failed to malloc space for file name %s", file_path);
						goto cleanup;
					}

					memcpy(elem, file_path, length + 1);
					as_vector_append(file_vec, &elem);
				}
			}

			inf("Found %u backup file(s) in %s", file_vec->size, dir_path);
			res = true;

cleanup:
			if (closedir(dir) < 0) {
				err_code("Error while closing directory handle for %s", dir_path);
				res = false;
			}

			if (!res) {
				for (uint32_t i = 0; i < file_vec->size; ++i) {
					cf_free(as_vector_get_ptr(file_vec, i));
				}

				as_vector_clear(file_vec);
			}

			break;
	}

	return res;
}

bool
file_proxy_is_std_path(const char* path)
{
	return strcmp(path, "-") == 0;
}

uint8_t
file_proxy_path_type(const char* path)
{
	if (strncasecmp(path, S3_PREFIX, S3_PREFIX_LEN) == 0) {
		return FILE_PROXY_TYPE_S3;
	}
	else {
		return FILE_PROXY_TYPE_LOCAL;
	}
}

bool
file_proxy_is_backup_file_path(const char* path)
{
	size_t path_len = strlen(path);
	return path_len > 4 && strcmp(path + path_len - 4, ".asb") == 0;
}


//==========================================================
// Local Helpers.
//

/*
 * Opens a local file, returning a pointer to the file stream or NULL on error.
 */
static FILE*
_open_local_file(const char* path, uint8_t mode, const char* mode_str)
{
	FILE* fd;

	if (file_proxy_is_std_path(path)) {

		if (mode == FILE_PROXY_READ_MODE) {
			int stdin_copy = dup(STDIN_FILENO);
			if (stdin_copy < 0) {
				err_code("Unable to duplicate stdin file descriptor");
				return NULL;
			}

			fd = fdopen(stdin_copy, mode_str);

			if (fd == NULL) {
				err("Failed to open stdin in \"%s\" mode", mode_str);
				close(stdin_copy);
				return NULL;
			}
		}
		else {
			int stdout_copy = dup(STDOUT_FILENO);
			if (stdout_copy < 0) {
				err_code("Unable to duplicate stdout file descriptor");
				return NULL;
			}

			fd = fdopen(stdout_copy, mode_str);

			if (fd == NULL) {
				err("Failed to open stdout in \"%s\" mode", mode_str);
				close(stdout_copy);
				return NULL;
			}
		}
	}
	else {
		fd = fopen(path, mode_str);

		if (fd == NULL) {
			err_code("Failed to open file %s in \"%s\" mode", path, mode_str);
			return NULL;
		}
	}

	return fd;
}

static int
_file_proxy_local_write_init(file_proxy_t* f, const char* name,
		uint64_t max_file_size)
{
	FILE* fd;

	fd = _open_local_file(name, FILE_PROXY_WRITE_MODE, "w");
	if (fd == NULL) {
		return -1;
	}

	char *tmp_path = safe_strdup(name);
	char *dir_path = dirname(tmp_path);
	uint64_t disk_space = disk_space_remaining(dir_path);
	cf_free(tmp_path);

	if (disk_space < max_file_size) {
		inf("Warning: %" PRIu64 " bytes of disk space remaining, but expected "
				"file size is %" PRIu64 " bytes",
				disk_space, max_file_size);
	}

	f->local.fd = fd;

	return 0;
}

static int
_file_proxy_local_read_init(file_proxy_t* f, const char* name)
{
	FILE* fd;

	fd = _open_local_file(name, FILE_PROXY_READ_MODE, "r");
	if (fd == NULL) {
		return -1;
	}

	f->local.fd = fd;

	return 0;
}

/*
 * Open a file continuing to read/write from <expected_fpos>.
 */
static int
_file_proxy_local_init_continue(file_proxy_t* f, const char* name,
		uint8_t mode, uint64_t expected_fpos)
{
	FILE* fd;
	const char* mode_str;
	long int fpos;

	switch (mode) {
		case FILE_PROXY_WRITE_MODE:
			mode_str = "a";
			break;
		case FILE_PROXY_READ_MODE:
			mode_str = "r";
			break;
		default:
			err("Unknown file proxy mode %u", mode);
			return -1;
	}

	fd = _open_local_file(name, mode, mode_str);
	if (fd == NULL) {
		return -1;
	}

	if (file_proxy_is_std_path(name)) {
		if (mode == FILE_PROXY_WRITE_MODE && expected_fpos != 0) {
			err("Expected file pos must be 0 when opening a file in write "
					"mode");
			return -1;
		}
	}
	else {
		switch (mode) {
			case FILE_PROXY_WRITE_MODE:
				fpos = ftell(fd);

				if (fpos < 0) {
					err_code("Unable to read file pos from file");
					return -1;
				}
				if ((uint64_t) fpos != expected_fpos) {
					err("Expected file pos (%" PRIu64 ") did not match file pos "
							"(%ld) for file (%s) opened in append mode",
							expected_fpos, fpos, f->file_path);
					return -1;
				}
				break;

			case FILE_PROXY_READ_MODE:
				if (fseek(fd, (long int) expected_fpos, SEEK_SET) < 0) {
					err_code("Unable to set the file pos");
					return -1;
				}
				break;

			default:
				__builtin_unreachable();
		}
	}

	f->local.fd = fd;

	return 0;
}

static bool
_write_mode(const file_proxy_t* f)
{
	return file_proxy_get_mode(f) == FILE_PROXY_WRITE_MODE;
}

static bool
_read_mode(const file_proxy_t* f)
{
	return file_proxy_get_mode(f) == FILE_PROXY_READ_MODE;
}

/*
 * Converts a full path (s3:<s3_path>) to an S3 path (i.e. bucket and key)
 */
static bool
_path_to_s3_path(const char* path, const char* g_bucket, char** bucket,
		char** key)
{
	char* s3_path = safe_strdup(path + S3_PREFIX_LEN);
	if (s3_path == NULL) {
		err("Failed to strdup path %s", path);
		return false;
	}

	/*
	char* delim = strchr(s3_path, '/');
	if (delim == NULL) {
		err("Expected '/<key>' after bucket name in S3 file %s", path);
		cf_free(s3_path);
		return false;
	}
	if (delim == s3_path) {
		err("Must specify a bucket after " S3_PREFIX " before the first '/'");
		cf_free(s3_path);
		return false;
	}

	// null-terminate the bucket name
	*delim = '\0';
	// increment delim until it no longer points to a '/'
	while (*(++delim) == '/');

	*bucket = s3_path;
	*key = delim;
	*/
	*key = s3_path;
	return true;
}

static void
_free_s3_path(char* bucket, char* key)
{
	(void) key;
	//char* s3_path = bucket;
	char* s3_path = key;

	cf_free(s3_path);
}

