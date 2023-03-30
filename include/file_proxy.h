/*
 * Aerospike File Proxy
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <aerospike/as_vector.h>

// Forward declare backup_config/backup_status/backup_state since they can't be
// included
typedef struct backup_config backup_config_t;
typedef struct backup_status backup_status_t;
typedef struct backup_state backup_state_t;


//==========================================================
// Typedefs & Constants.
//

#define S3_PREFIX "s3://"
#define S3_PREFIX_LEN (sizeof(S3_PREFIX) - 1)

// min part size is 5 MB
#define S3_MIN_PART_SIZE (5lu * 1024 * 1024)
// max part size is 5 GB
#define S3_MAX_PART_SIZE (5lu * 1024 * 1024 * 1024)
// the max number of UploadPart requests that can be made for a single file
#define S3_MAX_N_PARTS 10000
// the max size that an S3 object can be
#define S3_MAX_OBJECT_SIZE (5lu * 1024 * 1024 * 1024 * 1024)

#define S3_DEFAULT_MAX_ASYNC_UPLOADS 16
#define S3_DEFAULT_MAX_ASYNC_DOWNLOADS 32

#define S3_DEFAULT_LOG_LEVEL ((s3_log_level_t) Fatal)

/*
 * Defines where the file is stored, either locally or in the cloud.
 */
#define FILE_PROXY_TYPE_LOCAL 0x0
#define FILE_PROXY_TYPE_S3    0x1

#define FILE_PROXY_TYPE_MASK  0x1

/*
 * The mode that the file proxy was opened in.
 */
#define FILE_PROXY_WRITE_MODE 0x0
#define FILE_PROXY_READ_MODE  0x2

#define FILE_PROXY_MODE_MASK  0x2


// the file is finished and can be committed (to the cloud)
#define FILE_PROXY_EOF 0
// the file is incomplete
#define FILE_PROXY_CONTINUE 1
// the file should be deleted and not saved
#define FILE_PROXY_ABORT 2

#ifdef __cplusplus

typedef class StreamManager s3_state_t;

extern "C" {

#else
/*
 * opaque because this is defined as a C++ class in src/file_proxy_s3.cc
 */
typedef void s3_state_t;

#endif /* __cplusplus */

/*
 * LogLevel used to control verbosity of the AWS S3 C++ SDK logging system.
 */
typedef enum s3_log_level
{
	Off = 0,
	Fatal = 1,
	Error = 2,
	Warn = 3,
	Info = 4,
	Debug = 5,
	Trace = 6
} s3_log_level_t;

typedef struct local_file_s {
	FILE* fd;
} local_file_t;

typedef struct s3_file_s {
	s3_state_t* s3_state;
} s3_file_t;

typedef struct file_proxy_s {
	// the path to the file being proxied
	char* file_path;

	uint8_t flags;

	// The number of bytes that have been written to the file
	uint64_t fpos;

	union {
		local_file_t local;
		s3_file_t s3;
	};
} file_proxy_t;

typedef struct __attribute__((packed)) file_proxy_serial_s {
	uint64_t fpos;
	uint8_t flags;
} file_proxy_serial_t;


//==========================================================
// Public API.
//

/*
 * Parses the log level in string format, populating log_level or returning
 * false on error.
 */
bool s3_parse_log_level(const char* log_level_str, s3_log_level_t* log_level);

/*
 * Sets the S3 region to use.
 */
void s3_set_region(const char* region);

/*
 * Sets the S3 bucket to use.
 */
void s3_set_bucket(const char* bucket);

/*
 * Sets the AWS profile to use for credentials.
 */
void s3_set_profile(const char* profile);

/*
 * Sets the S3 endpoint to use. The default is the default AWS S3 URI, but it
 * may be replaced by S3 compatible storage.
 */
void s3_set_endpoint(const char* endpoint);

/*
 * Sets the respective max allowed simultaneous async downloads/uploads to S3.
 */
void s3_set_max_async_downloads(uint32_t max_async_downloads);
void s3_set_max_async_uploads(uint32_t max_async_uploads);

/*
 * Sets the logging level of the AWS c++ sdk.
 */
void s3_set_log_level(s3_log_level_t log_level);

/*
 * Immediately stop all async S3 requests currently being processed.
 */
void s3_disable_request_processing();

/*
 * Must be called just before exit, shuts down and cleans up all cloud API
 * instances.
 */
void file_proxy_cloud_shutdown();

/*
 * Delete a file given a path to the file. May be a local or cloud file.
 */
bool file_proxy_delete_file(const char* path);

/*
 * Delete all "*.asb" files under a directory, and the directory if it is empty
 * after this operation.
 */
bool file_proxy_delete_directory(const char* path);

/*
 * Initialized a file proxy given its full path and mode. max_file_size is the
 * max expected file size of the file. If set to 0, no disk space check is done,
 * and the minimum allowable S3 part size is used.
 *
 * If the full path begins with "s3://", the path that follows is interpreted as
 *
 *  "s3://<bucket>/<key>"
 *
 * where <bucket> is the name of the AWS S3 bucket we'll be
 * uploading to/downloading from, and <key> is the key of the object in that
 * bucket.
 */
int file_proxy_read_init(file_proxy_t*, const char* full_path);
int file_proxy_write_init(file_proxy_t*, const char* full_path, uint64_t max_file_size);

/*
 * Closes the file proxy and frees all resourced associated with it. If this
 * returns non-zero, the file_proxy is still in a valid state and hasn't been
 * closed.
 *
 * You may close read file proxies with file_proxy_close, but you have to use
 * file_proxy_close2 for write proxies to specify how the file should be closed.
 *
 * mode is the manner in which it is closed, which is one of:
 *  FILE_PROXY_EOF: the file is finished and can be committed (to the cloud)
 *  FILE_PROXY_CONTINUE: the file is incomplete
 *  FILE_PROXY_ABORT: the file should be deleted and not saved
 */
int file_proxy_close(file_proxy_t*);
int file_proxy_close2(file_proxy_t*, uint8_t mode);

/*
 * Serializes a file_proxy into file, returning 0 on success and < 0 on failure.
 */
int file_proxy_serialize(const file_proxy_t*, file_proxy_t* dst);

/*
 * Deserializes a file_proxy from the file, fully initializing the file_proxy.
 *
 * Returns 0 on success and < 0 on failure.
 */
int file_proxy_deserialize(file_proxy_t*, file_proxy_t* src);

/*
 * Returns the type of the file proxy (i.e. local, s3, etc.).
 */
uint8_t file_proxy_get_type(const file_proxy_t*);

/*
 * Returns the mode the file proxy was opened in (read or write).
 */
uint8_t file_proxy_get_mode(const file_proxy_t*);

/*
 * Returns the number of bytes that have been written to the file proxy.
 */
int64_t file_proxy_tellg(const file_proxy_t*);

/*
 * Returns the file path used to open this file proxy
 */
const char* file_proxy_path(const file_proxy_t*);

/*
 * Returns the size in bytes of the file being proxied (filesystem file or S3
 * object).
 *
 * Returns -1 on error.
 */
ssize_t file_proxy_get_size(file_proxy_t*);

/*
 * Writes a single byte to the file proxy.
 */
int file_proxy_putc(file_proxy_t*, int c);

/*
 * Writes a single byte to the file proxy.
 */
int file_proxy_putc_unlocked(file_proxy_t*, int c);

/*
 * Writes to the file proxy.
 */
size_t file_proxy_write(file_proxy_t*, const void* buf, size_t count);

/*
 * Truncates the file proxy, i.e. erases all the contents of it.
 */
int file_proxy_truncate(file_proxy_t*);

/*
 * Flushes the file proxy
 */
int file_proxy_flush(file_proxy_t*);

/*
 * Reads a single byte from the file proxy.
 */
int file_proxy_getc(file_proxy_t*);

/*
 * Reads a single byte from the file proxy.
 */
int file_proxy_getc_unlocked(file_proxy_t*);

/*
 * Reads the next byte from the file proxy without advancing the position in
 * the file.
 */
int file_proxy_peekc_unlocked(file_proxy_t*);

/*
 * Reads from the file proxy.
 */
size_t file_proxy_read(file_proxy_t*, void* buf, size_t count);

/*
 * Returns non-zero if EOF has been reached, otherwise 0 is returned.
 */
int file_proxy_eof(file_proxy_t*);

/*
 * Generates the path to the backup state file and verifies that the path is
 * valid (i.e. will be able to be opened if the backup fails and the state of
 * the file system does not change).
 *
 * Returns NULL on error (or if in estimate mode), otherwise a pointer to a
 * malloc-ed string of the generated file path.
 */
char* gen_backup_state_file_path(const backup_config_t* conf);

/*
 * Tests whether the given backup file exists.
 *
 * If clear is true, the file is deleted if it exists, otherwise an error is
 * printed and it returns false if it exists.
 */
bool prepare_output_file(const backup_config_t* conf);

/*
 * Prepares the given directory for a backup, creating the directory if it
 * doesn't exist.
 */
bool prepare_directory(const backup_config_t* conf);

/*
 * Scans the directory, doing one of the following:
 *  If !clear && !resume, checks that it contains no '.asb' files.
 *  If clear && !resume, removes all '.asb' files.
 *  If !clear && resume, sets file_count to the number of '.asb' files found.
 */
bool scan_directory(const backup_config_t* conf, const backup_status_t* status,
		backup_state_t* backup_state);

/*
 * Returns the number of remaining bytes available in the given directory.
 *
 * A return value of 0 indicates failure, and ULONG_MAX indicates infinity
 * (i.e. for cloud backups).
 */
uint64_t disk_space_remaining(const char *dir);

/*
 * Scans the given directory for backup files, populating file_vec with the
 * names of the files, as a vector of strings.
 * It returns the total size of all files added together in bytes.
 * Return values < 0 indicate an error.
 */
off_t get_backup_files(const char *dir_path, as_vector *file_vec);

/*
 * Returns true if the given file path is a standard intput/output path (i.e.
 * stdin or stdout)
 */
bool file_proxy_is_std_path(const char* path);

/*
 * Returns which type of file proxy this path corresponds to, either:
 *
 *  FILE_PROXY_TYPE_S3: if it begins with "s3://" (case insensitive)
 *  FILE_PROXY_TYPE_LOCAL: otherwise
 */
uint8_t file_proxy_path_type(const char* path);

/*
 * Returns true if the path ends with ".asb", meaning path points to a backup
 * file.
 */
bool file_proxy_is_backup_file_path(const char* path);

#ifdef __cplusplus
} // extern "C"
#endif /* __cplusplus */

