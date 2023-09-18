/*
 * Copyright 2023 Aerospike, Inc.
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

#include <cstdarg>
#include <cstdio>
#include <memory>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/Aws.h>
#include <aws/s3/model/AbortMultipartUploadRequest.h>
#include <aws/s3/model/HeadObjectRequest.h>
#include <aws/s3/model/ListMultipartUploadsRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/ListPartsRequest.h>

#pragma GCC diagnostic pop

#include <asbackup_logger.h>
#include <backup_state.h>
#include <delete_objects_buffer.h>
#include <file_proxy.h>
#include <s3_api.h>
#include <stream_manager.h>
#include <upload_manager.h>
#include <utils.h>


//==========================================================
// Forward Declarations.
//

extern "C" {

void file_proxy_s3_shutdown();

bool s3_delete_object(const char* file_path);
bool s3_delete_directory(const char* dir_path);

bool s3_prepare_output_file(const backup_config_t* conf, const char* file_path);
bool s3_scan_directory(const backup_config_t* conf,
		const backup_status_t* status, backup_state_t* backup_state,
		const char* dir_path);
off_t s3_get_backup_files(const char* prefix, as_vector* file_vec);

extern int file_proxy_s3_write_init(file_proxy_t*, const char* file_path,
		uint64_t max_file_size);
extern int file_proxy_s3_read_init(file_proxy_t*, const char* file_path);
int file_proxy_s3_close(file_proxy_t*, uint8_t mode);
int file_proxy_s3_serialize(const file_proxy_t*, file_proxy_t* dst);
int file_proxy_s3_deserialize(file_proxy_t*, file_proxy_t* src,
		const char* file_path);
ssize_t file_proxy_s3_get_size(file_proxy_t*);
int file_proxy_s3_putc(file_proxy_t* f, int c);
size_t file_proxy_s3_write(file_proxy_t* f, const void* buf, size_t count);
int file_proxy_s3_truncate(file_proxy_t* f);
int file_proxy_s3_flush(file_proxy_t* f);
int file_proxy_s3_getc(file_proxy_t* f);
int file_proxy_s3_getc_unlocked(file_proxy_t* f);
int file_proxy_s3_peekc_unlocked(file_proxy_t* f);
size_t file_proxy_s3_read(file_proxy_t* f, void* buf, size_t count);
int file_proxy_s3_eof(file_proxy_t* f);

}

static bool _abort_upload(const char* bucket,
		const Aws::S3::Model::MultipartUpload& upload);
static int64_t _scan_objects(const backup_config_t* conf,
		backup_state_t* backup_state, const char* bucket, const char* key);
static int64_t _scan_upload_requests(const backup_config_t* conf,
		backup_state_t* backup_state, const char* bucket, const char* key);
static uint64_t _calc_part_size(uint64_t max_file_size);


//==========================================================
// Public API.
//

bool
s3_parse_log_level(const char* log_level_str, s3_log_level_t* log_level)
{
	if (strcasecmp(log_level_str, "off") == 0) {
		*log_level = Off;
		return true;
	}
	if (strcasecmp(log_level_str, "fatal") == 0) {
		*log_level = Fatal;
		return true;
	}
	if (strcasecmp(log_level_str, "error") == 0) {
		*log_level = Error;
		return true;
	}
	if (strcasecmp(log_level_str, "warn") == 0) {
		*log_level = Warn;
		return true;
	}
	if (strcasecmp(log_level_str, "info") == 0) {
		*log_level = Info;
		return true;
	}
	if (strcasecmp(log_level_str, "debug") == 0) {
		*log_level = Debug;
		return true;
	}
	if (strcasecmp(log_level_str, "trace") == 0) {
		*log_level = Trace;
		return true;
	}

	return false;
}

/*
 * Closes the S3 API. Must be called just before the program exits.
 */
void
file_proxy_s3_shutdown()
{
	g_api.Shutdown();
}

void
s3_set_region(const char* region)
{
	g_api.SetRegion(region);
}

void
s3_set_profile(const char* profile)
{
	g_api.SetProfile(profile);
}

void
s3_set_endpoint(const char* endpoint)
{
	g_api.SetEndpoint(endpoint);
}

void
s3_set_max_async_downloads(uint32_t max_async_downloads)
{
	g_api.SetMaxAsyncDownloads(max_async_downloads);
}

void
s3_set_connect_timeout_ms(uint32_t connect_timeout_ms)
{
	g_api.SetConnectTimeoutMS(connect_timeout_ms);
}

void
s3_set_max_async_uploads(uint32_t max_async_uploads)
{
	g_api.SetMaxAsyncUploads(max_async_uploads);
}

void
s3_set_log_level(s3_log_level_t log_level)
{
	Aws::Utils::Logging::LogLevel s3_log_level;

	switch (log_level) {
		case Off:
			s3_log_level = Aws::Utils::Logging::LogLevel::Off;
			break;
		case Fatal:
			s3_log_level = Aws::Utils::Logging::LogLevel::Fatal;
			break;
		case Error:
			s3_log_level = Aws::Utils::Logging::LogLevel::Error;
			break;
		case Warn:
			s3_log_level = Aws::Utils::Logging::LogLevel::Warn;
			break;
		case Info:
			s3_log_level = Aws::Utils::Logging::LogLevel::Info;
			break;
		case Debug:
			s3_log_level = Aws::Utils::Logging::LogLevel::Debug;
			break;
		case Trace:
			s3_log_level = Aws::Utils::Logging::LogLevel::Trace;
			break;
		default:
			err("Unknown log level %d", (int32_t) log_level);
			break;
	}

	g_api.SetLogLevel(s3_log_level);
}

void
s3_disable_request_processing()
{
	if (g_api.IsInitialized()) {
		const_cast<Aws::S3::S3Client&>(g_api.GetS3Client()).DisableRequestProcessing();
	}
}

/*
 * Delete the given S3 object.
 */
bool
s3_delete_object(const char* file_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();
	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(file_path);
	if (!path_res.second) {
		return false;
	}
	const S3API::S3Path& path = path_res.first;

	DeleteObjectsBuffer del_buffer(client, path.GetBucket());
	del_buffer.DeleteObject(path.GetKey());
	return del_buffer.Flush();
}

bool
ListAllObjects(const Aws::S3::S3Client& client, Aws::S3::Model::ListObjectsV2Request& req, Aws::Vector<Aws::S3::Model::Object>& target) {

	Aws::S3::Model::ListObjectsV2Outcome outcome;
	do {
		outcome = client.ListObjectsV2(req);
		if (!outcome.IsSuccess()) {
			err("%s", outcome.GetError().GetMessage().c_str());
			return false;
		}

		Aws::S3::Model::ListObjectsV2Result res = outcome.GetResult();
		if (res.GetIsTruncated()) {
			const Aws::String& ct = res.GetNextContinuationToken();
			req.SetContinuationToken(ct);
		}

		for (const Aws::S3::Model::Object& object : res.GetContents()) {
			target.push_back(object);
		}
	}
	while (outcome.GetResult().GetIsTruncated());

	return true;
}

/*
 * Delete all S3 objects with given prefix ending in ".asb".
 */
bool
s3_delete_directory(const char* dir_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();
	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(dir_path);
	if (!path_res.second) {
		return false;
	}
	const S3API::S3Path& path = path_res.first;

	DeleteObjectsBuffer del_buffer(client, path.GetBucket());

	Aws::S3::Model::ListObjectsV2Request req;
	req.SetBucket(path.GetBucket());
	req.SetPrefix(path.GetKey());

	Aws::Vector<Aws::S3::Model::Object> res;
	if (!ListAllObjects(client, req, res)) {
		return false;
	}

	for (const Aws::S3::Model::Object& object : res) {
		const Aws::String& obj_key = object.GetKey();

		// check if the extension of the object is ".asb"
		if (file_proxy_is_backup_file_path(obj_key.c_str())) {
			if (!del_buffer.DeleteObject(obj_key)) {
				return false;
			}
		}
	}

	if (!del_buffer.Flush()) {
		return false;
	}

	Aws::S3::Model::ListMultipartUploadsRequest ureq;
	ureq.SetBucket(path.GetBucket());
	ureq.SetPrefix(path.GetKey());

	Aws::S3::Model::ListMultipartUploadsOutcome ures =
		client.ListMultipartUploads(ureq);
	if (!ures.IsSuccess()) {
		err("%s", ures.GetError().GetMessage().c_str());
		return -1;
	}

	for (const Aws::S3::Model::MultipartUpload& upload :
			ures.GetResult().GetUploads()) {
		const Aws::String& obj_key = upload.GetKey();

		// check if the extension of the object is ".asb"
		if (file_proxy_is_backup_file_path(obj_key.c_str())) {
			if (!_abort_upload(path.GetBucket().c_str(), upload)) {
				return -1;
			}
		}
	}

	return true;
}

/*
 * Check if the object exists, and if it does, remove it if --remove-files is
 * set.
 */
bool
s3_prepare_output_file(const backup_config_t* conf, const char* file_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();
	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(file_path);
	if (!path_res.second) {
		return false;
	}
	const S3API::S3Path& path = path_res.first;

	// first, get the Object metadata
	Aws::S3::Model::HeadObjectRequest meta_req;
	meta_req.SetBucket(path.GetBucket());
	meta_req.SetKey(path.GetKey());

	Aws::S3::Model::HeadObjectOutcome meta_res =
		client.HeadObject(meta_req);
	if (!meta_res.IsSuccess()) {
		if (meta_res.GetError().GetErrorType() != Aws::S3::S3Errors::RESOURCE_NOT_FOUND) {
			err("%s", meta_res.GetError().GetMessage().c_str());
			return false;
		}

		// object does not exist
	}
	else {
		// object exists, remove it if we can
		if (!conf->remove_files) {
			err("S3 object s3:%s/%s exists, pass --remove-files to replace it",
					path.GetBucket().c_str(), path.GetKey().c_str());
			return false;
		}

		if (!s3_delete_object(file_path)) {
			return false;
		}
	}

	return true;
}

/*
 * Iterates over all S3 objects and incomplete upload requests with prefix
 * "key", deleting them if --remove-files is enabled, or counting them if
 * conf->state_file != NULL (i.e. resuming a backup).
 *
 * Returns the number of backup files left in the directory (will be 0 if
 * --remove-files is enabled), or < 0 on error
 */
bool
s3_scan_directory(const backup_config_t* conf, const backup_status_t* status,
		backup_state_t* backup_state, const char* dir_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(dir_path);
	if (!path_res.second) {
		return false;
	}
	const S3API::S3Path& path = path_res.first;

	int64_t obj_count = _scan_objects(conf, backup_state,
			path.GetBucket().c_str(), path.GetKey().c_str());
	if (obj_count < 0) {
		return false;
	}

	int64_t upload_req_count = _scan_upload_requests(conf, backup_state,
			path.GetBucket().c_str(), path.GetKey().c_str());
	if (upload_req_count < 0) {
		return false;
	}

	uint64_t file_count = backup_status_get_file_count(status);
	if (static_cast<uint64_t>(obj_count + upload_req_count) != file_count) {
		err("Expected %" PRIu64 " backup files, but found %" PRIu64,
				file_count, obj_count + upload_req_count);
		return false;
	}

	return true;
}

/*
 * Scans the given bucket for all files with prefix "key" and populates file_vec
 * with the names of all files ending in ".asb" found.
 * It returns the total size of all files added together in bytes.
 * Return values < 0 indicate an error.
 */
off_t s3_get_backup_files(const char* prefix, as_vector* file_vec)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	off_t total_file_size = 0;

	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(prefix);
	if (!path_res.second) {
		return -1;
	}
	const S3API::S3Path& path = path_res.first;

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	size_t prefix_len = strlen(S3_PREFIX) + path.GetBucket().size() + 1;

	Aws::S3::Model::ListObjectsV2Request req;
	req.SetBucket(path.GetBucket());
	req.SetPrefix(path.GetKey());

	Aws::Vector<Aws::S3::Model::Object> res;
	if (!ListAllObjects(client, req, res)) {
		return -1;
	}

	for (const Aws::S3::Model::Object& object : res) {
		const Aws::String& obj_key = object.GetKey();

		// check if the extension of the object is ".asb"
		if (file_proxy_is_backup_file_path(obj_key.c_str())) {
			char *elem = static_cast<char*>(safe_malloc(prefix_len + obj_key.size() + 1));
			if (elem == NULL) {
				err("Failed to malloc space for file name %s",
						obj_key.c_str());
				goto cleanup;
			}

			snprintf(elem, prefix_len + obj_key.size() + 1,
					S3_PREFIX "%s/%s", path.GetBucket().c_str(), obj_key.c_str());
			as_vector_append(file_vec, &elem);

			total_file_size += object.GetSize();
		}
	}

	return total_file_size;

cleanup:
	for (uint32_t i = 0; i < file_vec->size; ++i) {
		cf_free(as_vector_get_ptr(file_vec, i));
	}

	as_vector_clear(file_vec);

	return -1;
}

int
file_proxy_s3_write_init(file_proxy_t* f, const char* file_path,
		uint64_t max_file_size)
{
	if (max_file_size > S3_MAX_OBJECT_SIZE) {
		err("The max S3 object size is %lu, but expected file size is %" PRIu64,
				S3_MAX_OBJECT_SIZE, max_file_size);
		return -1;
	}

	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(file_path);
	if (!path_res.second) {
		return -1;
	}
	const S3API::S3Path& path = path_res.first;

	f->s3.s3_state = new UploadManager(g_api.GetS3Client(), path.GetBucket(),
			path.GetKey(), _calc_part_size(max_file_size));
	if (!static_cast<UploadManager*>(f->s3.s3_state)->StartUpload()) {
		delete f->s3.s3_state;
		return -1;
	}

	return 0;
}

int
file_proxy_s3_read_init(file_proxy_t* f, const char* file_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(file_path);
	if (!path_res.second) {
		return -1;
	}
	const S3API::S3Path& path = path_res.first;

	f->s3.s3_state = new DownloadManager(g_api.GetS3Client(), path.GetBucket(),
			path.GetKey());
	if (!static_cast<DownloadManager*>(f->s3.s3_state)->StartDownload()) {
		return -1;
	}

	return 0;
}

int
file_proxy_s3_close(file_proxy_t* f, uint8_t mode)
{
	switch (file_proxy_get_mode(f)) {
		case FILE_PROXY_WRITE_MODE:
			switch (mode) {
				case FILE_PROXY_EOF:
					if (!static_cast<UploadManager*>(f->s3.s3_state)->FinishUpload()) {
						return EOF;
					}
					break;

				case FILE_PROXY_CONTINUE:
					// Don't do anything, let the MultipartUpload request
					// persist in S3.
					static_cast<UploadManager*>(f->s3.s3_state)->AwaitAsyncUploads();
					break;

				case FILE_PROXY_ABORT:
					if (!static_cast<UploadManager*>(f->s3.s3_state)->AbortUpload()) {
						return EOF;
					}
					break;
			}
			break;
		case FILE_PROXY_READ_MODE:
			if (!static_cast<DownloadManager*>(f->s3.s3_state)->AwaitAllDownloads()) {
				return EOF;
			}
			break;
	}

	delete f->s3.s3_state;

	return 0;
}

int
file_proxy_s3_serialize(const file_proxy_t* f, file_proxy_t* dst)
{

	switch (file_proxy_get_mode(f)) {
		case FILE_PROXY_WRITE_MODE:
			if (static_cast<UploadManager*>(f->s3.s3_state)->serialize(dst) != 0) {
				return -1;
			}

			break;

		case FILE_PROXY_READ_MODE:
			err("Serializing read file proxies not yet implemented");
			return -1;
	}
	return 0;
}

int
file_proxy_s3_deserialize(file_proxy_t* f, file_proxy_t* src,
		const char* file_path)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	const std::pair<S3API::S3Path, bool> path_res = g_api.ParseS3Path(file_path);
	if (!path_res.second) {
		return -1;
	}
	const S3API::S3Path& path = path_res.first;

	switch (file_proxy_get_mode(f)) {
		case FILE_PROXY_WRITE_MODE:
			f->s3.s3_state = new UploadManager(g_api.GetS3Client(),
					path.GetBucket(), path.GetKey(), 0);
			break;

		case FILE_PROXY_READ_MODE:
			err("Deserializing read file proxies not yet implemented");
			return -1;
	}

	if (f->s3.s3_state->deserialize(src) != 0) {
		return -1;
	}

	return 0;
}

ssize_t
file_proxy_s3_get_size(file_proxy_t* f)
{
	DownloadManager* downloader;

	switch (file_proxy_get_mode(f)) {
		case FILE_PROXY_WRITE_MODE:
			err("Cannot get size of S3 object opened in write mode");
			return -1;

		case FILE_PROXY_READ_MODE:
			downloader = static_cast<DownloadManager*>(f->s3.s3_state);
			return static_cast<ssize_t>(downloader->GetObjectSize());
	}

	return -1;
}

int
file_proxy_s3_putc(file_proxy_t* f, int c)
{
	(void) f;
	(void) c;
	return -1;
}

size_t
file_proxy_s3_write(file_proxy_t* f, const void* buf, size_t count)
{
	UploadManager* uploader = static_cast<UploadManager*>(f->s3.s3_state);
	return uploader->UploadText(static_cast<const char*>(buf), count);
}

int
file_proxy_s3_truncate(file_proxy_t* f)
{
	(void) f;
	return EOF;
}

int
file_proxy_s3_flush(file_proxy_t* f)
{
	(void) f;
	return 0;
}

int
file_proxy_s3_getc(file_proxy_t* f)
{
	(void) f;
	return EOF;
}

int
file_proxy_s3_getc_unlocked(file_proxy_t* f)
{
	(void) f;
	return EOF;
}

int
file_proxy_s3_peekc_unlocked(file_proxy_t* f)
{
	(void) f;
	return EOF;
}

size_t
file_proxy_s3_read(file_proxy_t* f, void* buf, size_t count)
{
	DownloadManager* downloader = static_cast<DownloadManager*>(f->s3.s3_state);
	return downloader->DownloadText(static_cast<char*>(buf), count);
}

int
file_proxy_s3_eof(file_proxy_t* f)
{
	DownloadManager* downloader = static_cast<DownloadManager*>(f->s3.s3_state);
	return downloader->AtEOF() ? 1 : 0;
}


//==========================================================
// Local Helpers.
//

/*
 * Aborts the MultipartUpload on S3, freeing resources saved there (which users
 * are charged for like normal data held in S3).
 */
static bool
_abort_upload(const char* bucket, const Aws::S3::Model::MultipartUpload& upload)
{
	const Aws::S3::S3Client& client = g_api.GetS3Client();

	Aws::S3::Model::AbortMultipartUploadRequest req;
	req.SetBucket(bucket);
	req.SetKey(upload.GetKey());
	req.SetUploadId(upload.GetUploadId());

	Aws::S3::Model::AbortMultipartUploadOutcome res =
		client.AbortMultipartUpload(req);
	if (!res.IsSuccess()) {
		err("%s", res.GetError().GetMessage().c_str());
		return false;
	}

	return true;
}

/*
 * Iterates over all S3 objects with prefix "key", deleting them if
 * --remove-files is enabled, or counting them if
 * conf->state_file != NULL (i.e. resuming a backup).
 *
 * Returns the number of backup files left in the directory (will be 0 if
 * --remove-files is enabled), or < 0 on error
 */
static int64_t
_scan_objects(const backup_config_t* conf, backup_state_t* backup_state,
		const char* bucket, const char* key)
{
	const Aws::S3::S3Client& client = g_api.GetS3Client();

	DeleteObjectsBuffer del_buffer(client, bucket);
	uint64_t file_count = 0;

	Aws::S3::Model::ListObjectsV2Request req;
	req.SetBucket(bucket);
	req.SetPrefix(key);

	Aws::Vector<Aws::S3::Model::Object> res;
	if (!ListAllObjects(client, req, res)) {
		return -1;
	}

	for (const Aws::S3::Model::Object& object : res) {
		const Aws::String& obj_key = object.GetKey();

		// check if the extension of the object is ".asb"
		if (file_proxy_is_backup_file_path(obj_key.c_str())) {
			if (conf->remove_files) {
				if (!del_buffer.DeleteObject(obj_key)) {
					return -1;
				}
			}
			else if (conf->state_file != NULL) {
				std::ostringstream full_path;
				full_path << S3_PREFIX << bucket << "/" << obj_key;
				if (backup_state_contains_file(backup_state, full_path.str().c_str())) {
					err("Expected object \"%s\" to be complete, but found in "
							"backup state list of incomplete files",
							full_path.str().c_str());
					return -1;
				}
				file_count++;
			}
			else {
				err("S3 directory %s in bucket %s seems to contain an existing "
						"backup; use -r to clear the directory",
						key, bucket);
				return -1;
			}
		}
	}

	if (!del_buffer.Flush()) {
		return -1;
	}

	return static_cast<int64_t>(file_count);
}

/*
 * Checks that each file in the backup state file list has a corresponding
 * multipart upload request, and verifies that the full paths of these files
 * begin with "S3_PREFIX<bucket>/<key>".
 */
static bool
_check_multipart_uploads_list(const backup_config_t* conf,
		backup_state_t* backup_state, const char* bucket,
		const char* key)
{
	const Aws::S3::S3Client& client = g_api.GetS3Client();
	size_t bucket_len = strlen(bucket);
	size_t key_len = strlen(key);

	if (conf->state_file != NULL) {
		for (uint32_t i = 0; i < backup_state->files.size; i++) {
			const backup_state_file_t* file =
				(const backup_state_file_t*) as_vector_get(&backup_state->files, i);
			const char* full_path = io_proxy_file_path(file->io_proxy);

			if (strncmp(full_path, S3_PREFIX, sizeof(S3_PREFIX) - 1) != 0) {
				err("Expected full path to begin with \"" S3_PREFIX "\" in %s",
						full_path);
				return false;
			}

			if (strncmp(full_path + (sizeof(S3_PREFIX) - 1), bucket, bucket_len) != 0) {
				err("Expected bucket name \"%s\", but found \"%.*s\" in full "
						"path %s",
						bucket, (int) bucket_len,
						full_path + (sizeof(S3_PREFIX) - 1), full_path);
				return false;
			}

			const char* request_key = full_path + sizeof(S3_PREFIX) + bucket_len;

			if (strncmp(request_key, key, key_len) != 0 || request_key[key_len] != '/') {
				err("Expected key prefix \"%s/\", but found \"%.*s\" in full "
						"path %s",
						key, (int) key_len, request_key, full_path);
				return false;
			}

			const file_proxy_t* file_proxy = &file->io_proxy->file;
			if (file_proxy_get_type(file_proxy) != FILE_PROXY_TYPE_S3) {
				err("Expected file proxy type for file \"%s\" to be S3",
						full_path);
				return false;
			}

			UploadManager* upload_manager = dynamic_cast<UploadManager*>(file_proxy->s3.s3_state);
			if (upload_manager == nullptr) {
				err("Expected file proxy mode for file \"%s\" to be write",
						full_path);
				return false;
			}

			// check for the existence of this multipart upload
			Aws::S3::Model::ListPartsRequest lreq;
			lreq.SetBucket(bucket);
			lreq.SetKey(request_key);
			lreq.SetUploadId(upload_manager->GetUploadId());
			lreq.SetMaxParts(0);

			Aws::S3::Model::ListPartsOutcome lres = client.ListParts(lreq);
			if (!lres.IsSuccess()) {
				err("%s: %s", full_path, lres.GetError().GetMessage().c_str());
				return false;
			}
		}
	}

	return true;
}

/*
 * Iterates over all S3 incomplete upload requests with prefix "key", aborting
 * them if --remove-files is enabled, or counting them if
 * conf->state_file != NULL (i.e. resuming a backup).
 *
 * Returns the number of upload requests left in the directory (will be 0 if
 * --remove-files is enabled), or < 0 on error
 */
static int64_t
_scan_upload_requests(const backup_config_t* conf, backup_state_t* backup_state,
		const char* bucket, const char* key)
{
	const Aws::S3::S3Client& client = g_api.GetS3Client();

	if (!_check_multipart_uploads_list(conf, backup_state, bucket, key)) {
		return -1;
	}

	Aws::S3::Model::ListMultipartUploadsRequest ureq;
	ureq.SetBucket(bucket);
	ureq.SetPrefix(key);

	Aws::S3::Model::ListMultipartUploadsOutcome ures =
		client.ListMultipartUploads(ureq);
	if (!ures.IsSuccess()) {
		err("%s", ures.GetError().GetMessage().c_str());
		return -1;
	}

	for (const Aws::S3::Model::MultipartUpload& upload :
			ures.GetResult().GetUploads()) {
		const Aws::String& obj_key = upload.GetKey();

		// check if the extension of the object is ".asb"
		if (file_proxy_is_backup_file_path(obj_key.c_str())) {
			if (conf->remove_files) {
				if (!_abort_upload(bucket, upload)) {
					return -1;
				}
			}
			else if (conf->state_file != NULL) {
				std::ostringstream full_path;
				full_path << S3_PREFIX << bucket << "/" << obj_key;
				if (!backup_state_contains_file(backup_state, full_path.str().c_str())) {
					err("Expected object \"%s\" to be in backup state list of "
							"incomplete files, but was not found",
							full_path.str().c_str());
					return -1;
				}
			}
			else {
				err("S3 directory %s in bucket %s seems to contain an existing "
						"backup; use -r to clear the directory",
						key, bucket);
				return -1;
			}
		}
	}

	return backup_state == NULL ? 0 : static_cast<int64_t>(backup_state->files.size);
}


/*
 * Calculates the min part size to use for S3 Multipart Upload parts. If not
 * set, a default value is calculated based on the type of backup being made and
 * the parameters given in the config.
 */
static uint64_t
_calc_part_size(uint64_t max_file_size)
{
	const backup_config_t* conf = get_g_backup_conf();
	if (conf->s3_min_part_size > 0) {
		return conf->s3_min_part_size;
	}
	uint64_t part_size = (max_file_size + S3_MAX_N_PARTS - 1) / S3_MAX_N_PARTS;
	return part_size < S3_MIN_PART_SIZE ? S3_MIN_PART_SIZE : part_size;
}

