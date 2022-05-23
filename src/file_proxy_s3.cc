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

#include <condition_variable>
#include <cstdio>
#include <memory>
#include <deque>

#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/Aws.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/AbortMultipartUploadRequest.h>
#include <aws/s3/model/CreateMultipartUploadRequest.h>
#include <aws/s3/model/UploadPartRequest.h>
#include <aws/s3/model/CompleteMultipartUploadRequest.h>
#include <aws/s3/model/HeadObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListMultipartUploadsRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/ListPartsRequest.h>
#include <aws/s3/model/DeleteObjectsRequest.h>

#pragma GCC diagnostic warning "-Wsign-conversion"

#include <file_proxy.h>

extern "C" {
#include <backup.h>
#include <backup_state.h>
#include <utils.h>
}


//==========================================================
// Typedefs & Constants.
//

// forward declarations
class GroupDownloadManager;

class S3API {
private:
	std::once_flag init_once;
	bool initialized;
	Aws::SDKOptions options;

	std::string region;
	std::string profile;
	std::string endpoint;
	Aws::S3::S3Client* client;

	// must be initialized with SetMaxAsync... methods
	uint32_t max_async_uploads;
	uint32_t max_async_downloads;

	// the current number of concurrent async uploads
	std::atomic<uint32_t> async_uploads;
	std::mutex async_uploads_lock;
	std::condition_variable async_uploads_cv;

	std::once_flag init_group_dowloader_once;
	std::unique_ptr<GroupDownloadManager> group_download_manager;

	static void _init_api(S3API& s3_api) {
		inf("Initializing S3 API");

		s3_api.options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Off;
		// Install SIGPIPE handler, which the sdk is able to recover from
		// without terminating the backup.
		// (see https://aerospike.atlassian.net/browse/TOOLS-2006)
		s3_api.options.httpOptions.installSigPipeHandler = true;
		Aws::InitAPI(s3_api.options);

		Aws::Client::ClientConfiguration conf;
		if (s3_api.region.empty() && s3_api.endpoint.empty()) {
			err("S3 API must be enabled by specifying a region if no endpoint "
					"override is given.");
			Aws::ShutdownAPI(s3_api.options);
			return;
		}
		else {
			conf.region = s3_api.region;
		}
		if (!s3_api.profile.empty()) {
			setenv("AWS_PROFILE", s3_api.profile.c_str(), true);
		}
		if (!s3_api.endpoint.empty()) {
			conf.endpointOverride = s3_api.endpoint;
			conf.scheme = Aws::Http::Scheme::HTTP;
		}

		s3_api.client = new Aws::S3::S3Client(conf,
				Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always,
				false);

		s3_api.initialized = true;
	}

	static void _RegisterAsync(std::mutex& lock, std::condition_variable& cv,
			std::atomic<uint32_t>& n, uint32_t max_n) {
		std::unique_lock<std::mutex> lg(lock);

		while (n >= max_n) {
			cv.wait(lg, [&]() { return n < max_n; });
		}

		n++;
	}

	static void _FinishAsync(std::mutex& lock, std::condition_variable& cv,
			std::atomic<uint32_t>& n, uint32_t max_n) {
		std::unique_lock<std::mutex> lg(lock);
		uint32_t prev_n = n.fetch_sub(1);
		lg.unlock();

		if (prev_n < max_n) {
			cv.notify_all();
		}
		else {
			cv.notify_one();
		}
	}

public:

	S3API() : initialized(false), client(nullptr), async_uploads(0) {}

	bool TryInitialize() {
		std::call_once(init_once, _init_api, std::ref(*this));

		return this->initialized;
	}

	void Shutdown() {
		if (initialized) {
			inf("Closing S3 API");
			if (client != nullptr) {
				delete client;
			}

			Aws::ShutdownAPI(options);
		}
	}

	bool IsInitialized() const {
		return initialized;
	}

	// This must be called before TryInitialize()
	S3API& SetRegion(const std::string& region) {
		if (IsInitialized()) {
			err("Cannot set region after initializing S3 API");
		}
		else {
			this->region = region;
		}
		return *this;
	}

	// This must be called before TryInitialize()
	S3API& SetProfile(const std::string& profile) {
		if (IsInitialized()) {
			err("Cannot set profile after initializing S3 API");
		}
		else {
			this->profile = profile;
		}
		return *this;
	}

	// This must be called before TryInitialize()
	S3API& SetEndpoint(const std::string& endpoint) {
		if (IsInitialized()) {
			err("Cannot set endpoint after initializing S3 API");
		}
		else {
			this->endpoint = endpoint;
		}
		return *this;
	}

	S3API& SetMaxAsyncDownloads(uint32_t max_async_downloads) {
		this->max_async_downloads = max_async_downloads;
		return *this;
	}

	S3API& SetMaxAsyncUploads(uint32_t max_async_uploads) {
		this->max_async_uploads = max_async_uploads;
		return *this;
	}

	// defined below, after the class definition of GroupDownloadManager
	GroupDownloadManager* GetGroupDownloadManager();

	const std::string& GetRegion() const {
		return region;
	}

	const std::string& GetProfile() const {
		return profile;
	}

	const std::string& GetEndpoint() const {
		return endpoint;
	}

	const Aws::S3::S3Client& GetS3Client() const {
		return *client;
	}

	/*
	 * Ensures that less than max_async_uploads outstanding async upload
	 * requests exist, and blocking until at least one finishes if necessary.
	 */
	void RegisterAsyncUpload() {
		_RegisterAsync(async_uploads_lock, async_uploads_cv, async_uploads,
				max_async_uploads);
	}

	/*
	 * To be called after an async call has returned, freeing up a slot for
	 * another async upload to be made.
	 */
	void FinishAsyncUpload() {
		_FinishAsync(async_uploads_lock, async_uploads_cv, async_uploads,
				max_async_uploads);
	}
};

// The global S3API object.
S3API g_api;

class StreamManager {
protected:
	const Aws::S3::S3Client& client;
	const std::string bucket;
	const std::string key;

public:

	StreamManager(const Aws::S3::S3Client& client, const std::string bucket,
			const std::string key) : client(client), bucket(bucket), key(key) {}

	virtual ~StreamManager() = default;

	const std::string& GetBucket() const {
		return bucket;
	}

	const std::string& GetKey() const {
		return key;
	}

	virtual int serialize(file_proxy_t* dst) {
		// Don't do anything: bucket/key are provided on construction, so no
		// need to save them.
		(void) dst;
		return 0;
	}

	virtual int deserialize(file_proxy_t* src) {
		(void) src;
		return 0;
	}

	static bool SerializeString(const Aws::String& str, file_proxy_t* dst) {
		if (!write_int32(static_cast<uint32_t>(str.size()), dst)) {
			return false;
		}

		if (file_proxy_write(dst, str.c_str(), str.size()) != str.size()) {
			return false;
		}

		return true;
	}

	static bool DeserializeString(Aws::String& str, file_proxy_t* src) {
		uint32_t size;
		char* tmp_str;

		if (!read_int32(&size, src)) {
			return false;
		}

		tmp_str = static_cast<char*>(cf_malloc(size));
		if (tmp_str == nullptr) {
			return false;
		}

		if (file_proxy_read(src, tmp_str, size) != size) {
			cf_free(tmp_str);
			return false;
		}

		str.assign(tmp_str, size);
		cf_free(tmp_str);

		return true;
	}

	static bool SerializeSStream(const Aws::StringStream& str, file_proxy_t* dst) {
		const Aws::String s = str.str();
		if (!write_int32(static_cast<uint32_t>(s.size()), dst)) {
			return false;
		}

		if (file_proxy_write(dst, s.c_str(), s.size()) != s.size()) {
			return false;
		}

		return true;
	}

	static bool DeserializeSStream(Aws::StringStream& str, file_proxy_t* src) {
		uint32_t size;
		char* tmp_str;

		if (!read_int32(&size, src)) {
			return false;
		}

		tmp_str = static_cast<char*>(cf_malloc(size));
		if (tmp_str == nullptr) {
			return false;
		}

		if (file_proxy_read(src, tmp_str, size) != size) {
			cf_free(tmp_str);
			return false;
		}

		str.write(tmp_str, size);
		cf_free(tmp_str);

		return true;
	}

	template<typename T>
	static bool SerializeVector(file_proxy_t* dst, const std::vector<T>& v,
			std::function<bool(file_proxy_t*, const T&)> serializer) {
		if (!write_int32((uint32_t) v.size(), dst)) {
			err("Failed to write vector size to file");
			return false;
		}

		for (const T& el : v) {
			if (!serializer(dst, el)) {
				return false;
			}
		}

		return true;
	}

	template<typename Serializable>
	static bool SerializeVector(file_proxy_t* dst,
			const std::vector<Serializable>& v) {
		std::function<bool(file_proxy_t*, const Serializable&)> serialize_fn =
			[](file_proxy_t* dst, const Serializable& el) {
			return el.Serialize(dst);
		};
		return SerializeVector(dst, v, serialize_fn);
	}

	template<typename T>
	static bool DeserializeVector(file_proxy_t* src, std::vector<T>& v,
			std::function<bool(file_proxy_t*, T&)> deserializer) {
		uint32_t size;
		if (!read_int32(&size, src)) {
			err("Failed to read vector list size from file");
			return false;
		}

		v.reserve(size);
		for (uint32_t i = 0; i < size; i++) {
			T el;
			if (!deserializer(src, el)) {
				return false;
			}
			v.push_back(std::move(el));
		}

		return true;
	}

	template<typename Serializable>
	static bool DeserializeVector(file_proxy_t* src,
			std::vector<Serializable>& v) {
		std::function<bool(file_proxy_t*, Serializable&)> deserialize_fn =
			[](file_proxy_t* src, Serializable& el) {
			return el.Deserialize(src);
		};
		return DeserializeVector(src, v, deserialize_fn);
	}

	class AsyncContext : public Aws::Client::AsyncCallerContext {
	private:
		StreamManager* sm;
		// for download parts, the size of the downloaded part in bytes
		uint64_t n_bytes;
		// the part number of the part
		uint64_t part_n;

	public:

		AsyncContext(StreamManager* sm) : sm(sm) {}

		StreamManager* GetStreamManager() const {
			return const_cast<StreamManager*>(sm);
		}

		void SetNBytes(uint64_t n_bytes) {
			this->n_bytes = n_bytes;
		}

		uint64_t GetNBytes() const {
			return n_bytes;
		}

		void SetPartN(uint64_t part_n) {
			this->part_n = part_n;
		}

		uint64_t GetPartN() const {
			return part_n;
		}
	};

};

class UploadManager : public StreamManager {
private:
	class FailedPart;

	bool do_content_hash;

	// The part number of the next part to be uploaded.
	int part_number;
	Aws::String upload_id;

	uint64_t min_part_size;

	/*
	 * A buffer of the text waiting to be uploaded.
	 */
	Aws::StringStream buffer;

	/*
	 * Atomic variable for the number of outstanding async calls for this upload.
	 */
	std::atomic<uint32_t> outstanding_calls;
	std::mutex outstanding_calls_lock;
	std::condition_variable outstanding_calls_cv;

	/*
	 * Mutex to be used on member variables in async function callbacks.
	 */
	std::mutex async_finished_mutex;

	/*
	 * A list of all CompletedPart objects, which are required to be sent with
	 * the final CompleteMultipartUpload call.
	 */
	Aws::Vector<Aws::S3::Model::CompletedPart> part_list;

	/*
	 * A list of all FailedParts which failed to upload to S3 for any reason.
	 */
	Aws::Vector<FailedPart> failed_part_list;

	void DecrementOutstandingCalls() {
		outstanding_calls_lock.lock();
		outstanding_calls--;
		outstanding_calls_lock.unlock();
		outstanding_calls_cv.notify_one();
	}

	static void UploadPartFinished(const Aws::S3::S3Client* client,
			const Aws::S3::Model::UploadPartRequest& req,
			const Aws::S3::Model::UploadPartOutcome& outcome,
			const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context) {
		(void) client;

		std::shared_ptr<const StreamManager::AsyncContext> async_ctx =
			std::static_pointer_cast<const StreamManager::AsyncContext>(context);
		UploadManager* upload_manager =
			static_cast<UploadManager*>(async_ctx->GetStreamManager());

		if (!outcome.IsSuccess()) {
			err("%s", outcome.GetError().GetMessage().c_str());

			backup_config_t* g_conf = get_g_backup_conf();
			backup_status_t* g_status = get_g_backup_status();
			backup_status_stop(g_conf, g_status);

			std::shared_ptr<Aws::StringStream> body =
				std::dynamic_pointer_cast<Aws::StringStream>(req.GetBody());
			if (body == nullptr) {
				err("Failed to convert request body to Aws::StringStream");
				backup_status_abort_backup(g_status);
				return;
			}

			upload_manager->async_finished_mutex.lock();
			upload_manager->failed_part_list.emplace_back(req.GetPartNumber(), body);
			upload_manager->async_finished_mutex.unlock();
		}
		else {
			Aws::S3::Model::CompletedPart part;
			part.SetETag(outcome.GetResult().GetETag());
			part.SetPartNumber(req.GetPartNumber());

			upload_manager->async_finished_mutex.lock();
			upload_manager->part_list.push_back(part);
			upload_manager->async_finished_mutex.unlock();
		}

		g_api.FinishAsyncUpload();

		upload_manager->DecrementOutstandingCalls();
	}

	bool _UploadPart(int part_number, std::shared_ptr<Aws::StringStream>& body) {
		// Don't try uploading this part if the backup has been stopped, just
		// immediately mark the part as failed and return.
		backup_status_t* backup_status = get_g_backup_status();
		if (backup_status_has_stopped(backup_status)) {
			async_finished_mutex.lock();
			failed_part_list.emplace_back(part_number, body);
			async_finished_mutex.unlock();
			return true;
		}

		g_api.RegisterAsyncUpload();

		Aws::S3::Model::UploadPartRequest part_req;
		part_req.SetBucket(bucket);
		part_req.SetKey(key);
		part_req.SetPartNumber(part_number);
		part_req.SetUploadId(upload_id);

		part_req.SetBody(body);

		if (do_content_hash) {
			Aws::Utils::ByteBuffer part_md5(
					Aws::Utils::HashingUtils::CalculateMD5(*body));
			part_req.SetContentMD5(Aws::Utils::HashingUtils::Base64Encode(part_md5));
		}

		std::shared_ptr<Aws::Client::AsyncCallerContext> context =
			Aws::MakeShared<StreamManager::AsyncContext>(
					"StreamManager::AsyncContext", this);
		context->SetUUID(key);

		outstanding_calls++;

		client.UploadPartAsync(part_req, UploadManager::UploadPartFinished, context);

		return true;
	}

	bool _UploadNextPart() {
		std::shared_ptr<Aws::StringStream> body =
			Aws::MakeShared<Aws::StringStream>("Aws::StringStream", std::move(buffer));
		if (_UploadPart(part_number, body)) {
			part_number++;
			return true;
		}
		else {
			return false;
		}
	}

	class FailedPart {
	private:
		std::shared_ptr<Aws::StringStream> buffer;
		int part_number;

	public:

		FailedPart() : part_number(-1) {}

		/*
		 * Constructs a failed part from the part number and text buffer that
		 * failed to upload.
		 */
		FailedPart(int part_number, std::shared_ptr<Aws::StringStream> buffer) :
			buffer(buffer), part_number(part_number) {}

		/*
		 * Retries a failed upload.
		 */
		bool RetryUpload(UploadManager& upload_manager) {
			return upload_manager._UploadPart(part_number, buffer);
		}

		bool Serialize(file_proxy_t* dst) const {
			if (!write_int32(static_cast<uint32_t>(part_number), dst)) {
				err("Failed to write part_number for failed part of "
						"UploadManager");
				return false;
			}

			if (!SerializeSStream(*buffer, dst)) {
				err("Failed to serialize buffer of UploadManager");
				return false;
			}
			return true;
		}

		bool Deserialize(file_proxy_t* src) {
			if (!read_int32(reinterpret_cast<uint32_t*>(&part_number), src)) {
				err("Failed to read part_number for failed part of "
						"UploadManager from file");
				return false;
			}

			buffer = Aws::MakeShared<Aws::StringStream>("Aws::StringStream");
			if (!DeserializeSStream(*buffer, src)) {
				err("Failed to serialize buffer of UploadManager");
				return false;
			}

			return true;
		}
	};

public:

	UploadManager(const Aws::S3::S3Client& client, const std::string& bucket,
			const std::string& key, uint64_t min_part_size) : StreamManager(client, bucket, key),
									  do_content_hash(true), part_number(1),
									  min_part_size(min_part_size), outstanding_calls(0) {}

	virtual ~UploadManager() {}

	const Aws::String GetUploadId() const {
		return upload_id;
	}

	/*
	 * Blocks until all async calls have finished running.
	 */
	void AwaitAsyncUploads() {
		std::unique_lock<std::mutex> lg(outstanding_calls_lock);
		outstanding_calls_cv.wait(lg, [&]() { return outstanding_calls == 0; });
	}

	bool StartUpload() {
		Aws::S3::Model::CreateMultipartUploadRequest create_req;
		create_req.SetBucket(bucket);
		create_req.SetKey(key);
		create_req.SetContentEncoding("text/plain");

		Aws::S3::Model::CreateMultipartUploadOutcome create_res =
			client.CreateMultipartUpload(create_req);

		if (!create_res.IsSuccess()) {
			err("%s", create_res.GetError().GetMessage().c_str());
			return false;
		}

		this->upload_id = create_res.GetResult().GetUploadId();

		return true;
	}

	/*
	 * Uploads a block text to S3 in chunks, returning true on success and
	 * false if any failure occured.
	 */
	uint64_t UploadText(const char* text, size_t text_len) {
		size_t buf_size = static_cast<size_t>(buffer.tellp());
		const size_t init_text_len = text_len;

		while (buf_size + text_len >= min_part_size &&
				part_number < S3_MAX_N_PARTS) {
			size_t n_chars = min_part_size - buf_size;
			buffer.write(text, static_cast<std::streamsize>(n_chars));

			if (!_UploadNextPart()) {
				return init_text_len - text_len;
			}

			buf_size = 0;
			text_len -= n_chars;
			text += n_chars;
		}

		if (text_len > S3_MAX_PART_SIZE) {
			err("Last S3 upload part size (%zu) has exceeded max UploadPart "
					"size (%lu). The file being uploaded may be too close to "
					"the S3 file size limit, or you may need to re-run setting "
					"--s3-minimum-part-size to something larger than %" PRIu64,
					text_len, S3_MAX_PART_SIZE, min_part_size);
			return init_text_len - text_len;
		}

		buffer.write(text, static_cast<std::streamsize>(text_len));

		return init_text_len;
	}

	/*
	 * Commits the uploaded file to S3, making a CompleteMultipartUpload request
	 * and finalizing the object. It can no longer be modified after this
	 * operation.
	 *
	 * This must be called after Flush to ensure all parts have finished
	 * uploading.
	 */
	bool FinishUpload() {
		if (buffer.tellp() > 0 && !_UploadNextPart()) {
			return false;
		}

		// wait for all outstanding async uploads for this object to complete
		// before we finish the upload
		AwaitAsyncUploads();

		if (failed_part_list.size() > 0) {
			// we can't close successfully if any upload part failed
			return false;
		}

		Aws::S3::Model::CompleteMultipartUploadRequest c_req;
		c_req.SetBucket(bucket);
		c_req.SetKey(key);
		c_req.SetUploadId(upload_id);

		// the upload parts must be in ascending order, but they may have
		// finished uploading out of order
		std::sort(part_list.begin(), part_list.end(),
				[](Aws::S3::Model::CompletedPart& a,
					Aws::S3::Model::CompletedPart& b) {
			return a.GetPartNumber() < b.GetPartNumber();
		});

		Aws::S3::Model::CompletedMultipartUpload complete_part;
		complete_part.SetParts(part_list);
		c_req.SetMultipartUpload(complete_part);

		Aws::S3::Model::CompleteMultipartUploadOutcome c_res =
			client.CompleteMultipartUpload(c_req);

		if (!c_res.IsSuccess()) {
			err("Error finishing S3 file upload: %s",
					c_res.GetError().GetMessage().c_str());
			return false;
		}

		this->upload_id.clear();

		return true;
	}

	/*
	 * Abort the current running MultipartUpload, clearing all cached data held
	 * on S3.
	 */
	bool AbortUpload() {
		// wait for all outstanding async uploads for this object to complete
		// before we abort the upload
		AwaitAsyncUploads();

		Aws::S3::Model::AbortMultipartUploadRequest abort_req;
		abort_req.SetBucket(bucket);
		abort_req.SetKey(key);
		abort_req.SetUploadId(upload_id);

		Aws::S3::Model::AbortMultipartUploadOutcome abort_res =
			client.AbortMultipartUpload(abort_req);

		if (!abort_res.IsSuccess()) {
			err("Failed to abort MultipartUpload with id %s, reason: %s",
					upload_id.c_str(), abort_res.GetError().GetMessage().c_str());
			return false;
		}

		this->upload_id.clear();

		return true;
	}

	virtual int serialize(file_proxy_t* dst) {
		AwaitAsyncUploads();

		if (this->StreamManager::serialize(dst) != 0) {
			return -1;
		}

		if (!write_int32(static_cast<uint32_t>(part_number), dst)) {
			err("Failed to write part_number of UploadManager");
			return -1;
		}

		if (!SerializeString(upload_id, dst)) {
			err("Failed to serialize upload_id of UploadManager");
			return -1;
		}

		if (!write_int64(min_part_size, dst)) {
			err("Failed to write min_part_size of UploadManager");
			return -1;
		}

		if (!SerializeSStream(buffer, dst)) {
			err("Failed to serialize buffer of UploadManager");
			return -1;
		}

		std::function<bool(file_proxy_t*, const Aws::S3::Model::CompletedPart&)>
			serialize_part_fn = [](file_proxy_t* dst,
					const Aws::S3::Model::CompletedPart& part) {
			const Aws::String& etag = part.GetETag();
			int part_num = part.GetPartNumber();

			if (!write_int32(static_cast<uint32_t>(part_num), dst)) {
				err("Failed to write part_number for completed part of "
						"UploadManager");
				return false;
			}

			if (!SerializeString(etag, dst)) {
				err("Failed to serialize etag of completed part");
				return false;
			}

			return true;
		};

		if (!SerializeVector(dst, part_list, serialize_part_fn)) {
			err("Failed to serialize part_list vector of UploadManager");
			return -1;
		}

		if (!SerializeVector(dst, failed_part_list)) {
			err("Failed to serialize failed_part_list vector of UploadManager");
			return -1;
		}

		return 0;
	}

	virtual int deserialize(file_proxy_t* src) {
		std::vector<FailedPart> failed_parts;

		if (this->StreamManager::deserialize(src) != 0) {
			return -1;
		}

		if (!read_int32(reinterpret_cast<uint32_t*>(&part_number), src)) {
			err("Failed to read part number of UploadManager from file");
			return -1;
		}

		if (!DeserializeString(upload_id, src)) {
			err("Failed to read upload_id of UploadManager from file");
			return -1;
		}

		if (!read_int64(&min_part_size, src)) {
			err("Failed to read min_part_size of UploadManager from file");
			return -1;
		}

		if (!DeserializeSStream(buffer, src)) {
			err("Failed to deserialize buffer of UploadManager from file");
			return -1;
		}

		std::function<bool(file_proxy_t*, Aws::S3::Model::CompletedPart&)> deserialize_part_fn =
			[](file_proxy_t* src, Aws::S3::Model::CompletedPart& part) {

			Aws::String etag;
			int part_num;

			if (!read_int32(reinterpret_cast<uint32_t*>(&part_num), src)) {
				err("Failed to read part_number for completed part of "
						"UploadManager from file");
				return false;
			}

			if (!DeserializeString(etag, src)) {
				err("Failed to deserialize etag of completed part from file");
				return false;
			}

			part.WithETag(std::move(etag)).WithPartNumber(part_num);
			return true;
		};
		if (!DeserializeVector(src, part_list, deserialize_part_fn)) {
			err("Failed to deserialize part_list vector of UploadManager from file");
			return -1;
		}

		if (!DeserializeVector(src, failed_parts)) {
			err("Failed to deserialize failed_part_list vector of UploadManager from file");
			return -1;
		}

		for (FailedPart& failed_part : failed_parts) {
			if (!failed_part.RetryUpload(*this)) {
				return -1;
			}
		}

		return 0;
	}
};

/*
 * Manages the concurrent downloading of multiple S3 object parts.
 */
template<class T>
class AsyncPartManager {
public:
	T** buf;
	// the size of buf in terms of sizeof(T)
	uint64_t buf_size;
	// the index of the next element to be popped
	uint64_t start;
	// the number of items in buf
	uint64_t n_items;

	std::mutex access_lock;
	std::condition_variable cv;

	void _Accomodate(uint64_t idx) {
		if (start + buf_size <= idx) {
			uint64_t diff = idx - start;
			uint64_t new_size = (1lu << (64 - __builtin_clzl(diff)));

			T** new_buf = new T*[new_size]();

			for (uint64_t i = start; i < start + buf_size; i++) {
				new_buf[i % new_size] = buf[i % buf_size];
			}

			delete[] buf;
			buf = new_buf;
			buf_size = new_size;
		}
	}

public:

	static constexpr intptr_t error_placeholder = -1;

	AsyncPartManager() : buf_size(4), start(0), n_items(0) {
		buf = new T*[buf_size]();
	}

	~AsyncPartManager() {
		std::unique_lock<std::mutex> lg(access_lock);
		for (uint64_t i = 0; i < buf_size; i++) {
			if (buf[i] != nullptr && buf[i] != reinterpret_cast<T*>(error_placeholder)) {
				delete buf[i];
			}
		}
		delete[] buf;
	}

	AsyncPartManager& push(T&& t, uint64_t idx) {
		std::unique_lock<std::mutex> lg(access_lock);
		uint64_t start = this->start;
		_Accomodate(idx);

		buf[idx % buf_size] = new T(std::move(t));
		n_items++;
		lg.unlock();

		if (idx == start) {
			cv.notify_one();
		}
		return *this;
	}

	AsyncPartManager& push_error(uint64_t idx) {
		std::unique_lock<std::mutex> lg(access_lock);
		uint64_t start = this->start;
		_Accomodate(idx);

		buf[idx % buf_size] = reinterpret_cast<T*>(error_placeholder);
		n_items++;
		lg.unlock();

		if (idx == start) {
			cv.notify_one();
		}
		return *this;
	}

	/*
	 * Returns nullptr if an error occured while downloading the part, otherwise
	 * a pointer to the download result.
	 */
	T* pop() {
		std::unique_lock<std::mutex> lg(access_lock);
		cv.wait(lg, [&]() { return buf[start % buf_size] != nullptr; });

		T* el_ptr = buf[start % buf_size];
		buf[start % buf_size] = nullptr;

		start++;
		n_items--;
		return el_ptr == reinterpret_cast<T*>(error_placeholder) ? nullptr : el_ptr;
	}

	/*
	 * Returns the index of the next part to be downloaded.
	 */
	uint64_t cur_idx() {
		std::unique_lock<std::mutex> lg(access_lock);
		return start;
	}

	uint64_t get_n_items() {
		std::unique_lock<std::mutex> lg(access_lock);
		return n_items;
	}
};

class DownloadManager : public StreamManager {
	friend class GroupDownloadManager;
private:
	typedef std::function<void(std::shared_ptr<Aws::Client::AsyncCallerContext>, bool)> GetPartHandler;
	Aws::String object_id;

	/*
	 * Set if an error occurs during a download.
	 */
	std::atomic_bool error_flag;

	/*
	 * The info from the download result stored in the result queue is the
	 * GetObjectResult and the size in bytes of the downloaded part.
	 */
	AsyncPartManager<std::pair<Aws::S3::Model::GetObjectResult, uint64_t>> result_queue;

	/*
	 * A buffer of the downloaded text. Hold the get_obj_result here because it
	 * is the owner of the buffer.
	 */
	Aws::S3::Model::GetObjectResult get_obj_result;
	Aws::IOStream* buffer;
	/*
	 * The number of bytes in buffer that have yet to be extracted.
	 */
	std::streamsize buffer_bytes_remaining;

	/*
	 * The total size of the S3 object in bytes.
	 */
	uint64_t object_size;

	/*
	 * Atomic variable for the number of outstanding async calls for this download.
	 */
	std::atomic<uint32_t> outstanding_calls;
	std::mutex outstanding_calls_lock;
	std::condition_variable outstanding_calls_cv;

	/*
	 * The chunk number to download next.
	 */
	std::atomic<uint64_t> download_idx;
	/*
	 * The size of chunks to download at a time.
	 */
	uint64_t chunk_size;

	void SetError() {
		error_flag = true;
	}

	void DecrementOutstandingCalls() {
		outstanding_calls_lock.lock();
		outstanding_calls--;
		outstanding_calls_lock.unlock();
		outstanding_calls_cv.notify_one();
	}

	static void GetObjectFinished(
			const GetPartHandler& received_cb,
			const Aws::S3::S3Client* client,
			const Aws::S3::Model::GetObjectRequest& req,
			const Aws::S3::Model::GetObjectOutcome& outcome,
			const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context) {
		(void) client;

		std::shared_ptr<const StreamManager::AsyncContext> async_ctx =
			std::static_pointer_cast<const StreamManager::AsyncContext>(context);
		DownloadManager* download_manager =
			static_cast<DownloadManager*>(async_ctx->GetStreamManager());

		uint64_t download_idx = async_ctx->GetPartN();

		if (!outcome.IsSuccess()) {
			err("%s", outcome.GetError().GetMessage().c_str());
			received_cb(std::const_pointer_cast<Aws::Client::AsyncCallerContext>(context), false);

			download_manager->result_queue.push_error(download_idx);
			download_manager->SetError();
			download_manager->DecrementOutstandingCalls();
			return;
		}

		download_manager->result_queue.push(
				{ const_cast<Aws::S3::Model::GetObjectOutcome&>(outcome).GetResultWithOwnership(),
				async_ctx->GetNBytes() },
				download_idx);

		received_cb(std::const_pointer_cast<Aws::Client::AsyncCallerContext>(context), true);

		download_manager->DecrementOutstandingCalls();
	}

	bool AwaitDownloadPart();

	bool RegisterWithGroupManager();

public:

	DownloadManager(const Aws::S3::S3Client& client, const std::string& bucket,
			const std::string& key) : StreamManager(client, bucket, key),
									  error_flag(false), buffer(nullptr),
									  buffer_bytes_remaining(0),
									  outstanding_calls(0), download_idx(0),
									  chunk_size(S3_MIN_PART_SIZE) {}

	virtual ~DownloadManager() {
	}

	uint64_t GetObjectSize() const {
		return object_size;
	}

	/*
	 * Returns true if all data has been extracted from the S3 Object (including
	 * all data buffered locally)
	 */
	bool AtEOF() {
		return result_queue.cur_idx() * chunk_size >= object_size &&
			buffer_bytes_remaining == 0;
	}

	bool HasError() const {
		return error_flag.load();
	}

	bool StartDownload() {
		// first, get the Object metadata
		Aws::S3::Model::HeadObjectRequest meta_req;
		meta_req.SetBucket(bucket);
		meta_req.SetKey(key);

		Aws::S3::Model::HeadObjectOutcome meta_res =
			client.HeadObject(meta_req);
		if (!meta_res.IsSuccess()) {
			err("%s", meta_res.GetError().GetMessage().c_str());
			return false;
		}

		this->object_size = static_cast<uint64_t>(meta_res.GetResult().GetContentLength());
		this->object_id = meta_res.GetResult().GetETag();

		return RegisterWithGroupManager();
	}

	/*
	 * Initiates a download of the next part. This function is thread safe.
	 */
	bool InitiateDownloadNextPart(const GetPartHandler& received_cb) {
		using namespace std::placeholders;
		uint64_t cur_download_idx = download_idx.load();
		uint64_t start;

		this->outstanding_calls++;
		do {
			start = chunk_size * cur_download_idx;

			if (start >= object_size) {
				// The whole object has already been downloaded.
				DecrementOutstandingCalls();
				return false;
			}
		} while (!this->download_idx.compare_exchange_weak(cur_download_idx,
					cur_download_idx + 1, std::memory_order_release,
					std::memory_order_relaxed));

		// AWS uses inclusive bounds on range selectors.
		uint64_t end = std::min(start + chunk_size, object_size) - 1;

		Aws::S3::Model::GetObjectRequest part_req;
		part_req.SetBucket(bucket);
		part_req.SetKey(key);
		part_req.SetIfMatch(object_id);

		std::ostringstream ostr;
		ostr << "bytes=" << start << "-" << end;
		part_req.SetRange(ostr.str());

		std::shared_ptr<StreamManager::AsyncContext> context =
			Aws::MakeShared<StreamManager::AsyncContext>(
					"StreamManager::AsyncContext", this);
		context->SetUUID(key);
		context->SetNBytes(end - start + 1);
		context->SetPartN(cur_download_idx);

		client.GetObjectAsync(part_req,
				std::bind(DownloadManager::GetObjectFinished, received_cb, _1, _2, _3, _4),
				context);

		return true;
	}

	/*
	 * Downloads and populates text with the next "text_len" characters from
	 * the S3 Object, returning the number of characters successfully read.
	 */
	size_t DownloadText(char* text, size_t text_len) {
		size_t n_chars_read = 0;

		if (text_len == 0 || AtEOF()) {
			return 0;
		}

		if (buffer == nullptr) {
			AwaitDownloadPart();
		}

		do {
			if (HasError()) {
				return n_chars_read;
			}

			std::streamsize n_bytes =
				std::min(static_cast<std::streamsize>(text_len - n_chars_read),
						buffer_bytes_remaining);

			buffer->read(text + n_chars_read, n_bytes);

			std::streamsize bytes_read = buffer->gcount();
			n_chars_read += static_cast<size_t>(bytes_read);
			buffer_bytes_remaining -= bytes_read;

			if (n_bytes != bytes_read) {
				break;
			}

		} while (n_chars_read < text_len && !AtEOF() && AwaitDownloadPart());

		return n_chars_read;
	}

	bool AwaitAllDownloads();

	virtual int serialize(file_proxy_t* dst) {
		if (this->StreamManager::serialize(dst) != 0) {
			return -1;
		}

		err("Serialization of DownloadManager is unimplemented");
		return -1;
	}

	virtual int deserialize(file_proxy_t* src) {
		if (this->StreamManager::deserialize(src) != 0) {
			return -1;
		}

		err("Derialization of DownloadManager is unimplemented");
		return -1;
	}
};

/*
 * Manages the concurrent downloading of multiple S3 objects.
 */
class GroupDownloadManager {
private:
	std::mutex access_lock;
	std::deque<DownloadManager*> dms;
	const uint32_t max_async_downloads;

	// the current number of concurrent async downloads
	uint32_t async_downloads;

	static void PartDownloadComplete(GroupDownloadManager* gdm,
			std::shared_ptr<Aws::Client::AsyncCallerContext> context,
			bool success) {
		(void) context;

		if (success) {
			std::unique_lock<std::mutex> lg(gdm->access_lock);

			// for exponential rampup, try initiating two downloads
			gdm->StartNextPart();
			gdm->StartNextPart();
		}
	}

	/*
	 * Attempts to start downloading another part. If the number of outstanding
	 * downloads is max_async_downloads, nothing happens.
	 *
	 * Must be called with access_lock held.
	 *
	 * Returns false only if an error occurred, not if the attempt to start
	 * downloading another part failed because the number of outstanding
	 * download was maxed out.
	 */
	bool StartNextPart() {
		using namespace std::placeholders;

		if (async_downloads >= max_async_downloads) {
			return true;
		}
		if (dms.empty()) {
			return true;
		}

		async_downloads++;
		DownloadManager* next = dms.front();

		// place next back on the end of the queue if it has more parts that
		// need to be downloaded.
		dms.pop_front();

		if (next->InitiateDownloadNextPart(std::bind(PartDownloadComplete, this, _1, _2))) {
			dms.push_back(next);
			return true;
		}
		else {
			return false;
		}
	}

public:
	GroupDownloadManager(uint32_t max_async_downloads) :
		max_async_downloads(max_async_downloads), async_downloads(0) {}

	bool RegisterDownloadManager(DownloadManager* dm) {
		std::unique_lock<std::mutex> lg(access_lock);
		dms.push_back(dm);

		StartNextPart();
		return true;
	}

	void RemoveDownloadManager(DownloadManager* dm) {
		std::unique_lock<std::mutex> lg(access_lock);

		for (std::deque<DownloadManager*>::const_iterator it = dms.cbegin();
				it != dms.cend(); it++) {
			if (*it == dm) {
				dms.erase(it);
				return;
			}
		}
	}

	/*
	 * Called when a download part is fully downloaded and no longer queued for
	 * consuming.
	 */
	void PartComplete(bool success) {
		std::unique_lock<std::mutex> lg(access_lock);
		async_downloads--;

		if (success) {
			StartNextPart();
		}
	}

	void PartsComplete(bool success, uint32_t n_parts) {
		std::unique_lock<std::mutex> lg(access_lock);
		async_downloads -= n_parts;

		if (success) {
			for (uint32_t i = 0; i < n_parts; i++) {
				StartNextPart();
			}
		}
	}

};

GroupDownloadManager* S3API::GetGroupDownloadManager() {
	std::call_once(init_group_dowloader_once, [&]() {
		group_download_manager = std::make_unique<GroupDownloadManager>(max_async_downloads);
	});

	return group_download_manager.get();
}

bool DownloadManager::AwaitDownloadPart() {
	uint64_t idx = result_queue.start;

	std::pair<Aws::S3::Model::GetObjectResult, uint64_t>* res = result_queue.pop();
	g_api.GetGroupDownloadManager()->PartComplete(true);
	if (res == nullptr) {
		SetError();
		return false;
	}

	get_obj_result = std::move(res->first);
	buffer = &get_obj_result.GetBody();
	buffer_bytes_remaining = static_cast<std::streamsize>(res->second);

	delete res;

	return true;
}

bool DownloadManager::RegisterWithGroupManager() {
	return g_api.GetGroupDownloadManager()->RegisterDownloadManager(this);
}

bool DownloadManager::AwaitAllDownloads() {
	GroupDownloadManager* gdm = g_api.GetGroupDownloadManager();
	gdm->RemoveDownloadManager(this);

	// wait for all outstanding async calls to complete
	std::unique_lock<std::mutex> lg(outstanding_calls_lock);
	outstanding_calls_cv.wait(lg, [&]() { return this->outstanding_calls == 0; });
	lg.unlock();

	// Mark all of the parts in result_queue as complete
	gdm->PartsComplete(false, uint32_t(result_queue.get_n_items()));
	return true;
}

/*
 * Used to simplify deleting many objects from an S3 bucket, buffering the
 * objects ID's to delete and sending DeleteObjects requests with them in
 * groups, rather than sending a DeleteObject request for each object.
 */
class DeleteObjectsBuffer {
private:
	// max number of objects that can be deleted in a single delete objects
	// request
	static constexpr const uint64_t max_delete_objs = 1000;

	const Aws::S3::S3Client& client;
	const Aws::String bucket;
	Aws::Vector<Aws::S3::Model::ObjectIdentifier> ids;

public:

	DeleteObjectsBuffer(const Aws::S3::S3Client& client,
			const Aws::String& bucket) : client(client),
										 bucket(bucket) {}

	bool DeleteObject(const Aws::String& key) {
		ids.push_back(Aws::S3::Model::ObjectIdentifier().WithKey(key));

		if (ids.size() >= max_delete_objs) {
			return Flush();
		}
		return true;
	}

	bool Flush() {
		if (ids.size() > 0) {
			Aws::S3::Model::Delete del;
			del.SetObjects(std::move(ids));

			Aws::S3::Model::DeleteObjectsRequest req;
			req.SetBucket(bucket);
			req.SetDelete(std::move(del));

			Aws::S3::Model::DeleteObjectsOutcome res = client.DeleteObjects(req);
			if (!res.IsSuccess()) {
				err("Delete object request failed: %s",
						res.GetError().GetMessage().c_str());
				return false;
			}

			ids.clear();
		}
		return true;
	}
};


//==========================================================
// Forward Declarations.
//

extern "C" {

void s3_set_region(const char* region);
void s3_set_endpoint(const char* endpoint);

off_t s3_get_file_size(const char* bucket, const char* key);
bool s3_delete_object(const char* bucket, const char* key);
bool s3_delete_directory(const char* bucket, const char* prefix);

bool s3_prepare_output_file(const backup_config_t* conf, const char* bucket,
		const char* key);
bool s3_scan_directory(const backup_config_t* conf,
		const backup_status_t* status, backup_state_t* backup_state,
		const char* bucket, const char* key);
bool s3_get_backup_files(const char* bucket, const char* key,
		as_vector* file_vec);

void file_proxy_s3_shutdown();
extern int file_proxy_s3_write_init(file_proxy_t*, const char* bucket, const char* key,
		uint64_t max_file_size);
extern int file_proxy_s3_read_init(file_proxy_t*, const char* bucket, const char* key);
int file_proxy_s3_close(file_proxy_t*, uint8_t mode);
int file_proxy_s3_serialize(const file_proxy_t*, file_proxy_t* dst);
int file_proxy_s3_deserialize(file_proxy_t*, file_proxy_t* src,
		const char* bucket, const char* key);
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
s3_set_max_async_uploads(uint32_t max_async_uploads)
{
	g_api.SetMaxAsyncUploads(max_async_uploads);
}

void
s3_disable_request_processing()
{
	if (g_api.IsInitialized()) {
		const_cast<Aws::S3::S3Client&>(g_api.GetS3Client()).DisableRequestProcessing();
	}
}

/*
 * Return the size of the given S3 object in bytes, or -1 on error.
 */
off_t
s3_get_file_size(const char* bucket, const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	Aws::S3::Model::HeadObjectRequest meta_req;
	meta_req.SetBucket(bucket);
	meta_req.SetKey(key);

	Aws::S3::Model::HeadObjectOutcome meta_res = client.HeadObject(meta_req);
	if (!meta_res.IsSuccess()) {
		err("%s", meta_res.GetError().GetMessage().c_str());
		return -1;
	}

	return static_cast<off_t>(meta_res.GetResult().GetContentLength());
}

/*
 * Delete the given S3 object.
 */
bool
s3_delete_object(const char* bucket, const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	DeleteObjectsBuffer del_buffer(client, bucket);
	del_buffer.DeleteObject(key);
	return del_buffer.Flush();
}

/*
 * Delete all S3 objects with given prefix ending in ".asb".
 */
bool
s3_delete_directory(const char* bucket, const char* prefix)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	DeleteObjectsBuffer del_buffer(client, bucket);

	Aws::S3::Model::ListObjectsRequest req;
	req.SetBucket(bucket);
	req.SetPrefix(prefix);

	Aws::S3::Model::ListObjectsOutcome res = client.ListObjects(req);
	if (!res.IsSuccess()) {
		err("%s", res.GetError().GetMessage().c_str());
		return false;
	}

	for (const Aws::S3::Model::Object& object : res.GetResult().GetContents()) {
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
	ureq.SetBucket(bucket);
	ureq.SetPrefix(prefix);

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
			if (!_abort_upload(bucket, upload)) {
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
s3_prepare_output_file(const backup_config_t* conf, const char* bucket,
		const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	// first, get the Object metadata
	Aws::S3::Model::HeadObjectRequest meta_req;
	meta_req.SetBucket(bucket);
	meta_req.SetKey(key);

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
					bucket, key);
			return false;
		}

		if (!s3_delete_object(bucket, key)) {
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
		backup_state_t* backup_state, const char* bucket, const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	int64_t obj_count = _scan_objects(conf, backup_state, bucket, key);
	if (obj_count < 0) {
		return false;
	}

	int64_t upload_req_count = _scan_upload_requests(conf, backup_state, bucket, key);
	if (upload_req_count < 0) {
		return false;
	}

	if (static_cast<uint64_t>(obj_count + upload_req_count) != status->file_count) {
		err("Expected %" PRIu64 " backup files, but found %" PRIu64,
				status->file_count, obj_count + upload_req_count);
		return false;
	}

	return true;
}

/*
 * Scans the given bucket for all files with prefix "key" and populates file_vec
 * with the names of all files ending in ".asb" found.
 */
bool s3_get_backup_files(const char* bucket, const char* key,
		as_vector* file_vec)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return false;
	}

	const Aws::S3::S3Client& client = g_api.GetS3Client();

	size_t prefix_len = strlen(S3_PREFIX) + strlen(bucket) + 1;

	Aws::S3::Model::ListObjectsRequest req;
	req.SetBucket(bucket);
	req.SetPrefix(key);

	Aws::S3::Model::ListObjectsOutcome res = client.ListObjects(req);
	if (!res.IsSuccess()) {
		err("%s", res.GetError().GetMessage().c_str());
		return false;
	}

	for (const Aws::S3::Model::Object& object : res.GetResult().GetContents()) {
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
					S3_PREFIX "%s/%s", bucket, obj_key.c_str());
			as_vector_append(file_vec, &elem);
		}
	}

	return true;

cleanup:
	for (uint32_t i = 0; i < file_vec->size; ++i) {
		cf_free(as_vector_get_ptr(file_vec, i));
	}

	as_vector_clear(file_vec);

	return false;
}

int
file_proxy_s3_write_init(file_proxy_t* f, const char* bucket, const char* key,
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

	f->s3.s3_state = new UploadManager(g_api.GetS3Client(), bucket, key,
			_calc_part_size(max_file_size));
	if (!static_cast<UploadManager*>(f->s3.s3_state)->StartUpload()) {
		return -1;
	}

	return 0;
}

int
file_proxy_s3_read_init(file_proxy_t* f, const char* bucket, const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	f->s3.s3_state = new DownloadManager(g_api.GetS3Client(), bucket, key);
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
		const char* bucket, const char* key)
{
	// if this is the first thread to access S3, we have to initialize the AWS
	// SDK
	if (!g_api.TryInitialize()) {
		return -1;
	}

	switch (file_proxy_get_mode(f)) {
		case FILE_PROXY_WRITE_MODE:
			f->s3.s3_state = new UploadManager(g_api.GetS3Client(), bucket, key, 0);
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

	Aws::S3::Model::ListObjectsRequest req;
	req.SetBucket(bucket);
	req.SetPrefix(key);

	Aws::S3::Model::ListObjectsOutcome res = client.ListObjects(req);
	if (!res.IsSuccess()) {
		err("%s", res.GetError().GetMessage().c_str());
		return -1;
	}

	for (const Aws::S3::Model::Object& object : res.GetResult().GetContents()) {
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

