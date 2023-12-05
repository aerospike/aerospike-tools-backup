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

#include <s3_api.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>

#pragma GCC diagnostic pop

#include <asbackup_logger.h>
#include <utils.h>


//==========================================================
// Globals.
//

S3API g_api;


//==========================================================
// Class Definitions - S3API
//

S3API::S3API() : initialized(false),
				 logLevel(Aws::Utils::Logging::LogLevel::Off),
				 client(nullptr),
				 async_uploads(0) {}

bool
S3API::TryInitialize()
{
	std::unique_lock<std::mutex> lg(s3_init_lock);
	if(!initialized) {
		_init_api(std::ref(*this));
	}

	return initialized;
}

void
S3API::Shutdown()
{
	std::unique_lock<std::mutex> lg(s3_init_lock);
	if (initialized) {
		inf("Closing S3 API");
		if (client != nullptr) {
			delete client;
		}

		Aws::ShutdownAPI(options);
		initialized = false;
	}
}

bool
S3API::IsInitialized()
{
	std::unique_lock<std::mutex> lg(s3_init_lock);
	return initialized;
}

S3API&
S3API::SetRegion(const std::string& region)
{
	if (IsInitialized()) {
		err("Cannot set region after initializing S3 API");
	}
	else {
		this->region = region;
	}
	return *this;
}

S3API&
S3API::SetProfile(const std::string& profile)
{
	if (IsInitialized()) {
		err("Cannot set profile after initializing S3 API");
	}
	else {
		this->profile = profile;
	}
	return *this;
}

S3API&
S3API::SetEndpoint(const std::string& endpoint)
{
	if (IsInitialized()) {
		err("Cannot set endpoint after initializing S3 API");
	}
	else {
		this->endpoint = endpoint;
	}
	return *this;
}

S3API&
S3API::SetLogLevel(Aws::Utils::Logging::LogLevel logLevel)
{
	if (IsInitialized()) {
		err("Cannot set log level after initializing S3 API");
	}
	else {
		this->logLevel = logLevel;
	}
	return *this;
}

S3API&
S3API::SetMaxAsyncDownloads(uint32_t max_async_downloads)
{
	this->max_async_downloads = max_async_downloads;
	return *this;
}

S3API&
S3API::SetMaxAsyncUploads(uint32_t max_async_uploads)
{
	this->max_async_uploads = max_async_uploads;
	return *this;
}

S3API&
S3API::SetConnectTimeoutMS(uint32_t connect_timeout_ms)
{
	this->connect_timeout_ms = connect_timeout_ms;
	return *this;
}

GroupDownloadManager*
S3API::GetGroupDownloadManager()
{
	std::call_once(init_group_dowloader_once, [&]() {
		group_download_manager = std::make_unique<GroupDownloadManager>(max_async_downloads);
	});

	return group_download_manager.get();
}

const std::string&
S3API::GetRegion() const
{
	return region;
}

const std::string&
S3API::GetBucket() const
{
	return bucket;
}

const std::string&
S3API::GetProfile() const
{
	return profile;
}

const std::string&
S3API::GetEndpoint() const
{
	return endpoint;
}

const Aws::S3::S3Client&
S3API::GetS3Client() const
{
	return *client;
}

void
S3API::RegisterAsyncUpload()
{
	_RegisterAsync(async_uploads_lock, async_uploads_cv, async_uploads,
			max_async_uploads);
}

void
S3API::FinishAsyncUpload()
{
	_FinishAsync(async_uploads_lock, async_uploads_cv, async_uploads,
			max_async_uploads);
}


const std::string&
S3API::S3Path::GetKey() const
{
	return key;
}

const std::string&
S3API::S3Path::GetBucket() const
{
	return bucket;
}

bool
S3API::S3Path::ParsePath(const std::string& bucket, const std::string& path)
{
	if (bucket.size() == 0) {
		// path is in the format "s3://<bucket>/<key>"
		size_t delim = path.find('/', S3_PREFIX_LEN);

		if (delim == std::string::npos) {
			err("Failed to parse S3 path \"%s\", bucket name not followed by "
					"'/'.", path.c_str());
			return false;
		}

		this->bucket = path.substr(S3_PREFIX_LEN, delim - S3_PREFIX_LEN);
		this->key = path.substr(delim + 1);
	}
	else {
		this->bucket = bucket;
		this->key = path.substr(S3_PREFIX_LEN);
	}

	return true;
}


std::pair<S3API::S3Path, bool>
S3API::ParseS3Path(const std::string& path) const
{
	S3API::S3Path path_obj;
	if (!path_obj.ParsePath(this->bucket, path)) {
		return std::pair<S3API::S3Path, bool>(S3API::S3Path(), false);
	}

	return std::pair<S3API::S3Path, bool>(std::move(path_obj), true);
}

void
S3API::_init_api(S3API& s3_api)
{
	inf("Initializing S3 API");

	s3_api.options.loggingOptions.logLevel = s3_api.logLevel;
	s3_api.options.loggingOptions.logger_create_fn = [&s3_api]() {
		return Aws::MakeShared<AsbackupLogger>(
				"AsbackupLogger",
				s3_api.logLevel);
	};
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

	conf.maxConnections = std::max(s3_api.max_async_downloads,
			s3_api.max_async_uploads);
	
	conf.connectTimeoutMs = s3_api.connect_timeout_ms;

	s3_api.client = new Aws::S3::S3Client(
			std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>(),
			conf,
			Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always,
			false);

	s3_api.initialized = true;
}

void
S3API::_RegisterAsync(std::mutex& lock, std::condition_variable& cv,
		std::atomic<uint32_t>& n, uint32_t max_n)
{
	std::unique_lock<std::mutex> lg(lock);

	while (n >= max_n) {
		cv.wait(lg, [&]() { return n < max_n; });
	}

	n++;
}

void
S3API::_FinishAsync(std::mutex& lock, std::condition_variable& cv,
		std::atomic<uint32_t>& n, uint32_t max_n)
{
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

