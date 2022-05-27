/*
 * Aerospike S3 API
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

#include <condition_variable>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3/S3Client.h>

#pragma GCC diagnostic pop

#include <download_manager.h>


//==========================================================
// Class Declarations.
//

class S3API {
public:

	S3API();

	bool TryInitialize();

	void Shutdown();

	bool IsInitialized() const;

	// This must be called before TryInitialize()
	S3API& SetRegion(const std::string& region);

	// This must be called before TryInitialize()
	S3API& SetProfile(const std::string& profile);

	// This must be called before TryInitialize()
	S3API& SetEndpoint(const std::string& endpoint);

	S3API& SetLogLevel(Aws::Utils::Logging::LogLevel logLevel);

	S3API& SetMaxAsyncDownloads(uint32_t max_async_downloads);

	S3API& SetMaxAsyncUploads(uint32_t max_async_uploads);

	GroupDownloadManager* GetGroupDownloadManager();

	const std::string& GetRegion() const;

	const std::string& GetProfile() const;

	const std::string& GetEndpoint() const;

	const Aws::S3::S3Client& GetS3Client() const;

	/*
	 * Ensures that less than max_async_uploads outstanding async upload
	 * requests exist, and blocking until at least one finishes if necessary.
	 */
	void RegisterAsyncUpload();

	/*
	 * To be called after an async call has returned, freeing up a slot for
	 * another async upload to be made.
	 */
	void FinishAsyncUpload();

private:
	std::once_flag init_once;
	bool initialized;
	Aws::SDKOptions options;

	std::string region;
	std::string profile;
	std::string endpoint;
	Aws::Utils::Logging::LogLevel logLevel;

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

	static void _init_api(S3API& s3_api);

	static void _RegisterAsync(std::mutex& lock, std::condition_variable& cv,
			std::atomic<uint32_t>& n, uint32_t max_n);

	static void _FinishAsync(std::mutex& lock, std::condition_variable& cv,
			std::atomic<uint32_t>& n, uint32_t max_n);

};

// The global S3API object.
extern S3API g_api;

