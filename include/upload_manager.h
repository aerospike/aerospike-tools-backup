/*
 * Aerospike Upload Manager
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/utils/HashingUtils.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/CreateMultipartUploadRequest.h>
#include <aws/s3/model/CompleteMultipartUploadRequest.h>
#include <aws/s3/model/UploadPartRequest.h>

#pragma GCC diagnostic pop

#include <backup.h>
#include <file_proxy.h>
#include <stream_manager.h>
#include <utils.h>


//==========================================================
// Class Declarations.
//

class UploadManager : public StreamManager {
public:

	UploadManager(const Aws::S3::S3Client& client, const std::string& bucket,
			const std::string& key, uint64_t min_part_size);

	virtual ~UploadManager();

	const Aws::String GetUploadId() const;

	/*
	 * Blocks until all async calls have finished running.
	 */
	void AwaitAsyncUploads();

	bool StartUpload();

	/*
	 * Uploads a block text to S3 in chunks, returning the number of characters
	 * successfully written.
	 */
	uint64_t UploadText(const char* text, size_t text_len);

	/*
	 * Commits the uploaded file to S3, making a CompleteMultipartUpload request
	 * and finalizing the object. It can no longer be modified after this
	 * operation.
	 *
	 * This must be called after Flush to ensure all parts have finished
	 * uploading.
	 */
	bool FinishUpload();

	/*
	 * Abort the current running MultipartUpload, clearing all cached data held
	 * on S3.
	 */
	bool AbortUpload();

	virtual int serialize(file_proxy_t* dst);

	virtual int deserialize(file_proxy_t* src);

private:
	// Forward declaration
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

	void DecrementOutstandingCalls();

	static void UploadPartFinished(const Aws::S3::S3Client* client,
			const Aws::S3::Model::UploadPartRequest& req,
			const Aws::S3::Model::UploadPartOutcome& outcome,
			const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context);

	bool _UploadPart(int part_number, std::shared_ptr<Aws::StringStream>& body);

	bool _UploadNextPart();

	class FailedPart {
	public:

		FailedPart();

		/*
		 * Constructs a failed part from the part number and text buffer that
		 * failed to upload.
		 */
		FailedPart(int part_number, std::shared_ptr<Aws::StringStream> buffer);

		/*
		 * Retries a failed upload.
		 */
		bool RetryUpload(UploadManager& upload_manager);

		bool Serialize(file_proxy_t* dst) const;

		bool Deserialize(file_proxy_t* src);

	private:
		std::shared_ptr<Aws::StringStream> buffer;
		int part_number;

	};

};


