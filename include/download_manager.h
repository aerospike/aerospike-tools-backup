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
#include <deque>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/core/Aws.h>
#include <aws/s3/model/GetObjectRequest.h>

#pragma GCC diagnostic pop

#include <stream_manager.h>


//==========================================================
// Class Declarations - AsyncPartManager
//

/*
 * Manages the concurrent downloading of multiple S3 object parts.
 */
template<class T>
class AsyncPartManager {
public:

	static constexpr intptr_t error_placeholder = -1;

	AsyncPartManager() : buf_size(4),
						 start(0),
						 n_items(0)
	{
		buf = new T*[buf_size]();
	}

	~AsyncPartManager()
	{
		std::unique_lock<std::mutex> lg(access_lock);
		for (uint64_t i = 0; i < buf_size; i++) {
			if (buf[i] != nullptr && buf[i] != reinterpret_cast<T*>(error_placeholder)) {
				delete buf[i];
			}
		}
		delete[] buf;
	}

	AsyncPartManager& push(T&& t, uint64_t idx)
	{
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

	AsyncPartManager& push_error(uint64_t idx)
	{
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
	T* pop()
	{
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
	uint64_t cur_idx()
	{
		std::unique_lock<std::mutex> lg(access_lock);
		return start;
	}

	uint64_t get_n_items()
	{
		std::unique_lock<std::mutex> lg(access_lock);
		return n_items;
	}

private:
	T** buf;
	// the size of buf in terms of sizeof(T)
	uint64_t buf_size;
	// the index of the next element to be popped
	uint64_t start;
	// the number of items in buf
	uint64_t n_items;

	std::mutex access_lock;
	std::condition_variable cv;

	void _Accomodate(uint64_t idx)
	{
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

};


//==========================================================
// Class Declarations - DownloadManager
//

class DownloadManager : public StreamManager {
	friend class GroupDownloadManager;
private:
	typedef std::function<void(std::shared_ptr<Aws::Client::AsyncCallerContext>, bool)> GetPartHandler;

public:

	DownloadManager(const Aws::S3::S3Client& client, const std::string& bucket,
			const std::string& key);

	virtual ~DownloadManager();

	uint64_t GetObjectSize() const;

	/*
	 * Returns true if all data has been extracted from the S3 Object (including
	 * all data buffered locally)
	 */
	bool AtEOF();

	bool HasError() const;

	bool StartDownload();

	/*
	 * Initiates a download of the next part. This function is thread safe.
	 */
	bool InitiateDownloadNextPart(const GetPartHandler& received_cb);

	/*
	 * Downloads and populates text with the next "text_len" characters from
	 * the S3 Object, returning the number of characters successfully read.
	 */
	size_t DownloadText(char* text, size_t text_len);

	bool AwaitAllDownloads();

	virtual int serialize(file_proxy_t* dst);

	virtual int deserialize(file_proxy_t* src);

private:
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

	void SetError();

	void DecrementOutstandingCalls();

	static void GetObjectFinished(
			const GetPartHandler& received_cb,
			const Aws::S3::S3Client* client,
			const Aws::S3::Model::GetObjectRequest& req,
			const Aws::S3::Model::GetObjectOutcome& outcome,
			const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context);

	bool AwaitDownloadPart();

	bool RegisterWithGroupManager();

};


//==========================================================
// Class Declarations - GroupDownloadManager
//

/*
 * Manages the concurrent downloading of multiple S3 objects.
 */
class GroupDownloadManager {
public:
	GroupDownloadManager(uint32_t max_async_downloads);

	bool RegisterDownloadManager(DownloadManager* dm);

	void RemoveDownloadManager(DownloadManager* dm);

	/*
	 * Called when a download part is fully downloaded and no longer queued for
	 * consuming.
	 */
	void PartComplete(bool success);

	void PartsComplete(bool success, uint32_t n_parts);

private:
	std::mutex access_lock;
	std::deque<DownloadManager*> dms;
	const uint32_t max_async_downloads;

	// the current number of concurrent async downloads
	uint32_t async_downloads;

	static void PartDownloadComplete(GroupDownloadManager* gdm,
			std::shared_ptr<Aws::Client::AsyncCallerContext> context,
			bool success);

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
	bool StartNextPart();

};

