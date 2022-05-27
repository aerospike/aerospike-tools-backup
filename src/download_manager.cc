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

#include <download_manager.h>

#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/s3/model/HeadObjectRequest.h>

#pragma GCC diagnostic warning "-Wsign-conversion"

#include <s3_api.h>


//==========================================================
// Class Definitions - DownloadManager
//

DownloadManager::DownloadManager(const Aws::S3::S3Client& client,
		const std::string& bucket, const std::string& key)
		: StreamManager(client, bucket, key),
		  error_flag(false),
		  buffer(nullptr),
		  buffer_bytes_remaining(0),
		  outstanding_calls(0),
		  download_idx(0),
		  chunk_size(S3_MIN_PART_SIZE) {}

DownloadManager::~DownloadManager() {}

uint64_t
DownloadManager::GetObjectSize() const
{
	return object_size;
}

bool
DownloadManager::AtEOF()
{
	return result_queue.cur_idx() * chunk_size >= object_size &&
		buffer_bytes_remaining == 0;
}

bool
DownloadManager::HasError() const
{
	return error_flag.load();
}

bool
DownloadManager::StartDownload()
{
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

bool
DownloadManager::InitiateDownloadNextPart(const GetPartHandler& received_cb)
{
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

size_t
DownloadManager::DownloadText(char* text, size_t text_len)
{
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

bool
DownloadManager::AwaitAllDownloads()
{
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

int
DownloadManager::serialize(file_proxy_t* dst)
{
	if (this->StreamManager::serialize(dst) != 0) {
		return -1;
	}

	err("Serialization of DownloadManager is unimplemented");
	return -1;
}

int
DownloadManager::deserialize(file_proxy_t* src)
{
	if (this->StreamManager::deserialize(src) != 0) {
		return -1;
	}

	err("Derialization of DownloadManager is unimplemented");
	return -1;
}

void
DownloadManager::SetError()
{
	error_flag = true;
}

void
DownloadManager::DecrementOutstandingCalls()
{
	outstanding_calls_lock.lock();
	outstanding_calls--;
	outstanding_calls_lock.unlock();
	outstanding_calls_cv.notify_one();
}

void
DownloadManager::GetObjectFinished(
		const GetPartHandler& received_cb,
		const Aws::S3::S3Client* client,
		const Aws::S3::Model::GetObjectRequest& req,
		const Aws::S3::Model::GetObjectOutcome& outcome,
		const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context)
{
	(void) client;
	(void) req;

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

bool
DownloadManager::AwaitDownloadPart()
{
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

bool
DownloadManager::RegisterWithGroupManager()
{
	return g_api.GetGroupDownloadManager()->RegisterDownloadManager(this);
}


//==========================================================
// Class Definitions - GroupDownloadManager
//

GroupDownloadManager::GroupDownloadManager(uint32_t max_async_downloads) :
		max_async_downloads(max_async_downloads),
		async_downloads(0) {}

bool
GroupDownloadManager::RegisterDownloadManager(DownloadManager* dm)
{
	std::unique_lock<std::mutex> lg(access_lock);
	dms.push_back(dm);

	StartNextPart();
	return true;
}

void
GroupDownloadManager::RemoveDownloadManager(DownloadManager* dm)
{
	std::unique_lock<std::mutex> lg(access_lock);

	for (std::deque<DownloadManager*>::const_iterator it = dms.cbegin();
			it != dms.cend(); it++) {
		if (*it == dm) {
			dms.erase(it);
			return;
		}
	}
}

void
GroupDownloadManager::PartComplete(bool success)
{
	std::unique_lock<std::mutex> lg(access_lock);
	async_downloads--;

	if (success) {
		StartNextPart();
	}
}

void
GroupDownloadManager::PartsComplete(bool success, uint32_t n_parts)
{
	std::unique_lock<std::mutex> lg(access_lock);
	async_downloads -= n_parts;

	if (success) {
		for (uint32_t i = 0; i < n_parts; i++) {
			StartNextPart();
		}
	}
}

void
GroupDownloadManager::PartDownloadComplete(GroupDownloadManager* gdm,
		std::shared_ptr<Aws::Client::AsyncCallerContext> context,
		bool success)
{
	(void) context;

	if (success) {
		std::unique_lock<std::mutex> lg(gdm->access_lock);

		// for exponential rampup, try initiating two downloads
		gdm->StartNextPart();
		gdm->StartNextPart();
	}
}

bool
GroupDownloadManager::StartNextPart()
{
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

