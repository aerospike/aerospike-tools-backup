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

#include <upload_manager.h>

#include <aws/s3/model/AbortMultipartUploadRequest.h>

#include <s3_api.h>


//==========================================================
// Class Definitions - UploadManager
//

UploadManager::UploadManager(const Aws::S3::S3Client& client, const std::string& bucket,
		const std::string& key, uint64_t min_part_size) : StreamManager(client, bucket, key),
														  do_content_hash(true),
														  part_number(1),
														  min_part_size(min_part_size),
														  outstanding_calls(0) {}

UploadManager::~UploadManager() {}

const Aws::String
UploadManager::GetUploadId() const
{
	return upload_id;
}

void
UploadManager::AwaitAsyncUploads()
{
	std::unique_lock<std::mutex> lg(outstanding_calls_lock);
	outstanding_calls_cv.wait(lg, [&]() { return outstanding_calls == 0; });
}

bool
UploadManager::StartUpload()
{
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

uint64_t
UploadManager::UploadText(const char* text, size_t text_len)
{
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

bool
UploadManager::FinishUpload()
{
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

bool
UploadManager::AbortUpload()
{
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

int
UploadManager::serialize(file_proxy_t* dst)
{
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

int
UploadManager::deserialize(file_proxy_t* src)
{
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


void
UploadManager::DecrementOutstandingCalls()
{
	outstanding_calls_lock.lock();
	outstanding_calls--;
	outstanding_calls_lock.unlock();
	outstanding_calls_cv.notify_one();
}

void
UploadManager::UploadPartFinished(const Aws::S3::S3Client* client,
		const Aws::S3::Model::UploadPartRequest& req,
		const Aws::S3::Model::UploadPartOutcome& outcome,
		const std::shared_ptr<const Aws::Client::AsyncCallerContext>& context)
{
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

bool
UploadManager::_UploadPart(int part_number,
		std::shared_ptr<Aws::StringStream>& body)
{
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

bool
UploadManager::_UploadNextPart()
{
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


//==========================================================
// Class Definitions - UploadManager::FailedPart
//

UploadManager::FailedPart::FailedPart() : part_number(-1) {}

UploadManager::FailedPart::FailedPart(int part_number,
		std::shared_ptr<Aws::StringStream> buffer) : buffer(buffer),
													 part_number(part_number) {}

bool
UploadManager::FailedPart::RetryUpload(UploadManager& upload_manager)
{
	return upload_manager._UploadPart(part_number, buffer);
}

bool
UploadManager::FailedPart::Serialize(file_proxy_t* dst) const
{
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

bool
UploadManager::FailedPart::Deserialize(file_proxy_t* src)
{
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

