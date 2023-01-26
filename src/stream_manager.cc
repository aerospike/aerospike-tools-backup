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

#include <stream_manager.h>


//==========================================================
// Class Definitions - StreamManager
//

StreamManager::StreamManager(const Aws::S3::S3Client& client,
		const std::string bucket, const std::string key) : client(client),
														   bucket(bucket),
														   key(key)
{}

const std::string&
StreamManager::GetBucket() const
{
	return bucket;
}

const std::string&
StreamManager::GetKey() const
{
	return key;
}

int
StreamManager::serialize(file_proxy_t* dst)
{
	// Don't do anything: bucket/key are provided on construction, so no
	// need to save them.
	(void) dst;
	return 0;
}

int StreamManager::deserialize(file_proxy_t* src)
{
	(void) src;
	return 0;
}

bool
StreamManager::SerializeString(const Aws::String& str, file_proxy_t* dst)
{
	if (!write_int32(static_cast<uint32_t>(str.size()), dst)) {
		return false;
	}

	if (file_proxy_write(dst, str.c_str(), str.size()) != str.size()) {
		return false;
	}

	return true;
}

bool
StreamManager::DeserializeString(Aws::String& str, file_proxy_t* src)
{
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

bool
StreamManager::SerializeSStream(const Aws::StringStream& str, file_proxy_t* dst)
{
	const Aws::String s = str.str();
	if (!write_int32(static_cast<uint32_t>(s.size()), dst)) {
		return false;
	}

	if (file_proxy_write(dst, s.c_str(), s.size()) != s.size()) {
		return false;
	}

	return true;
}

bool
StreamManager::DeserializeSStream(Aws::StringStream& str, file_proxy_t* src)
{
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


//==========================================================
// Class Definitions - StreamManager::AsyncContext
//

StreamManager::AsyncContext::AsyncContext(StreamManager* sm) : sm(sm) {}

StreamManager*
StreamManager::AsyncContext::GetStreamManager() const
{
	return const_cast<StreamManager*>(sm);
}

void
StreamManager::AsyncContext::SetNBytes(uint64_t n_bytes)
{
	this->n_bytes = n_bytes;
}

uint64_t
StreamManager::AsyncContext::GetNBytes() const
{
	return n_bytes;
}

void
StreamManager::AsyncContext::SetPartN(uint64_t part_n)
{
	this->part_n = part_n;
}

uint64_t
StreamManager::AsyncContext::GetPartN() const
{
	return part_n;
}

