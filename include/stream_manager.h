/*
 * Aerospike Stream Manager
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

#include <aws/s3/S3Client.h>

#pragma GCC diagnostic pop

#include <file_proxy.h>
#include <utils.h>


//==========================================================
// Class Declarations.
//

class StreamManager {
public:

	StreamManager(const Aws::S3::S3Client& client, const std::string bucket,
			const std::string key);

	virtual ~StreamManager() = default;

	const std::string& GetBucket() const;

	const std::string& GetKey() const;

	virtual int serialize(file_proxy_t* dst);

	virtual int deserialize(file_proxy_t* src);

	static bool SerializeString(const Aws::String& str, file_proxy_t* dst);

	static bool DeserializeString(Aws::String& str, file_proxy_t* src);

	static bool SerializeSStream(const Aws::StringStream& str, file_proxy_t* dst);

	static bool DeserializeSStream(Aws::StringStream& str, file_proxy_t* src);

	template<typename T>
	static bool SerializeVector(file_proxy_t* dst, const std::vector<T>& v,
			std::function<bool(file_proxy_t*, const T&)> serializer)
	{
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
			const std::vector<Serializable>& v)
	{
		std::function<bool(file_proxy_t*, const Serializable&)> serialize_fn =
			[](file_proxy_t* dst, const Serializable& el) {
			return el.Serialize(dst);
		};
		return SerializeVector(dst, v, serialize_fn);
	}

	template<typename T>
	static bool DeserializeVector(file_proxy_t* src, std::vector<T>& v,
			std::function<bool(file_proxy_t*, T&)> deserializer)
	{
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
			std::vector<Serializable>& v)
	{
		std::function<bool(file_proxy_t*, Serializable&)> deserialize_fn =
			[](file_proxy_t* src, Serializable& el) {
			return el.Deserialize(src);
		};
		return DeserializeVector(src, v, deserialize_fn);
	}

	class AsyncContext : public Aws::Client::AsyncCallerContext {
	public:

		AsyncContext(StreamManager* sm);

		StreamManager* GetStreamManager() const;

		void SetNBytes(uint64_t n_bytes);

		uint64_t GetNBytes() const;

		void SetPartN(uint64_t part_n);

		uint64_t GetPartN() const;

	private:
		StreamManager* sm;
		// for download parts, the size of the downloaded part in bytes
		uint64_t n_bytes;
		// the part number of the part
		uint64_t part_n;

	};

protected:
	const Aws::S3::S3Client& client;
	const std::string bucket;
	const std::string key;

};

