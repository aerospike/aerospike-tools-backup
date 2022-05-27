/*
 * Aerospike Delete Objects Buffer
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

#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aws/s3/S3Client.h>
#include <aws/s3/model/DeleteObjectsRequest.h>

#pragma GCC diagnostic warning "-Wsign-conversion"

#include <download_manager.h>


//==========================================================
// Class Declarations.
//

/*
 * Used to simplify deleting many objects from an S3 bucket, buffering the
 * objects ID's to delete and sending DeleteObjects requests with them in
 * groups, rather than sending a DeleteObject request for each object.
 */
class DeleteObjectsBuffer {
public:

	DeleteObjectsBuffer(const Aws::S3::S3Client& client,
			const Aws::String& bucket);

	bool DeleteObject(const Aws::String& key);

	bool Flush();

private:
	// max number of objects that can be deleted in a single delete objects
	// request
	static constexpr const uint64_t max_delete_objs = 1000;

	const Aws::S3::S3Client& client;
	const Aws::String bucket;
	Aws::Vector<Aws::S3::Model::ObjectIdentifier> ids;

};

