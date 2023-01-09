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

#include <delete_objects_buffer.h>


//==========================================================
// Class Definitions.
//

DeleteObjectsBuffer::DeleteObjectsBuffer(const Aws::S3::S3Client& client,
		const Aws::String& bucket) : client(client),
									 bucket(bucket) {}

bool
DeleteObjectsBuffer::DeleteObject(const Aws::String& key)
{
	ids.push_back(Aws::S3::Model::ObjectIdentifier().WithKey(key));

	if (ids.size() >= max_delete_objs) {
		return Flush();
	}
	return true;
}

bool
DeleteObjectsBuffer::Flush()
{
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

