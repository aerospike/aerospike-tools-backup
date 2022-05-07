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

#include <record_uploader.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/aerospike_key.h>
#include <aerospike/as_record.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"


//==========================================================
// Public API.
//

int
record_uploader_init(record_uploader_t* uploader,
		batch_uploader_t* batch_uploader, uint32_t batch_size)
{
	uploader->batch_uploader = batch_uploader;
	uploader->batch_size = batch_size;
	record_list_init(&uploader->records, batch_size);

	return 0;
}

void
record_uploader_free(record_uploader_t* uploader)
{
	record_list_free(&uploader->records);
}

bool
record_uploader_put(record_uploader_t* uploader, as_record* rec)
{
	if (record_list_size(&uploader->records) == uploader->batch_size) {
		// upload the record batch and reset for the next batch of records
		if (!record_uploader_flush(uploader)) {
			return false;
		}
	}

	return record_list_append(&uploader->records, rec);
}

bool
record_uploader_flush(record_uploader_t* uploader)
{
	if (!batch_uploader_submit(uploader->batch_uploader,
				&uploader->records)) {
		return false;
	}

	record_list_clear(&uploader->records);

	return true;
}

