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

	as_batch_records_init(&uploader->batch, batch_size);

	return 0;
}

void
record_uploader_free(record_uploader_t* uploader)
{
	as_batch_records_destroy(&uploader->batch);
}

as_batch_write_record*
record_uploader_reserve(record_uploader_t* uploader)
{
	if (uploader->batch.list.size == uploader->batch_size) {
		// upload the record batch and reset for the next batch of records
		if (!record_uploader_flush(uploader)) {
			return NULL;
		}
	}

	return as_batch_write_reserve(&uploader->batch);
}

bool
record_uploader_flush(record_uploader_t* uploader)
{
	if (!batch_uploader_submit(uploader->batch_uploader, &uploader->batch)) {
		return false;
	}

	for (uint32_t i = 0; i < uploader->batch.list.size; i++) {
		as_batch_base_record* record =
			(as_batch_base_record*) as_vector_get(&uploader->batch.list, i);

		as_key_destroy(&record->key);
		as_record_destroy(&record->record);
	}

	as_vector_clear(&uploader->batch.list);
	return true;
}

