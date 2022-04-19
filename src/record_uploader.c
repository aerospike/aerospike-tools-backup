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
	as_vector_init(&uploader->records, sizeof(as_record), batch_size);

	return 0;
}

void
record_uploader_free(record_uploader_t* uploader)
{
	as_vector_destroy(&uploader->records);
}

bool
record_uploader_put(record_uploader_t* uploader, as_record* rec)
{
	if (uploader->records.size == uploader->batch_size) {
		// upload the record batch and reset for the next batch of records
		if (!record_uploader_flush(uploader)) {
			return false;
		}
	}

	as_record* rec_ptr = (as_record*) as_vector_reserve(&uploader->records);
	*rec_ptr = *rec;
	// reset the reference count of the as_val
	rec_ptr->_._.count = 1;
	if (rec->key.valuep == &rec->key.value) {
		rec_ptr->key.valuep = &rec_ptr->key.value;
		// reset the reference count of the key, which we can choose any of the
		// key types to do since the as_val fields alias one another
		rec_ptr->key.value.integer._.count = 1;
	}

	return true;
}

bool
record_uploader_flush(record_uploader_t* uploader)
{
	if (!batch_uploader_submit(uploader->batch_uploader,
				&uploader->records)) {
		return false;
	}

	for (uint32_t i = 0; i < uploader->records.size; i++) {
		as_record* rec = (as_record*) as_vector_get(&uploader->records, i);

		as_record_destroy(rec);
	}

	as_vector_clear(&uploader->records);

	return true;
}

