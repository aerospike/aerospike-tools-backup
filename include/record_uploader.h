/*
 * Aerospike Record Uploader
 *
 * Copyright (c) 2008-2022 Aerospike, Inc. All rights reserved.
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
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/aerospike_batch.h>

#pragma GCC diagnostic pop

#include <batch_uploader.h>


//==========================================================
// Typedefs & constants.
//

/*
 * The record uploader struct, which is used to build batches of records to
 * upload to the batch_uploader. This struct should only be used by one thread,
 * as it's methods are not thread-safe.
 */
typedef struct record_uploader {
	// The batch uploader to submit batch upload requests to when batches fill
	// up or record_uploader_flush is called.
	batch_uploader_t* batch_uploader;
	// The max size a batch can be, automatically flushing once it reaches this
	// size.
	uint32_t batch_size;

	// list of as_record's to upload.
	as_vector records;
} record_uploader_t;


//==========================================================
// Public API.
//

/*
 * Initializes the record uploader, given the batch_size to use and the shared
 * batch_uploader to submit record batches to.
 */
int record_uploader_init(record_uploader_t*, batch_uploader_t*,
		uint32_t batch_size);

void record_uploader_free(record_uploader_t*);

/*
 * Reserves a slot for the next record to upload, transferring ownership of the
 * record passed to it (i.e. it should not be freed by the caller).
 *
 * Returns false if an error occurred.
 */
bool record_uploader_put(record_uploader_t*, as_record* rec);

/*
 * Flushes all records in the batch being constructed. This must be called
 * before record_uploader_free if all records should be flushed to the server,
 * otherwise records left in the current batch will not be written.
 */
bool record_uploader_flush(record_uploader_t*);

