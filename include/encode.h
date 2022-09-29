/*
 * Aerospike Format Encoder Interface
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

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================
// Includes.
//

#include <stdbool.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/aerospike_index.h>
#include <aerospike/aerospike_udf.h>
#include <aerospike/as_record.h>
#include <aerospike/as_admin.h>

#pragma GCC diagnostic pop

#include <io_proxy.h>


//==========================================================
// Typedefs & constants.
//

// Indicates a legacy backup file.
#define VERSION_3_0 "3.0"
// Indicates a new-style backup file.
#define VERSION_3_1 "3.1"

// The maximal length of a meta data line in a backup file.
#define MAX_META_LINE 1000

// Every meta data line starts with this prefix.
#define META_PREFIX "# "
// The meta data tag that marks the backup file that was written first and thus
// may contain secondary index information and UDF files.
#define META_FIRST_FILE "first-file"
// The meta data tag that specifies the namespace from which this backup file
// was created.
#define META_NAMESPACE "namespace"

// Every global data (= secondary index information and UDF files) line starts
// with this prefix.
#define GLOBAL_PREFIX "* "
// Every record meta data (= digest, generation, etc.) line starts with this
// prefix.
#define RECORD_META_PREFIX "+ "
// Every record bin line starts with this prefix.
#define RECORD_BIN_PREFIX "- "

/*
 * The data type of a path expression.
 */
typedef enum {
	// Invalid.
	PATH_TYPE_INVALID,
	// The path results in a string.
	PATH_TYPE_STRING,
	// The path results in an integer.
	PATH_TYPE_NUMERIC,
	// The path results in a geo2dsphere value.
	PATH_TYPE_GEO2DSPHERE
} path_type;

/*
 * Represents a path expression and its data type.
 */
typedef struct {
	// The path expression.
	char *path;
	// The data type.
	path_type type;
} path_param;

/*
 * The type of a secondary index.
 */
typedef enum {
	// Invalid.
	INDEX_TYPE_INVALID,
	// Original, vanilla secondary index.
	INDEX_TYPE_NONE,
	// Index on list elements.
	INDEX_TYPE_LIST,
	// Index on map keys.
	INDEX_TYPE_MAPKEYS,
	// Index on map values.
	INDEX_TYPE_MAPVALUES
} index_type;

/*
 * Encapsulates secondary index information.
 */
typedef struct {
	// The namespace of the index.
	char *ns;
	// The set of the index.
	char *set;
	// The index name.
	char *name;
	// The type of the index.
	index_type type;
	// The path expressions of the index as a vector of path_param. Currently,
	// there's always only one path expression.
	// c-client changed "position" (here called "path_vec->path") to "bin_name"
	as_vector path_vec;
	// The as_index_task struct populated by the aerospike_index_create_complex
	// command which is used by aerospike_index_create_wait
	as_index_task task;
	// b64 encoded context for CDTs.
	char *ctx;
} index_param;

/*
 * Encapsulates a UDF file.
 */
typedef struct {
	// The language of the UDF file.
	as_udf_type type;
	// The name of the UDF file.
	char *name;
	// The size of the UDF file.
	uint32_t size;
	// The content of the UDF file.
	void *data;
} udf_param;

/*
 * The result codes for the backup file format decoder.
 */
typedef enum {
	// A record was read and is returned.
	DECODER_RECORD,
	// Secondary index information was read and is returned.
	DECODER_INDEX,
	// A UDF file was read and is returned.
	DECODER_UDF,
	// A User info was read and is returned.
	DECODER_USER,
	// The end of the backup file was encountered.
	DECODER_EOF,
		// An error occurred.
	DECODER_ERROR
} decoder_status;

/*
 * The interface exposed by the backup file format encoder.
 */
typedef struct backup_encoder {
	/*
	 * Writes a record to the backup file.
	 * @param fd       The file descriptor of the backup file.
	 * @param compact  If true, don't use base-64 encoding on BLOB bin values.
	 * @param rec      The record to be written.
	 *
	 * @result         `true`, if successful.
	 */
	bool (*put_record)(io_write_proxy_t *fd, bool compact, const as_record *rec);

	/*
	 * Writes a UDF file to the backup file.
	 *
	 * @param fd     The file descriptor of the backup file.
	 * @param file   The UDF file to be written.
	 *
	 * @result       `true`, if successful.
	 */
	bool (*put_udf_file)(io_write_proxy_t *fd, const as_udf_file *file);

	/*
	 * Writes the specification of a secondary index to the backup file.
	 *
	 * @param fd     The file descriptor of the backup file.
	 * @param index  The index specification to be written.
	 *
	 * @result       `true`, if successful.
	 */
	bool (*put_secondary_index)(io_write_proxy_t *fd, const index_param *index);

	/*
	 * Writes the specification of a user and it's roles to the backup file.
	 *
	 * @param fd     The file descriptor of the backup file.
	 * @param user   The user specification to be written.
	 *
	 * @result       `true`, if successful.
	 */
	bool (*put_user_info)(io_write_proxy_t *fd, const as_user *user);
} backup_encoder_t;

/*
 * The interface exposed by the backup file format decoder.
 */
typedef struct backup_decoder {
	/*
	 * Reads, parses, and returns the next entity from a backup file descriptor.
	 *
	 * @param fd        The file descriptor.
	 * @param legacy    Indicates a version 3.0 backup file.
	 * @param ns_vec    The (optional) source and (also optional) target namespace to be restored.
	 * @param bin_vec   The bins to be restored, as a vector of strings.
	 * @param line_no   The current line number.
	 * @param rec       The returned record. Only valid, if the result is
	 *                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	 * @param extra_ttl Extra-ttl to be added to expirable records.
	 * @param expired   Indicates that an expired record was read. Only valid, if the result is
	 *                  [DECODER_RECORD](@ref decoder_status::DECODER_RECORD).
	 * @param index     The returned secondary index information. Only valid, if the result is
	 *                  [DECODER_INDEX](@ref decoder_status::DECODER_INDEX).
	 * @param udf       The returned UDF file. Only valid, if the result is
	 *                  [DECODER_UDF](@ref decoder_status::DECODER_UDF).
	 * @param user       The returned user information. Only valid, if the result is
	 *                  [DECODER_USER](@ref decoder_status::DECODER_USER).
	 *
	 * @result          See @ref decoder_status.
	 */
	decoder_status (*parse)(io_read_proxy_t *fd, bool legacy, as_vector *ns_vec,
			as_vector *bin_vec, uint32_t *line_no, as_record *rec,
			int32_t extra_ttl, bool *expired, index_param *index,
			udf_param *udf, as_user *user);
} backup_decoder_t;


//==========================================================
// Public API.
//

void free_udf(udf_param *param);

void free_udfs(as_vector *udf_vec);

void free_index(index_param *param);

void free_indexes(as_vector *index_vec);

void free_user(as_user *user);

void free_users(as_vector /*<as_user>*/ *users, int user_size);

#ifdef __cplusplus
}
#endif

