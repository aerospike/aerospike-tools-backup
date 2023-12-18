/*
 * Aerospike Restore Configuration
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

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================
// Includes.
//

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_tls.h>
#include <sa_client.h>

#pragma GCC diagnostic pop

#include <io_proxy.h>


//==========================================================
// Typedefs & constants.
//

#define RESTORE_CONFIG_INIT_FAILURE -1

// to be returned by restore_config_init when the program should immediately exit
// with success error code
#define RESTORE_CONFIG_INIT_EXIT -2

// returned when a restore_config_t fails validation
#define RESTORE_CONFIG_VALIDATE_FAILURE -3

// The default number of restore threads.
#define DEFAULT_THREADS 20

// Maximal number of tries for each record put.
#define MAX_TRIES 10
// Initial backoff delay (in ms) between tries when overloaded; doubled after
// each try.
#define INITIAL_BACKOFF 10

#define DEFAULT_MAX_ASYNC_BATCHES 32
#define DEFAULT_BATCH_SIZE 128
#define DEFAULT_KEY_REC_BATCH_SIZE 16
#define BATCH_SIZE_UNDEFINED -1u

#define DEFAULT_EVENT_LOOPS 1

/*
 * The global restore configuration and stats shared by all restore threads and the counter thread.
 */
typedef struct restore_config {

	char *host;
	int32_t port;
	bool use_services_alternate;
	char *user;
	char *password;
	uint32_t parallel;
	char *nice_list;
	bool no_records;
	bool no_indexes;
	bool indexes_last;
	bool no_udfs;
	bool wait;
	bool validate;
	// timeout for Aerospike commands.
	uint32_t timeout;
	// The max number of times a write transaction will be retried.
	uint64_t max_retries;
	// The scale factor in exponential backoff in microseconds.
	uint64_t retry_scale_factor;

	// C client socket timeout/retry policies.
	uint32_t socket_timeout;
	uint32_t total_timeout;
	// this option has been replaced by retry-scale-factor
	uint32_t retry_delay;

	// When set, don't use batch writes.
	bool disable_batch_writes;

	// Max number of outstanding async record batch write calls at a time.
	uint32_t max_async_batches;
	// The batch size to use for batch uploading, or the size of groups of
	// records to simultaneously upload.
	uint32_t batch_size;
	// The number of c-client event loops to use.
	uint32_t event_loops;

	// The region to use for S3.
	char* s3_region;
	// The profile to use for AWS credentials.
	char* s3_profile;
	// An alternative endpoint for S3 compatible storage to send all S3 requests to.
	char* s3_endpoint_override;
	// Max simultaneous download requests from S3 allowed at a time.
	uint32_t s3_max_async_downloads;
	// aws-sdk-cpp client connectTimeoutMS.
	uint32_t s3_connect_timeout;
	// Logging level of the AWS S3 C+ SDK.
	s3_log_level_t s3_log_level;

	as_config_tls tls;
	char* tls_name;

	// The (optional) source and (also optional) target namespace to be restored.
	char *ns_list;
	// The directory to restore from. `NULL`, when restoring from a single file.
	char *directory;
	// A list of directories to restore from. `NULL`, when restoring from a single file or directory.
	char *directory_list;
	// A common path to be prepended to entries in directory_list.
	char *parent_directory;
	// The file to restore from. `NULL`, when restoring from a directory.
	char *input_file;
	// The path for the machine-readable output.
	char *machine;
	// The bins to be restored.
	char *bin_list;
	// The sets to be restored.
	char *set_list;
	// The encryption key given by the user
	encryption_key_t* pkey;
	// The compression mode to be used (default is none)
	compression_opt compress_mode;
	// The encryption mode to be used (default is none)
	encryption_opt encrypt_mode;
	// Indicates that existing records shouldn't be touched.
	bool unique;
	// Indicates that existing records should be replaced instead of updated.
	bool replace;
	// Ignore record specific errors.
	bool ignore_rec_error;
	// Indicates that the generation count of existing records should be ignored.
	bool no_generation;
	// Amount of extra time-to-live to add to records that have expirable
	// void-times.
	int32_t extra_ttl;
	// The B/s cap for throttling.
	uint64_t bandwidth;
	// The TPS cap for throttling.
	uint32_t tps;

	// Authentication mode.
	char *auth_mode;

	// secret agent client configs
	sa_cfg secret_cfg;
} restore_config_t;


//==========================================================
// Public API.
//

/*
 * Parses command line arguments from argv and populates/initializes the
 * backup_config_t struct.
 *
 * The restore_config_t struct returned by this method is always destroyable (and
 * should be destroyed) regardless of the return value
 */
int restore_config_set(int argc, char* argv[], restore_config_t* conf);

/*
 * Validates the restore config, checking for mutually exclusive options,
 * invalid options, etc. This should be called immediately after restore_config_init.
 * Success: return 0
 * Failure: return RESTORE_CONFIG_VALIDATE_FAILURE
 */
int restore_config_validate(restore_config_t *conf);

/* restore_config_set_defaults sets conf fields that are heap allocated
 * to their default value. This is used internally to allow users of the shared library
 * this function should be called after restore_config_init and before restore_config_set
 * to set their conf values without leaking the heap allocated default values
 */
void restore_config_set_heap_defaults(restore_config_t *conf);

/*
 * restore_config_init initializes all conf fields to their
 * zero value or a default value.
 */
void restore_config_init(restore_config_t* conf);

void restore_config_destroy(restore_config_t* conf);

/*
 * Parses a `item1[,item2[,...]]` string into a vector of strings.
 *
 * @param which  The type of the list to be parsed. Only used in error messages.
 * @param size   Maximal length of each individual list item.
 * @param list   The string to be parsed.
 * @param vec    The populated vector.
 *
 * @result       `true`, if successful.
 */
bool restore_config_parse_list(const char *which, size_t size, char *list,
		as_vector *vec);

/*
 * Returns true if restoring from the cloud (i.e. S3), otherwise restores from
 * the local filesystem.
 */
bool restore_config_from_cloud(const restore_config_t* conf);

#ifdef __cplusplus
}
#endif

