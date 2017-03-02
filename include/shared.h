/*
 * Aerospike Shared Includes
 *
 * Copyright (c) 2008-2017 Aerospike, Inc. All rights reserved.
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

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/alloc.h>
#include <citrusleaf/cf_atomic.h>
#include <citrusleaf/cf_b64.h>
#include <citrusleaf/cf_clock.h>

#include <aerospike/aerospike.h>
#include <aerospike/aerospike_index.h>
#include <aerospike/aerospike_info.h>
#include <aerospike/aerospike_key.h>
#include <aerospike/aerospike_llist.h>
#include <aerospike/aerospike_lmap.h>
#include <aerospike/aerospike_udf.h>
#include <aerospike/as_arraylist.h>
#include <aerospike/as_bin.h>
#include <aerospike/as_cluster.h>
#include <aerospike/as_hashmap.h>
#include <aerospike/as_info.h>
#include <aerospike/as_key.h>
#include <aerospike/as_log_macros.h>
#include <aerospike/as_nil.h>
#include <aerospike/as_node.h>
#include <aerospike/as_policy.h>
#include <aerospike/as_record.h>
#include <aerospike/as_scan.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <getopt.h>
#include <libgen.h>
#include <math.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined __APPLE__
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#define VERSION_3_0 "3.0"               ///< Indicates a legacy backup file.
#define VERSION_3_1 "3.1"               ///< Indicates a new-style backup file.

#define MAX_META_LINE 1000              ///< The maximal length of a meta data line in a backup
                                        ///  file.
#define META_PREFIX "# "                ///< Every meta data line starts with this prefix.
#define META_FIRST_FILE "first-file"    ///< The meta data tag that marks the backup file that was
                                        ///  written first and thus may contain secondary index
                                        ///  information and UDF files.
#define META_NAMESPACE "namespace"      ///< The meta data tag that specifies the namespace from
                                        ///  which this backup file was created.

#define GLOBAL_PREFIX "* "              ///< Every global data (= secondary index information and
                                        ///  UDF files) line starts with this prefix.
#define RECORD_META_PREFIX "+ "         ///< Every record meta data (= digest, generation, etc.)
                                        ///  line starts with this prefix.
#define RECORD_BIN_PREFIX "- "          ///< Every record bin line starts with this prefix.

#define MAX_TOKEN_SIZE 1000             ///< The maximal length of an individual syntactic token in
                                        ///  the backup file.

#define DEFAULT_HOST "127.0.0.1"        ///< The default host to connect to.
#define DEFAULT_PORT 3000               ///< The default port to connect to.

#define TIMEOUT 10000                   ///< The timeout for all operations (in ms).

///
/// The data type of a path expression.
///
typedef enum {
	PATH_TYPE_INVALID,  ///< Invalid.
	PATH_TYPE_STRING,   ///< The path results in a string.
	PATH_TYPE_NUMERIC,  ///< The path results in an integer.
	PATH_TYPE_GEOJSON   ///< The path results in a geojson value.
} path_type;

///
/// Represents a path expression and its data type.
///
typedef struct {
	char *path;     ///< The path expression.
	path_type type; ///< The data type.
} path_param;

///
/// The type of a secondary index.
///
typedef enum {
	INDEX_TYPE_INVALID,     ///< Invalid.
	INDEX_TYPE_NONE,        ///< Original, vanilla secondary index.
	INDEX_TYPE_LIST,        ///< Index on list elements.
	INDEX_TYPE_MAPKEYS,     ///< Index on map keys.
	INDEX_TYPE_MAPVALUES    ///< Index on map values.
} index_type;

///
/// Encapsulates secondary index information.
///
typedef struct {
	char *ns;           ///< The namespace of the index.
	char *set;          ///< The set of the index.
	char *name;         ///< The index name.
	index_type type;    ///< The type of the index.
	as_vector path_vec; ///< The path expressions of the index as a vector of path_param. Currently,
	                    ///  there's always only one path expression.
} index_param;

///
/// Identifies the TLS client command line options.
///
typedef enum {
	TLS_OPT_ENABLE = 1000,      ///< The `--tlsEnable` option.
	TLS_OPT_ENCRYPT_ONLY,       ///< The `--tlsEncryptOnly` option.
	TLS_OPT_CA_FILE,            ///< The `--tlsCaFile` option.
	TLS_OPT_CA_PATH,            ///< The `--tlsCaPath` option.
	TLS_OPT_PROTOCOLS,          ///< The `--tlsProtocols` option.
	TLS_OPT_CIPHER_SUITE,       ///< The `--tlsCipherSuite` option.
	TLS_OPT_CRL_CHECK,          ///< The `--tlsCrlCheck` option.
	TLS_OPT_CRL_CHECK_ALL,      ///< The `--tlsCrlCheckAll` option.
	TLS_OPT_CERT_BLACK_LIST,    ///< The `--tlsCertBlackList` option.
	TLS_OPT_LOG_SESSION_INFO,   ///< The `--tlsLogSessionInfo` option.
	TLS_OPT_KEY_FILE,           ///< The `--tlsKeyFile` option.
	TLS_OPT_CERT_FILE           ///< The `--tlsCertFile` option.
} tls_opt;
