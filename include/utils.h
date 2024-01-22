/*
 * Aerospike Utility Functions
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

// used to make sure C++ understands
// atomic_bool see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=60932
#ifdef __cplusplus
extern "C" {
#else
// defined here so that C++ doesn't see atomic_bool
// it won't recognize it and will throw a compile time error
#include <stdatomic.h>
// Enables verbose logging.
extern atomic_bool g_verbose;
// Disables all logging output except for errors.
extern atomic_bool g_silent;
#endif

//==========================================================
// Includes.
//

#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#if defined __APPLE__
#include <sys/syscall.h>
#else
#include <syscall.h>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <citrusleaf/cf_b64.h>
#include <aerospike/aerospike.h>
#include <aerospike/aerospike_info.h>
#include <aerospike/as_cluster.h>
#include <aerospike/as_exp.h>
#include <aerospike/as_node.h>
#include <aerospike/as_vector.h>

#include <sa_client.h>

#pragma GCC diagnostic pop

#include <encode.h>
#include <io_proxy.h>


//==========================================================
// Typedefs & constants.
//

// The maximal length of an individual syntactic token in the backup file.
#define MAX_TOKEN_SIZE 1000

// The default host to connect to.
#define DEFAULT_HOST "127.0.0.1"
// The default port to connect to.
#define DEFAULT_PORT 3000

// The default host to connect to the Aerospike secret agent on.
#define DEFAULT_SECRET_AGENT_HOST "127.0.0.1"
// The default port to connect to the Aerospike secret agent on.
#define DEFAULT_SECRET_AGENT_PORT "3005"

// The timeout for all operations (in ms).
#define TIMEOUT 10000

// The character to encode true boolean values.
#define BOOLEAN_TRUE_CHAR  'T'
// The character to encode false boolean values.
#define BOOLEAN_FALSE_CHAR 'F'

// The size limit for stack-allocated buffers.
#define STACK_BUF_SIZE (1024 * 16)
// The buffer size for pretty-printing an ETA.
#define ETA_BUF_SIZE (4 + 3 + 3 + 3 + 1)

// The maximal supported number of threads.
#define MAX_THREADS 4096

/*
 * Allocates a buffer. Buffers smaller than @ref STACK_BUF_SIZE are allocated on the stack.
 */
#define buffer_init(_sz) (_sz <= STACK_BUF_SIZE ? alloca(_sz) : safe_malloc(_sz))

/*
 * Frees an allocated buffer. Buffers smaller than @ref STACK_BUF_SIZE are ignored, as they
 * are freed automatically.
 */
#define buffer_free(_buf, _sz) do {     \
	if (_sz > STACK_BUF_SIZE) {         \
		cf_free(_buf);                  \
	}                                   \
} while (false);

/*
 * '\'-escapes a string. Measures the size of the result, allocates a buffer, then escapes.
 */
#define escape(_str) escape_space(_str, alloca(escape_space(_str, NULL).len)).str

// The maximal size of an IPv4 or IPv6 address string + maximum size of a X509
// common name (including the terminating NUL).
#define IP_ADDR_SIZE 111

/*
 * The callback invoked by the get_info() function to parse info key-value pairs.
 *
 * @param context  The opaque user-specified context.
 * @param key      The key of the current key-value pair.
 * @param value    The corresponding value.
 *
 * @result         `true`, if successful.
 */
typedef bool (*info_callback)(void *context, const char *key, const char *value);

/*
 * The callback context passed to get_info() when parsing the namespace object count and
 * replication factor.
 */
typedef struct {
	// The object count.
	uint64_t count;
	// The replication factor.
	uint32_t factor;
} ns_count_context;

/*
 * The callback context passed to get_info() when parsing the set object count.
 */
typedef struct {
	// The namespace in which we are interested.
	const char *ns;
	// The set in which we are interested.
	const char *set;
	// The object count;
	uint64_t count;
} set_count_context;

/*
 * Encapsulates the IP address and port of a cluster node.
 */
typedef struct {
	// The IP address as a string.
	char addr_string[IP_ADDR_SIZE];
	// The address family of the IP address.
	sa_family_t family;
	// The IPv4 / IPv6 address in network byte order.
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ver;
	// The port in network byte order.
	in_port_t port;
	// TLS_NAME for server node.
	char *tls_name_str;
} node_spec;

/*
 * Encapsulates an (output buffer, length) pair for escape_space() and unescape_space().
 */
typedef struct {
	// The output buffer.
	char *str;
	// The length.
	size_t len;
} esc_res;

/*
 * Identifies the TLS client command line options.
 */
typedef enum {
	// The `--tls-enable` option.
	TLS_OPT_ENABLE = 1000,
	// The `--tls-encrypt-only` option.
	TLS_OPT_ENCRYPT_ONLY,
	// The `--tls-name` option.
	TLS_OPT_NAME,
	// The `--tls-cafile` option.
	TLS_OPT_CA_FILE,
	// The `--tls-capath` option.
	TLS_OPT_CA_PATH,
	// The `--tls-protocols` option.
	TLS_OPT_PROTOCOLS,
	// The `--tls-cipher-suite` option.
	TLS_OPT_CIPHER_SUITE,
	// The `--tls-crl-check` option.
	TLS_OPT_CRL_CHECK,
	// The `--tls-crl-checkall` option.
	TLS_OPT_CRL_CHECK_ALL,
	// The `--tls-cert-blacklist` option. (DEPRECATED)
	TLS_OPT_CERT_BLACK_LIST,
	// The `--tlsLogSessionInfo` option.
	TLS_OPT_LOG_SESSION_INFO,
	// The `--tls-keyfile` option.
	TLS_OPT_KEY_FILE,
	// The `--tls-keyfile-password` option.
	TLS_OPT_KEY_FILE_PASSWORD,
	// The `--tls-certfile` option.
	TLS_OPT_CERT_FILE
} tls_opt;

/*
 * Identifies the config file command line options.
 */
typedef enum {
	CONFIG_FILE_OPT_FILE = 2000,
	CONFIG_FILE_OPT_INSTANCE,
	CONFIG_FILE_OPT_NO_CONFIG_FILE,
	CONFIG_FILE_OPT_ONLY_CONFIG_FILE,
} cfgfile_opt;

/*
 * Identifies the config and command line options.
 */
typedef enum {
	COMMAND_OPT_NO_TTL_ONLY = 3000,
	COMMAND_OPT_SOCKET_TIMEOUT,
	COMMAND_OPT_TOTAL_TIMEOUT,
	COMMAND_OPT_MAX_RETRIES,
	COMMAND_OPT_RETRY_DELAY,
	COMMAND_OPT_RETRY_SCALE_FACTOR,
	COMMAND_OPT_COMPRESSION_LEVEL,
	COMMAND_OPT_REMOVE_ARTIFACTS,
	COMMAND_OPT_ESTIMATE_SAMPLES,
	COMMAND_OPT_S3_REGION,
	COMMAND_OPT_S3_PROFILE,
	COMMAND_OPT_S3_ENDPOINT_OVERRIDE,
	COMMAND_OPT_S3_MIN_PART_SIZE,
	COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS,
	COMMAND_OPT_S3_MAX_ASYNC_UPLOADS,
	COMMAND_OPT_S3_LOG_LEVEL,
	COMMAND_OPT_S3_CONNECT_TIMEOUT,
	COMMAND_OPT_DISABLE_BATCH_WRITES,
	COMMAND_OPT_MAX_ASYNC_BATCHES,
	COMMAND_OPT_BATCH_SIZE,
	COMMAND_OPT_EVENT_LOOPS,
	COMMAND_OPT_DIRECTORY_LIST,
	COMMAND_OPT_PARENT_DIRECTORY,
	COMMAND_OPT_VALIDATE,
	COMMAND_OPT_PREFER_RACKS,
	COMMAND_SA_ADDRESS,
	COMMAND_SA_PORT,
	COMMAND_SA_TIMEOUT,
	COMMAND_SA_CAFILE
} cmd_opt;

/*
 * The arguments passed to the counter thread in asbackup and asrestore.
 */
typedef struct {
	// The global configuration.
	void *conf;
	// The global status.
	void *status;
	// The cluster nodes to be backed up.
	char (*node_names)[][AS_NODE_NAME_SIZE];
	// The number of cluster nodes to be backed up.
	uint32_t n_node_names;
	// The file descriptor for the machine-readable
	FILE *mach_fd;
} counter_thread_args;

/*
 * Context for the streaming base-64 decoder.
 */
typedef struct {
	// The size of the decoded data.
	size_t size;
	// The index of the next buffered byte to be read.
	int32_t index;
	// Space for two buffered bytes.
	uint8_t buffer[2];
} b64_context;

/*
 * Struct containing server version information.
 */
typedef struct server_version {
	// server version looks like "<major>.<minor>.<patch>.<build_id>"
	uint32_t major;
	uint32_t minor;
	uint32_t patch;
	uint32_t build_id;
} server_version_t;

extern const uint8_t b64map[256];


//==========================================================
// Inlines and macros.
//

// Marks an expression that is likely true.
#define LIKELY(x) __builtin_expect(!!(x), 1)
// Marks an expression that is unlikely true.
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#ifndef MIN
#define MIN(a, b) ((b) > (a) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

#ifdef __APPLE__

#define htobe32 OSSwapHostToBigInt32
#define be32toh OSSwapBigToHostInt32

#define htobe64 OSSwapHostToBigInt64
#define be64toh OSSwapBigToHostInt64

#endif /* __APPLE__ */

#define SERVER_VERSION_BEFORE(version_info, _major, _minor) \
	((version_info)->major < _major || \
	 ((version_info)->major == _major && (version_info)->minor < _minor))


//==========================================================
// Public API.
//

#define ver(...) \
	do { \
		if (g_verbose) { \
			_ver_fn(__VA_ARGS__); \
		} \
	} while(0)

void log_line(const char *tag, const char *prefix, const char *format,
		va_list args, bool error);
void _ver_fn(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void inf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void err(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void sa_log_err(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void err_code(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
const char* boolstr(bool val);
void hex_dump_ver(const void *data, uint32_t len);
void hex_dump_inf(const void *data, uint32_t len);
void hex_dump_err(const void *data, uint32_t len);
bool str_vector_clone(as_vector* dst, const as_vector* src);
bool str_vector_contains(const as_vector* v, const char* str);
char* str_vector_tostring(const as_vector* v);
void enable_client_log(void);
void *safe_malloc(size_t size);
char *safe_strdup(const char *string);
void safe_lock(pthread_mutex_t* mutex);
void safe_unlock(pthread_mutex_t* mutex);
void safe_wait(pthread_cond_t *cond, pthread_mutex_t* mutex);
void safe_signal(pthread_cond_t *cond);
double erfinv(double y);
double confidence_z(double p, uint64_t n_records);
char* dyn_sprintf(const char* format, ...) __attribute__ ((format (printf, 1, 2)));
bool better_atoi(const char *string, int64_t *val);
bool parse_date_time(const char *string, int64_t *nanos);
bool parse_host(char** pp, char** host, char** port);
bool format_date_time(int64_t nanos, char *buffer, size_t size);
void get_current_time(struct timespec* now);
void timespec_add_us(struct timespec* ts, uint64_t us);
uint64_t timespec_diff(const struct timespec* from,
		const struct timespec* until);
bool timespec_has_not_happened(struct timespec* ts);
esc_res escape_space(const char *source, char *dest);
esc_res unescape_space(const char *source, char *dest);
char *trim_string(char *str);
void split_string(char *str, char split, bool trim, as_vector *vec);
void format_eta(int32_t seconds, char *buffer, size_t size);
char *print_char(int32_t ch);
bool write_int64(uint64_t val, file_proxy_t* fd);
bool write_int32(uint32_t val, file_proxy_t* fd);
bool read_int64(uint64_t* val, file_proxy_t* fd);
bool read_int32(uint32_t* val, file_proxy_t* fd);
int32_t read_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no);
int32_t read_char_dec(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		b64_context *b64c);
int peek_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no);
bool expect_char(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		int32_t ch);
bool read_block(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		void *buffer, size_t size);
bool read_block_dec(io_read_proxy_t *fd, uint32_t *line_no, uint32_t *col_no,
		void *buffer, size_t size, b64_context *b64c);

void sa_config_clone(sa_cfg* clone, const sa_cfg* src);
void sa_config_destroy(sa_cfg* cfg);
void sa_tls_clone(sa_tls_cfg* clone, const sa_tls_cfg* src);
void sa_tls_destroy(sa_tls_cfg* cfg);

/*
 * reads a private key from the given file into the pkey buffer and
 * initializes/populates the key passed
 */
int read_private_key_file(const char* pkey_file_path,
		encryption_key_t* key);

/*
 * reads a private key from the given buffer into the pkey buffer and
 * initializes/populates the key passed
 */
int read_private_key(char* pkey_data,
		encryption_key_t* key);

// the following functions are only valid in C, not C++
#ifndef __cplusplus

int get_secret_arg(sa_client* sc, char* path, char** res, bool* is_secret);
void get_node_names(as_cluster *clust, node_spec *node_specs, uint32_t n_node_specs,
		char (**node_names)[][AS_NODE_NAME_SIZE], uint32_t *n_node_names);
bool get_info(aerospike *as, const char *value, const char *node_name, void *context,
		info_callback callback, bool kv_split);
bool get_migrations(aerospike *as, char (*node_names)[][AS_NODE_NAME_SIZE],
		uint32_t n_node_names, uint64_t *mig_count);

#endif /* __cplusplus */

bool parse_index_info(char *ns, char *index_str, index_param *index);
bool parse_set_list(as_vector* dst, const char* set_list);
encryption_key_t* parse_encryption_key_env(const char* env_var_name);

// Gets the current server version via an info command, returning 0 on success
// and nonzero on failure.
int get_server_version(aerospike* as, server_version_t*);
bool server_has_batch_writes(aerospike* as, const server_version_t*,
		bool* batch_writes_enabled);

/*
 * Moves the contents of a key from src to dst. src should not be freed after
 * this operation, and its memory should be treated as uninitialized.
 *
 * Fails if the ref count of src is > 1, returning false.
 */
bool as_key_move(as_key* dst, as_key* src);

/*
 * Moves the contents of a record from src to dst. src should not be freed after
 * this operation, and its memory should be treated as uninitialized.
 *
 * Fails if the ref count of src is > 1, returning false.
 */
bool as_record_move(as_record* dst, as_record* src);

/*
 * Swaps the contents of two vectors.
 */
void as_vector_swap(as_vector* v1, as_vector* v2);

#ifdef __APPLE__
char* strchrnul(const char* s, int c_in);
#endif /* __APPLE__ */

/*
 * exp_component_t's are used to programatically join multiple expressions with
 * a join_op. Initialize each exp_component with its corresponding expression,
 * and join them all with join_op by calling exp_component_join_and_compile on
 * a list of pointers to the expressions to be joined.
 */
typedef struct exp_component {
	as_exp_entry* expr;
	uint64_t size;
} exp_component_t;

/*
 * Initializes an exp_component to empty, which will be ignored if passed to
 * exp_component_join_and_compile.
 */
#define exp_component_init_nil(exp_comp) \
{ \
	(exp_comp)->expr = NULL; \
	(exp_comp)->size = 0; \
}

#define exp_component_init(exp_comp, ...) \
{ \
	(exp_comp)->size = sizeof((as_exp_entry[]) { __VA_ARGS__ }); \
	(exp_comp)->expr = (as_exp_entry*) cf_malloc((exp_comp)->size); \
	memcpy((exp_comp)->expr, (as_exp_entry[]) { __VA_ARGS__ }, (exp_comp)->size); \
}

#define exp_component_set(exp_comp, expr_ptr, expr_size) \
{ \
	(exp_comp)->expr = (as_exp_entry*) cf_malloc((expr_size)); \
	memcpy((exp_comp)->expr, (expr_ptr), (expr_size)); \
	(exp_comp)->size = (expr_size); \
}

#define exp_component_free(exp_comp) \
	cf_free((exp_comp)->expr)

/*
 * Error code returnd by exp_component_join_and_compile on failure.
 */
#define EXP_ERR ((as_exp*) -1)

/*
 * Joins a list of n_ops exp_component_t*'s with the given as_exp_ops operation,
 * returning the resulting compiled expression.
 *
 * Returns (as_exp*) -1 on error, since NULL is a valid return value for lists of
 * no expressions.
 */
as_exp* exp_component_join_and_compile(as_exp_ops join_op, uint32_t n_ops,
		exp_component_t** components);

/*
 * Frees an as_config_tls. May be called multiple times without double frees
 * happening.
 */
void tls_config_destroy(as_config_tls* tls);

/*
 * Duplicates an as_config_tls object.
 */
void tls_config_clone(as_config_tls* clone, const as_config_tls* src);

/*
 * Reads the contents of `path` and adds a null terminator.
 * The returned char* must be freed by the caller
 */
char* read_file_as_string(const char* path);

#ifdef __cplusplus
}
#endif

