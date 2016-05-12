/*
 * Copyright 2015 Aerospike, Inc.
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

#include <utils.h>

#if defined __APPLE__
#define MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER      ///< Mutex initializer on OS X.
#define THREAD_ID SYS_thread_selfid                         ///< Thread ID system call on OS X.
#else
#define MUTEX_INIT PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP   ///< Mutex initializer on Linux.
#define THREAD_ID SYS_gettid                                ///< Thread ID system call on Linux.
#endif

static pthread_mutex_t mutex = MUTEX_INIT;                  ///< Mutex used by safe_lock(),
                                                            ///  safe_unlock(), and safe_wait().
bool verbose = false;                                       ///< Enables verbose logging.

///
/// Lookup table for base-64 decoding. Invalid characters yield 0xff. '=' (0x3d) yields 0x00 to
/// make it a legal character.
///
const uint8_t b64map[256] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

///
/// Central log function. Writes a single log message.
///
/// @param tag     The severity tag.
/// @param prefix  A prefix to be prepended to the log message.
/// @param format  The format string for the log message.
/// @param args    The arguments for the log message, according to the format string.
/// @param error   Indicates that errno information is to be added to the log message.
///
static void
log_line(const char *tag, const char *prefix, const char *format, va_list args, bool error)
{
	char buffer[10000];
	time_t now;
	struct tm now_tm;

	if ((now = time(NULL)) == (time_t)-1) {
		fprintf(stderr, "Error while getting current time, error %d, %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (gmtime_r(&now, &now_tm) == NULL) {
		fprintf(stderr, "Error while calculating GMT, error %d, %s\n", errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	size_t index = 0;
	size_t length = strftime(buffer + index, sizeof buffer, "%Y-%m-%d %H:%M:%S %Z ", &now_tm);

	if (length == 0) {
		fprintf(stderr, "Error while converting time to string, error %d, %s\n", errno,
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	index += length;
	length = (size_t)snprintf(buffer + index, sizeof buffer - index, "[%s] [%5d] %s", tag,
			(int32_t)(syscall(THREAD_ID) % 100000), prefix);
	index += length;

	length = (size_t)vsnprintf(buffer + index, sizeof buffer - index, format, args);
	index += length;

	if (index >= sizeof buffer) {
		fprintf(stderr, "Buffer overflow while creating log message\n");
		exit(EXIT_FAILURE);
	}

	if (error) {
		length = (size_t)snprintf(buffer + index, sizeof buffer - index, " (error %d: %s)", errno,
				strerror(errno));
		index += length;

		if (index >= sizeof buffer) {
			fprintf(stderr, "Buffer overflow while creating log message\n");
			exit(EXIT_FAILURE);
		}
	}

	if (index >= sizeof buffer) {
		fprintf(stderr, "Buffer overflow while creating log message\n");
		exit(EXIT_FAILURE);
	}

	buffer[index] = 0;
	fprintf(stderr, "%s\n", buffer);
}

///
/// Logs a debug message.
///
/// @param format  The format string for the debug message.
///
void
ver(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_line("VER", "", format, args, false);
	va_end(args);
}

///
/// Logs an informational message.
///
/// @param format  The format string for the informational message.
///
void
inf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_line("INF", "", format, args, false);
	va_end(args);
}

///
/// Logs an error message.
///
/// @param format  The format string for the error message.
///
void
err(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_line("ERR", "", format, args, false);
	va_end(args);
}

///
/// Logs an error message and includes errno information.
///
/// @param format  The format string for the error message.
///
void
err_code(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_line("ERR", "", format, args, true);
	va_end(args);
}

///
/// Hex dump helper function. Feeds a hex dump of the given data to the given function line by line.
///
/// @param data    The data to be dumped.
/// @param len     The length of the data to be dumped.
/// @param output  The output function to be invoked for every line of the hex dump.
///
static void
hex_dump(const void *data, uint32_t len, void (*output)(const char *format, ...))
{
	uint32_t i, k;
	char line[4 + 16 * 3 + 1 + 16 + 1];

	for (i = 0; i < len; i += k) {
		sprintf(line, "%04x", i);

		for (k = 0; k < 16 && i + k < len; ++k) {
			uint8_t x = ((uint8_t *)data)[i + k];
			sprintf(line + 4 + k * 3, " %02x", x);
			line[4 + 16 * 3 + 1 + k] = (char)(x >= 32 && x <= 126 ? x : '.');
		}

		line[4 + 16 * 3 + 1 + k] = 0;

		while (k < 16) {
			strcpy(line + 4 + k * 3, "   ");
			++k;
		}

		line[4 + 16 * 3] = ' ';
		output("%s", line);
	}
}

///
/// Logs a debug hex dump of the given data.
///
/// @param data  The data to be dumped.
/// @param len   The length of the data to be dumped.
///
void
hex_dump_ver(const void *data, uint32_t len)
{
	hex_dump(data, len, ver);
}

///
/// Logs an informational hex dump of the given data.
///
/// @param data  The data to be dumped.
/// @param len   The length of the data to be dumped.
///
void
hex_dump_inf(const void *data, uint32_t len)
{
	hex_dump(data, len, inf);
}

///
/// Logs an error hex dump of the given data.
///
/// @param data  The data to be dumped.
/// @param len   The length of the data to be dumped.
///
void
hex_dump_err(const void *data, uint32_t len)
{
	hex_dump(data, len, err);
}

///
/// Log callback for the Aerospike client library. Receives log messages from the Aerospike client
/// and outputs them to our own log.
///
/// @param level   The severity level of the log message.
/// @param func    The client library function that issued the log message.
/// @param file    The source code file that contains the function.
/// @param line    The source code line that issued the log message.
/// @param format  The format string of the log message.
///
/// @result        Always `true`.
///
static bool
log_callback(as_log_level level, const char *func, const char *file, uint32_t line,
		const char *format, ...)
{
	char prefix[1000];

	if ((size_t)snprintf(prefix, sizeof prefix, "[%s:%d][%s] ", file, line,
			func) >= sizeof prefix) {
		fprintf(stderr, "Buffer overflow while creating client log prefix");
		exit(EXIT_FAILURE);
	}

	char *tag = "???";

	switch (level) {
	case AS_LOG_LEVEL_ERROR:
	case AS_LOG_LEVEL_WARN:
		tag = "ERR";
		break;

	case AS_LOG_LEVEL_INFO:
		tag = "INF";
		break;

	case AS_LOG_LEVEL_DEBUG:
	case AS_LOG_LEVEL_TRACE:
		tag = "VER";
		break;
	}

	va_list args;
	va_start(args, format);
	log_line(tag, prefix, format, args, false);
	va_end(args);
	return true;
}

///
/// Enables the Aerospike client log.
///
void
enable_client_log(void)
{
	as_log_set_level(AS_LOG_LEVEL_INFO);
	as_log_set_callback(log_callback);
}

///
/// A wrapper around `cf_malloc()` that exits on errors.
///
void *
safe_malloc(size_t size)
{
	void *mem = cf_malloc(size);

	if (mem == NULL) {
		err_code("Error while allocating %zu byte(s)", size);
		exit(EXIT_FAILURE);
	}

	return mem;
}

///
/// A wrapper around `cf_strdup()` that exits on errors.
///
char *
safe_strdup(const char *string)
{
	char *res = cf_strdup(string);

	if (res == NULL) {
		err_code("Error while duplicating string %s", string);
		exit(EXIT_FAILURE);
	}

	return res;
}

///
/// A wrapper around `pthread_mutex_lock()` that uses @ref mutex and that exits on errors.
///
void
safe_lock(void)
{
	if (pthread_mutex_lock(&mutex) != 0) {
		err_code("Error while locking mutex");
		exit(EXIT_FAILURE);
	}
}

///
/// A wrapper around `pthread_mutex_unlock()` that uses @ref mutex and that exits on errors.
///
void
safe_unlock(void)
{
	if (pthread_mutex_unlock(&mutex) != 0) {
		err_code("Error while unlocking mutex");
		exit(EXIT_FAILURE);
	}
}

///
/// A version of `pthread_cond_wait()` that uses @ref mutex and that exits on errors.
///
void
safe_wait(pthread_cond_t *cond)
{
	if (pthread_cond_wait(cond, &mutex) != 0) {
		err_code("Error while waiting for condition");
		exit(EXIT_FAILURE);
	}
}

///
/// A version of `pthread_cond_broadcast()` that exits on errors.
///
void
safe_signal(pthread_cond_t *cond)
{
	if (pthread_cond_broadcast(cond) != 0) {
		err_code("Error while signaling condition");
		exit(EXIT_FAILURE);
	}
}

///
/// Turns a string of digits into an unsigned 64-bit value.
///
/// @param string  The string of digits.
/// @param val     The output integer.
///
/// @result        `true`, if successful.
///
bool
better_atoi(const char *string, uint64_t *val)
{
	if (*string < '0' || *string > '9') {
		return false;
	}

	char *end;
	*val = strtoul(string, &end, 10);
	return *end == 0;
}

///
/// '\'-escapes spaces and line feeds in a string. Used by the @ref escape() macro.
///
/// @param source  The string to be escaped.
/// @param dest    The output buffer for the escaped string. May be `NULL` to determine the
///                length of the escaped string.
///
/// @result        An esc_res, i.e., an (output buffer, length) pair.
///
esc_res
escape_space(const char *source, char *dest)
{
	size_t k = 0;

	for (size_t i = 0; source[i] != 0; ++i) {
		char ch = source[i];

		if (ch == '\\' || ch == ' ' || ch == '\n') {
			if (dest != NULL) {
				dest[k] = '\\';
			}

			++k;
		}

		if (dest != NULL) {
			dest[k] = ch;
		}

		++k;
	}

	if (dest != NULL) {
		dest[k] = 0;
	}

	return (esc_res){ dest, ++k };
}

///
/// '\'-unescapes a string.
///
/// @param source  The string to be unescaped.
/// @param dest    The output buffer for the unescaped string. May be `NULL` to determine the
///                length of the unescaped string.
///
/// @result        An esc_res, i.e., an (output buffer, length) pair.
///
esc_res
unescape_space(const char *source, char *dest)
{
	size_t k = 0;
	bool esc = false;

	for (size_t i = 0; source[i] != 0; ++i) {
		char ch = source[i];

		if (ch == '\\' && !esc) {
			esc = true;
			continue;
		}

		esc = false;

		if (dest != NULL) {
			dest[k] = ch;
		}

		++k;
	}

	if (dest != NULL) {
		dest[k] = 0;
	}

	return (esc_res){ dest, ++k };
}

///
/// Removes space characters at the beginning and end of a string.
///
/// @param str  The string to be trimmed.
///
/// @result     A pointer to the beginning of the trimmed string.
///
char *
trim_string(char *str)
{
	size_t len = strlen(str);
	char *end = str + len - 1;

	while (end >= str && isspace(*end)) {
		--end;
	}

	*(end + 1) = 0;

	while (isspace(*str)) {
		++str;
	}

	return str;
}

///
/// Splits a string at the given split character into a vector of strings. Optionally trims
/// the resulting parts.
///
/// @param str    The string to be split.
/// @param split  The character to split at.
/// @param trim   Requests trimming of the resulting parts.
/// @param vec    The result vector to be populated.
///
void
split_string(char *str, char split, bool trim, as_vector *vec)
{
	char *prev = str;
	bool stop = false;

	while (!stop) {
		stop = *str == 0;

		if (*str == split || stop) {
			*str = 0;
			char *append = trim ? trim_string(prev) : prev;
			as_vector_append(vec, &append);
			prev = str + 1;
		}

		++str;
	}
}

///
/// Pretty-prints the given number of seconds.
///
/// @param seconds  The number of seconds to be pretty-printed.
/// @param buffer   The output buffer to receive the formatted result.
/// @param size     The size of the output buffer.
///
void
format_eta(int32_t seconds, char *buffer, size_t size)
{
	size_t length = 0;

	if (seconds > 100 * 86400) {
		length = (size_t)snprintf(buffer, size, "%s", ">100d");

		if (length >= size) {
			fprintf(stderr, "Buffer overflow while formatting days\n");
			exit(EXIT_FAILURE);
		}

		return;
	}

	if (seconds < 0) {
		seconds = 0;
	}

	int32_t divisors[] = { 86400, 3600, 60, 1 };
	char labels[] = { 'd', 'h', 'm', 's' };
	size_t index = 0;
	bool printed = false;

	for (uint32_t i = 0; i < 4; ++i) {
		int32_t val = seconds / divisors[i];

		if (val == 0 && !printed && i < 3) {
			continue;
		}

		seconds = seconds - val * divisors[i];
		length = (size_t)snprintf(buffer + index, size - index, "%d%c", val, labels[i]);
		index += length;

		if (index >= size) {
			fprintf(stderr, "Buffer overflow while formatting ETA\n");
			exit(EXIT_FAILURE);
		}

		printed = true;
	}
}

///
/// Formats a character as a string. Unprintable characters use "\x..." notation.
///
/// For thread safety, this function uses a fixed number of static buffers based on the maximal
/// number of threads.
///
/// @param ch  The character to be formatted.
///
/// @result    The string representing the character.
///
char *
print_char(int32_t ch)
{
	// allow print_char() to be used up to 4 times in a single expression (e.g., function call)
	static char buff[MAX_THREADS * 4][5];
	static uint32_t index = 0;

	safe_lock();
	uint32_t i = index++;

	if (index >= MAX_THREADS * 4) {
		index = 0;
	}

	safe_unlock();

	if (ch >= 32 && ch <= 126) {
		snprintf(buff[i], sizeof buff[i], "\"%c\"", ch);
	} else {
		snprintf(buff[i], sizeof buff[i], "\\x%02x", ch & 255);
	}

	return buff[i];
}

///
/// Obtains the node IDs of the cluster from the Aerospike client library. Optionally only
/// considers user-specified nodes.
///
/// The first pass just counts the nodes, the second pass actually gets their IDs.
///
/// @param clust         The Aerospike cluster.
/// @param node_specs    The IP addresses and ports of the user-specified nodes.
/// @param n_node_specs  The number of user-specified nodes. Zero means "give me all cluster nodes."
/// @param node_names    The created array of node IDs.
/// @param n_node_names  The number of elements in the created array.
///
void
get_node_names(as_cluster *clust, node_spec *node_specs, uint32_t n_node_specs,
		char (**node_names)[][AS_NODE_NAME_SIZE], uint32_t *n_node_names)
{
	as_nodes *nodes = as_nodes_reserve(clust);

	for (int32_t pass = 1; pass <= 2; ++pass) {
		*n_node_names = 0;

		for (uint32_t i = 0; i < nodes->size; ++i) {
			as_node *node = nodes->array[i];
			bool keep;

			if (n_node_specs == 0) {
				keep = true;
			} else {
				keep = false;
				as_vector *addr_vec = &node->addresses;

				for (uint32_t k = 0; !keep && k < addr_vec->size; ++k) {
					as_address *addr = as_vector_get(addr_vec, k);

					for (uint32_t m = 0; m < n_node_specs; ++m) {
						if (addr->addr.sin_addr.s_addr == node_specs[m].addr &&
								addr->addr.sin_port == node_specs[m].port) {
							if (verbose && pass == 2) {
								ver("Found node for %s:%d", node_specs[m].addr_string,
										ntohs(node_specs[m].port));
							}

							keep = true;
							break;
						}
					}
				}
			}

			if (keep) {
				if (pass == 2) {
					if (verbose) {
						ver("Adding node %s", node->name);
					}

					memcpy((**node_names)[*n_node_names], node->name, AS_NODE_NAME_SIZE);
				}

				++(*n_node_names);
			}
		}

		if (pass == 1) {
			*node_names = safe_malloc(*n_node_names * AS_NODE_NAME_SIZE);
		}
	}

	as_nodes_release(nodes);
}

///
/// Retrieves the given info value from the given node, parses it, and feeds the resulting
/// info key-value pairs to the given callback function.
///
/// @param as         The Aerospike client instance.
/// @param value      The info value to be retrieved.
/// @param node_name  The name of the node to be queried.
/// @param context    The opaque user-specified context for the callback.
/// @param callback   The callback to be invoked for each key-value pair.
///
/// @result          `true`, if successful.
///
bool
get_info(aerospike *as, const char *value, const char *node_name, void *context,
		info_callback callback)
{
	bool res = false;

	if (verbose) {
		ver("Getting info value %s for node %s", value, node_name);
	}

	as_node *node = as_node_get_by_name(as->cluster, node_name);

	if (node == NULL) {
		err("Node %s disappeared from the cluster", node_name);
		goto cleanup0;
	}

	struct sockaddr_in *addr = as_node_get_address(node);
	as_node_release(node);

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = TIMEOUT;

	char *resp = NULL;
	as_error ae;

	if (aerospike_info_socket_address(as, &ae, &policy, addr, value, &resp) != AEROSPIKE_OK) {
		err("Error while retrieving info from node %s - code %d: %s at %s:%d", node_name, ae.code,
				ae.message, ae.file, ae.line);
		goto cleanup0;
	}

	if (verbose) {
		ver("Parsing info");
	}

	char *info = NULL;

	if (as_info_parse_single_response(resp, &info) != AEROSPIKE_OK) {
		err("Error while parsing single info response");
		goto cleanup1;
	}

	if (info[0] == 0) {
		err("Empty info string");
		goto cleanup1;
	}

	char *clone = safe_strdup(info);
	as_vector info_vec;
	as_vector_inita(&info_vec, sizeof (void *), 25);

	split_string(info, ';', false, &info_vec);

	for (uint32_t i = 0; i < info_vec.size; ++i) {
		char *key = as_vector_get_ptr(&info_vec, i);
		char *equals = strchr(key, '=');

		if (equals == NULL) {
			err("Invalid info string %s (missing \"=\")", clone);
			goto cleanup2;
		}

		*equals = 0;
		char *value = equals + 1;

		if (!callback(context, key, value)) {
			err("Info callback reports an error");
			goto cleanup2;
		}
	}

	res = true;

cleanup2:
	as_vector_destroy(&info_vec);
	cf_free(clone);

cleanup1:
	cf_free(resp);

cleanup0:
	return res;
}

///
/// The callback passed to get_info() to parse the number of pending incoming and
/// outgoing migrations.
///
/// @param context_  The migration_count_context for the parsed result.
/// @param key       The key of the current key-value pair.
/// @param value     The corresponding value.
///
/// @result          `true`, if successful.
///
static bool
migration_count_callback(void *context_, const char *key, const char *value)
{
	migration_count_context *context = (migration_count_context *)context_;
	uint64_t tmp;

	if (strcmp(key, "migrate_progress_recv") == 0) {
		if (!better_atoi(value, &tmp)) {
			err("Invalid number of pending incoming migrations %s", value);
			return false;
		}

		context->incoming = tmp;
		return true;
	}

	if (strcmp(key, "migrate_progress_send") == 0) {
		if (!better_atoi(value, &tmp)) {
			err("Invalid number of pending outgoing migrations %s", value);
			return false;
		}

		context->outgoing = tmp;
		return true;
	}

	return true;
}

///
/// Retrieves the total number of pending migrations on the given nodes.
///
/// @param as            The Aerospike client instance.
/// @param node_names    The array of node IDs of the cluster nodes to be queried.
/// @param n_node_names  The number of elements in the node ID array.
/// @param mig_count     The number of migrations.
///
/// @result              `true`, if successful.
///
bool
get_migrations(aerospike *as, char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names,
		uint64_t *mig_count)
{
	if (verbose) {
		ver("Getting cluster migration count");
	}

	*mig_count = 0;
	migration_count_context context = { 0, 0 };

	for (uint32_t i = 0; i < n_node_names; ++i) {
		if (verbose) {
			ver("Getting migration count for node %s", (*node_names)[i]);
		}

		if (!get_info(as, "statistics", (*node_names)[i], &context, migration_count_callback)) {
			err("Error while getting migration count for node %s", (*node_names)[i]);
			return false;
		}

		(*mig_count) += context.incoming + context.outgoing;
	}

	return true;
}

///
/// Parses the given secondary index information string obtained from a cluster.
///
/// @param ns         The namespace that contains the secondary index.
/// @param index_str  The information string to be parsed.
/// @param index      The secondary index specification to be populated. The caller is responsible
///                   for deallocating `index->path_vec`.
///
/// @result           `true`, if successful.
///
bool
parse_index_info(char *ns, char *index_str, index_param *index)
{
	bool res = false;

	if (index_str[0] == 0) {
		err("Empty index info in");
		goto cleanup0;
	}

	as_vector index_vec;
	as_vector_inita(&index_vec, sizeof (void *), 25);
	split_string(index_str, ':', false, &index_vec);

	index->ns = ns;
	index->set = NULL;
	index->name = NULL;
	index->type = INDEX_TYPE_INVALID;
	as_vector_init(&index->path_vec, sizeof (path_param), 25);

	char *path = NULL;
	path_type type = PATH_TYPE_INVALID;

	for (uint32_t i = 0; i < index_vec.size; ++i) {
		char *para = as_vector_get_ptr(&index_vec, i);
		char *equals = strchr(para, '=');

		if (equals == NULL) {
			err("Invalid secondary index parameter string %s (missing \"=\")", para);
			goto cleanup2;
		}

		*equals = 0;
		char *arg = equals + 1;

		if (strcmp(para, "set") == 0) {
			index->set = strcmp(arg, "NULL") == 0 ? NULL : arg;
		} else if (strcmp(para, "indexname") == 0) {
			index->name = arg;
		} else if (strcmp(para, "num_bins") == 0) {
			if (strcmp(arg, "1") != 0) {
				err("Multi-bin secondary indexes currently not supported, number of bins: %s",
						arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "type") == 0) {
			if (strcmp(arg, "STRING") == 0) {
				type = PATH_TYPE_STRING;
			} else if (strcmp(arg, "TEXT") == 0) {
				type = PATH_TYPE_STRING;
			} else if (strcmp(arg, "NUMERIC") == 0) {
				type = PATH_TYPE_NUMERIC;
			} else if (strcmp(arg, "INT SIGNED") == 0) {
				type = PATH_TYPE_NUMERIC;
			} else if (strcmp(arg, "GEOJSON") == 0) {
				type = PATH_TYPE_GEOJSON;
			} else {
				err("Invalid path type %s", arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "indextype") == 0) {
			if (strcmp(arg, "LIST") == 0) {
				index->type = INDEX_TYPE_LIST;
			} else if (strcmp(arg, "MAPKEYS") == 0) {
				index->type = INDEX_TYPE_MAPKEYS;
			} else if (strcmp(arg, "MAPVALUES") == 0) {
				index->type = INDEX_TYPE_MAPVALUES;
			} else if (strcmp(arg, "NONE") == 0) {
				index->type = INDEX_TYPE_NONE;
			} else {
				err("Invalid index type %s", arg);
				goto cleanup2;
			}
		} else if (strcmp(para, "path") == 0) {
			path = arg;
		}

		if (path != NULL && type != PATH_TYPE_INVALID) {
			path_param tmp = { path, type };
			as_vector_append(&index->path_vec, &tmp);
			path = NULL;
			type = PATH_TYPE_INVALID;
		}
	}

	if (index->name == NULL) {
		err("Missing index name");
		goto cleanup2;
	}

	if (index->type == INDEX_TYPE_INVALID) {
		err("Missing index type in index %s", index->name);
		goto cleanup2;
	}

	if (index->path_vec.size != 1) {
		err("Invalid number of paths in index %s (%u)", index->name, index->path_vec.size);
		goto cleanup2;
	}

	res = true;
	goto cleanup1;

cleanup2:
	as_vector_destroy(&index->path_vec);

cleanup1:
	as_vector_destroy(&index_vec);

cleanup0:
	return res;
}
