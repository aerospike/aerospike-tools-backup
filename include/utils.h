/*
 * Aerospike Utility Functions
 *
 * Copyright (c) 2008-2016 Aerospike, Inc. All rights reserved.
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

#include <shared.h>

#define IO_BUF_SIZE (1024 * 1024 * 16)      ///< We do I/O in blocks of this size.
#define STACK_BUF_SIZE (1024 * 16)          ///< The size limit for stack-allocated buffers.
#define ETA_BUF_SIZE (4 + 3 + 3 + 3 + 1)    ///< The buffer size for pretty-printing an ETA.

#define MAX_THREADS 4096                    ///< The maximal supported number of threads.

///
/// Allocates a buffer. Buffers smaller than @ref STACK_BUF_SIZE are allocated on the stack.
///
#define buffer_init(_sz) (_sz <= STACK_BUF_SIZE ? alloca(_sz) : safe_malloc(_sz))

///
/// Frees an allocated buffer. Buffers smaller than @ref STACK_BUF_SIZE are ignored, as they
/// are freed automatically.
///
#define buffer_free(_buf, _sz) do {     \
	if (_sz > STACK_BUF_SIZE) {         \
		cf_free(_buf);                  \
	}                                   \
} while (false);

///
/// '\'-escapes a string. Measures the size of the result, allocates a buffer, then escapes.
///
#define escape(_str) escape_space(_str, alloca(escape_space(_str, NULL).len)).str

#define IP_ADDR_SIZE 111 ///< The maximal size of an IPv4 or IPv6 address string +
						///  maximum size of a X509 common name (including the
                        ///  terminating NUL).

///
/// The callback invoked by the get_info() function to parse info key-value pairs.
///
/// @param context  The opaque user-specified context.
/// @param key      The key of the current key-value pair.
/// @param value    The corresponding value.
///
/// @result         `true`, if successful.
///
typedef bool (*info_callback)(void *context, const char *key, const char *value);

///
/// The callback context passed to get_info() when parsing the namespace object count and
/// replication factor.
///
typedef struct {
	uint64_t count;     ///< The object count.
	uint32_t factor;    ///< The replication factor.
} ns_count_context;

///
/// The callback context passed to get_info() when parsing the set object count.
///
typedef struct {
	const char *ns;     ///< The namespace in which we are interested.
	const char *set;    ///< The set in which we are interested.
	uint64_t count;     ///< The object count;
} set_count_context;

///
/// Encapsulates the IP address and port of a cluster node.
///
typedef struct {
	char addr_string[IP_ADDR_SIZE];   ///< The IP address as a string.
	sa_family_t family;               ///< The address family of the IP address.
	union {                           ///< The IPv4 / IPv6 address in network byte order.
		struct in_addr v4;
		struct in6_addr v6;
	} ver;
	in_port_t port;                   ///< The port in network byte order.
	char *tls_name_str;		  ///< TLS_NAME for server node.
} node_spec;

///
/// Encapsulates an (output buffer, length) pair for escape_space() and unescape_space().
///
typedef struct {
	char *str;  ///< The output buffer.
	size_t len; ///< The length.
} esc_res;

///
/// Context for the streaming base-64 decoder.
///
typedef struct {
	size_t size;        ///< The size of the decoded data.
	int32_t index;      ///< The index of the next buffered byte to be read.
	uint8_t buffer[2];  ///< Space for two buffered bytes.
} b64_context;

extern bool verbose;
extern const uint8_t b64map[256];

extern void ver(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern void inf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern void err(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern void err_code(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
extern void hex_dump_ver(const void *data, uint32_t len);
extern void hex_dump_inf(const void *data, uint32_t len);
extern void hex_dump_err(const void *data, uint32_t len);
extern void enable_client_log(void);
extern void *safe_malloc(size_t size);
extern char *safe_strdup(const char *string);
extern void safe_lock(void);
extern void safe_unlock(void);
extern void safe_wait(pthread_cond_t *cond);
extern void safe_signal(pthread_cond_t *cond);
extern bool better_atoi(const char *string, uint64_t *val);
extern bool parse_date_time(const char *string, int64_t *nanos);
extern bool format_date_time(int64_t nanos, char *buffer, size_t size);
extern esc_res escape_space(const char *source, char *dest);
extern esc_res unescape_space(const char *source, char *dest);
extern char *trim_string(char *str);
extern void split_string(char *str, char split, bool trim, as_vector *vec);
extern void format_eta(int32_t seconds, char *buffer, size_t size);
extern char *print_char(int32_t ch);
extern void get_node_names(as_cluster *clust, node_spec *node_specs, uint32_t n_node_specs,
		char (**node_names)[][AS_NODE_NAME_SIZE], uint32_t *n_node_names);
extern bool get_info(aerospike *as, const char *value, const char *node_name, void *context,
		info_callback callback, bool kv_split);
extern bool get_migrations(aerospike *as, char (*node_names)[][AS_NODE_NAME_SIZE],
		uint32_t n_node_names, uint64_t *mig_count);
extern bool parse_index_info(char *ns, char *index_str, index_param *index);

#define LIKELY(x) __builtin_expect(!!(x), 1)    ///< Marks an expression that is likely true.
#define UNLIKELY(x) __builtin_expect(!!(x), 0)  ///< Marks an expression that is unlikely true.

///
/// Reads a character from a file descriptor. Updates the current line and column number as well as
/// the total number of read bytes.
///
/// @param fd       The file descriptor to read from.
/// @param line_no  The line number. `line_no[0]` is the current line, `line_no[1]` is the next
///                 line.
/// @param col_no   The column number. `col_no[0]` is the current column, `col_no[1]` is the next
///                 column.
/// @param bytes    Incremented, if a character was successfully read.
///
/// @result         The read character on success, otherwise `EOF`.
///
static __attribute__((always_inline)) inline int32_t
read_char(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes)
{
	line_no[0] = line_no[1];
	col_no[0] = col_no[1];

	int32_t ch = getc_unlocked(fd);

	switch (ch) {
	case EOF:
		if (ferror(fd) != 0) {
			err("Error while reading backup block (line %u, col %u)", line_no[0], col_no[0]);
			return EOF;
		}

		err("Unexpected end of file in backup block (line %u, col %u)", line_no[0], col_no[0]);
		return EOF;

	case '\n':
		++line_no[1];
		col_no[1] = 1;
		++(*bytes);
		return ch;

	default:
		++col_no[1];
		++(*bytes);
		return ch;
	}
}

///
/// Reads from a file descriptor, decodes base-64 data, and returns the next decoded byte. Updates
/// the current line and column number as well as the total number of read bytes.
///
/// The function reads 4 bytes at a time, decodes them into 3 bytes, buffers 2 of those 3 bytes,
/// and returns the 1 remaining byte. Subsequent calls will read the 2 buffered bytes. After that,
/// everything starts over.
///
/// @param fd       The file descriptor to read from.
/// @param line_no  The line number. `line_no[0]` is the current line, `line_no[1]` is the next
///                 line.
/// @param col_no   The column number. `col_no[0]` is the current column, `col_no[1]` is the next
///                 column.
/// @param bytes    Incremented, if a character was successfully read.
/// @param b64c     The base-64 context used, for example, to store buffered bytes.
///
/// @result         The decoded byte on success, otherwise `EOF`.
///
static inline int32_t
read_char_dec(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, b64_context *b64c)
{
	if (LIKELY(b64c->index < 2)) {
		return b64c->buffer[b64c->index++];
	}

	int32_t ch1 = read_char(fd, line_no, col_no, bytes);
	int32_t ch2 = read_char(fd, line_no, col_no, bytes);
	int32_t ch3 = read_char(fd, line_no, col_no, bytes);
	int32_t ch4 = read_char(fd, line_no, col_no, bytes);

	if (UNLIKELY(ch1 == EOF || ch2 == EOF || ch3 == EOF || ch4 == EOF)) {
		err("Unexpected end of file in base-64 data");
		return EOF;
	}

	if (UNLIKELY(ch4 == '=')) {
		b64c->size += ch3 == '=' ? 1 : 2;
	} else {
		b64c->size += 3;
	}

	int32_t dig1 = b64map[ch1];
	int32_t dig2 = b64map[ch2];
	int32_t dig3 = b64map[ch3];
	int32_t dig4 = b64map[ch4];

	if (UNLIKELY(dig1 == 0xff || dig2 == 0xff || dig3 == 0xff || dig4 == 0xff)) {
		err("Invalid base-64 character (%s, %s, %s, or %s at or before line %u, col %u)",
				print_char(ch1), print_char(ch2), print_char(ch3), print_char(ch4),
				line_no[0], col_no[0]);
		return EOF;
	}

	b64c->buffer[0] = (uint8_t)((dig2 << 4) | (dig3 >> 2));
	b64c->buffer[1] = (uint8_t)((dig3 << 6) | dig4);
	b64c->index = 0;
	return (dig1 << 2) | (dig2 >> 4);
}

///
/// Pushes a character back to a file descriptor. Adjusts the current line and column number as
/// well as the total number of read bytes.
///
/// @param ch       The character to be pushed back.
/// @param fd       The file descriptor.
/// @param line_no  The line number. `line_no[0]` is the current line, `line_no[1]` is the next
///                 line.
/// @param col_no   The column number. `col_no[0]` is the current column, `col_no[1]` is the next
///                 column.
/// @param bytes    Incremented, if a character was successfully read.
///
/// @result         `true`, if successful.
///
static inline bool
push_char(int32_t ch, FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes)
{
	if (UNLIKELY(ungetc(ch, fd) == EOF)) {
		err("Error while pushing character in backup block (line %u, col %u)", line_no[0],
				col_no[0]);
		return false;
	}

	line_no[1] = line_no[0];
	col_no[1] = col_no[0];
	--(*bytes);
	return true;
}

///
/// Expects the given character to be the next character read from the given file descriptor.
///
/// @param fd       The file descriptor.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param ch       The expected character.
///
/// @result         `true`, if successful.
///
static inline bool
expect_char(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, int32_t ch)
{
	int32_t x = read_char(fd, line_no, col_no, bytes);

	if (UNLIKELY(x == EOF)) {
		return false;
	}

	if (UNLIKELY(x != ch)) {
		err("Unexpected character %s in backup block (line %u, col %u), expected %s", print_char(x),
				line_no[0], col_no[0], print_char(ch));
		return false;
	}

	return true;
}

///
/// Reads the given number of bytes from the given file descriptor.
///
/// @param fd       The file descriptor.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The output buffer for the read bytes.
/// @param size     The number of bytes to be read.
///
/// @result         `true`, if successful.
///
static inline bool
read_block(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, void *buffer, size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		int32_t ch = read_char(fd, line_no, col_no, bytes);

		if (UNLIKELY(ch == EOF)) {
			return false;
		}

		((char *)buffer)[i] = (char)ch;
	}

	return true;
}

///
/// Reads the given number of characters from the given file descriptor and base-64 decodes them.
///
/// @param fd       The file descriptor.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The output buffer for the decoded bytes.
/// @param size     The number of characters to be read. Note that this is not the size of the
///                 output buffer. This is the number of base-64 characters. The output buffer,
///                 however, receives the decoded bytes and thus is smaller.
/// @param b64c     The base-64 context to be used for decoding.
///
/// @result         `true`, if successful.
///
static inline bool
read_block_dec(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, void *buffer,
		size_t size, b64_context *b64c)
{
	for (size_t i = 0; i < size; ++i) {
		int32_t ch = read_char_dec(fd, line_no, col_no, bytes, b64c);

		if (UNLIKELY(ch == EOF)) {
			return false;
		}

		((char *)buffer)[i] = (char)ch;
	}

	return true;
}

///
/// A wrapper around `fprintf()` that counts the bytes that were written.
///
/// @param bytes   Increased by the number of bytes written.
/// @param fd      The file descriptor to write to.
/// @param format  The format string for `fprintf()`.
///
/// @result        The result returned by `fprintf()`.
///
static inline int32_t
fprintf_bytes(uint64_t *bytes, FILE *fd, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int32_t res = fd != NULL ? vfprintf(fd, format, args) : vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (LIKELY(res != EOF)) {
		*bytes += (uint64_t)res;
	}

	return res;
}

///
/// A wrapper around `fwrite()` that counts the bytes that were written.
///
/// @param bytes   Increased by the number of bytes written.
/// @param data    The data to be written.
/// @param len     The size of an individual data chunk to be written.
/// @param num     The number of data chunks to be written.
/// @param fd      The file descriptor to write to.
///
/// @result        The result returned by `fwrite()`.
///
static inline size_t
fwrite_bytes(uint64_t *bytes, const void *data, size_t len, size_t num, FILE *fd)
{
	size_t res = fd != NULL && len > 0 ? fwrite(data, len, num, fd) : num;

	if (LIKELY(res == num)) {
		*bytes += num * len;
	}

	return res;
}
