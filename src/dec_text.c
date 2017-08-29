/*
 * Copyright 2015-2016 Aerospike, Inc.
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

#include <dec_text.h>
#include <utils.h>

///
/// Ensures that the given string is a prefix of a valid floating-point value.
///
/// @param buffer  The string to be tested.
/// @param len     The string length.
///
/// @result         `true`, if successful.
///
static inline bool
text_check_floating_point(const char *buffer, size_t len)
{
	size_t i = 0;

	if (buffer[i] == '+' || buffer[i] == '-') {
		++i;
	}

	if (i == len) {
		return true;
	}

	if (strncasecmp("nan", buffer + i, len - i) == 0) {
		return true;
	}

	if (strncasecmp("inf", buffer + i, len - i) == 0) {
		return true;
	}

	if (strncasecmp("infinity", buffer + i, len - i) == 0) {
		return true;
	}

	bool dot = false;
	bool ex = false;
	char ch = 0, prev;

	while (i < len) {
		prev = ch;
		ch = buffer[i++];

		if (ch >= '0' && ch <= '9') {
			continue;
		}

		if ((ch == '+' || ch == '-') && prev == 'e') {
			continue;
		}

		if (ch == '.' && !dot && !ex) {
			dot = true;
			continue;
		}

		if (ch == 'e' && !ex) {
			ex = true;
			continue;
		}

		return false;
	}

	return true;
}

///
/// Reads from the backup file until one of the delimiter characters is found.
///
/// Before it is returned, the data is NUL-terminated.
///
/// @param fd       The file descriptor of the backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The buffer to store the read data.
/// @param size     The size of the supplied buffer.
/// @param digits   Indicates that only digits are valid data.
/// @param neg      Indicates that, in addition to digits, a minus sign is also valid data.
/// @param fp       Indicates that only floating point notation is valid data.
/// @param delim    The delimiter characters as a NUL-terminated string.
/// @param unesc    Indicates that the read data is to be unescaped.
///
/// @result         `true`, if successful.
///
static inline bool
text_nul_read_until(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, char *buffer,
		size_t size, bool digits, bool neg, bool fp, char *delim, bool unesc)
{
	size_t len = 0;
	bool esc = false;

	while (true) {
		int32_t ch = read_char(fd, line_no, col_no, bytes);

		if (ch == EOF) {
			return false;
		}

		if (unesc && ch == '\\' && !esc) {
			esc = true;
			continue;
		}

		if (!esc && strchr(delim, ch) != NULL) {
			if (!push_char(ch, fd, line_no, col_no, bytes)) {
				return false;
			}

			buffer[len] = 0;
			return true;
		}

		esc = false;

		if (len == size - 1) {
			err("Buffer overflow while reading token in backup block (line %u, col %u)", line_no[0],
					col_no[0]);
			return false;
		}

		if (digits && (ch < '0' || ch > '9') && (!neg || len > 0 || ch != '-')) {
			err("Invalid character %s in backup block (line %u, col %u), expected digit",
					print_char(ch), line_no[0], col_no[0]);
			return false;
		}

		buffer[len++] = (char)ch;

		if (fp && !text_check_floating_point(buffer, len)) {
			err("Invalid character %s in backup block (line %u, col %u), expected floating point "
					"notation", print_char(ch), line_no[0], col_no[0]);
			return false;
		}
	}
}

///
/// Reads a token from the backup.
///
/// The token is delimited by the given delimiter characters. Before it is returned, the token is
/// NUL-terminated.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The buffer to store the read data.
/// @param size     The size of the supplied buffer.
/// @param delim    The delimiter characters as a NUL-terminated string.
///
/// @result         `true`, if successful.
///
static inline bool
text_nul_read_token(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		char *buffer, size_t size, char *delim)
{
	return text_nul_read_until(fd, line_no, col_no, bytes, buffer, size, false, false, false, delim,
			!legacy);
}

///
/// Reads and parses a size integer from the backup file.
///
/// The size is a non-negative integer less than or equal to 1024^5. It is delimited by the given
/// delimiter characters.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param value    The parsed size.
/// @param delim    The delimiter characters as a NUL-terminated string.
///
/// @result         `true`, if successful.
///
static inline bool
text_read_size(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		size_t *value, char *delim)
{
	char buffer[MAX_TOKEN_SIZE];

	if (!text_nul_read_until(fd, line_no, col_no, bytes, buffer, sizeof buffer, true, false, false,
			delim, !legacy)) {
		return false;
	}

	size_t accu = 0;

	for (int32_t i = 0; buffer[i] != 0; ++i) {
		accu = accu * 10 + (size_t)(buffer[i] - '0');

		if (accu > (size_t)1024 * 1024 * 1024 * 1024 * 1024) {
			err("Size overflow with number %s in backup block (line %u, col %u)", buffer,
					line_no[0], col_no[0]);
			return false;
		}
	}

	*value = accu;
	return true;
}

///
/// Reads and parses a signed 64-bit integer from the backup file.
///
/// The integer is delimited by the given delimiter characters.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param value    The parsed value.
/// @param delim    The delimiter characters as a NUL-terminated string.
///
/// @result         `true`, if successful.
///
static inline bool
text_read_integer(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		int64_t *value, char *delim)
{
	char buffer[MAX_TOKEN_SIZE];

	if (!text_nul_read_until(fd, line_no, col_no, bytes, buffer, sizeof buffer, true, true, false,
			delim, !legacy)) {
		return false;
	}

	bool neg = buffer[0] == '-';
	uint64_t limit = neg ? (uint64_t)1 << 63 : ((uint64_t)1 << 63) - 1;
	uint64_t accu_limit = limit / 10;
	uint64_t digit_limit = limit % 10;
	uint64_t accu = 0;

	for (int32_t i = neg ? 1 : 0; buffer[i] != 0; ++i) {
		uint64_t digit = (uint64_t)(buffer[i] - '0');

		if (accu > accu_limit || (accu == accu_limit && digit > digit_limit)) {
			err("Integer overflow with number %s in backup block (line %u, col %u)", buffer,
					line_no[0], col_no[0]);
			return false;

		}

		accu = accu * 10 + digit;
	}

	*value = neg ? -(int64_t)accu : (int64_t)accu;
	return true;
}

///
/// Reads and parses a double-precision floating-point value from the backup file.
///
/// The value is delimited by the given delimiter characters.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param value    The parsed value.
/// @param delim    The delimiter characters as a NUL-terminated string.
///
/// @result         `true`, if successful.
///
static inline bool
text_read_double(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		double *value, char *delim)
{
	char buffer[MAX_TOKEN_SIZE];

	if (!text_nul_read_until(fd, line_no, col_no, bytes, buffer, sizeof buffer, false, false, true,
			delim, !legacy)) {
		return false;
	}

	char *end;
	*value = strtod(buffer, &end);

	if (*end != 0) {
		err("Invalid floating-point value %s in backup block (line %u, col %u)", buffer, line_no[0],
				col_no[0]);
		return false;
	}

	return true;
}

///
/// Reads and parses a string from the backup file.
///
/// The string may contain NUL characters and thus is *not* NUL-terminated. Instead, its size
/// is returned.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The buffer allocated for the string.
/// @param size     The size of the string.
/// @param extra    The amount of extra memory to allocate.
///
/// @result         `true`, if successful.
///
static bool
text_parse_string(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		void **buffer, size_t *size, size_t extra)
{
	if (!text_read_size(fd, legacy, line_no, col_no, bytes, size, " ")) {
		err("Error while reading string size");
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	*buffer = safe_malloc(*size + extra);

	if (!read_block(fd, line_no, col_no, bytes, *buffer, *size)) {
		err("Error while reading string data");
		cf_free(*buffer);
		return false;
	}

	return true;
}

///
/// Reads and parses a BLOB from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The buffer allocated for the BLOB.
/// @param size     The size of the BLOB.
/// @param extra    The amount of extra memory to allocate.
///
/// @result         `true`, if successful.
///
static bool
text_parse_data(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		void **buffer, size_t *size, size_t extra)
{
	if (!text_read_size(fd, legacy, line_no, col_no, bytes, size, " ")) {
		err("Error while reading data size");
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	*buffer = safe_malloc(*size + extra);

	if (!read_block(fd, line_no, col_no, bytes, *buffer, *size)) {
		err("Error while reading data");
		cf_free(*buffer);
		return false;
	}

	return true;
}

///
/// Reads and parses an encoded BLOB from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param buffer   The buffer allocated for the string.
/// @param size     The size of the string.
/// @param extra    The amount of extra memory to allocate.
///
/// @result         `true`, if successful.
///
static bool
text_parse_data_dec(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		void **buffer, size_t *size, size_t extra)
{
	size_t enc_size;

	if (!text_read_size(fd, legacy, line_no, col_no, bytes, &enc_size, " ")) {
		err("Error while reading encoded data size");
		return false;
	}

	if ((enc_size & 3) != 0) {
		err("Invalid encoded data size %zu (line %u, col %u)", enc_size, line_no[0], col_no[0]);
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	int64_t orig_bytes = *bytes;
	b64_context b64_cont = { 0, 9999, { 99, 99 }};
	// over-estimates the decoded size by up to 2 bytes (includes the padding)
	size_t dec_size = enc_size / 4 * 3;
	*buffer = safe_malloc(dec_size + extra);

	if (!read_block_dec(fd, line_no, col_no, bytes, *buffer, dec_size, &b64_cont)) {
		err("Error while reading encoded data");
		cf_free(*buffer);
		return false;
	}

	if ((size_t)(*bytes - orig_bytes) != enc_size) {
		err("Encoded data size mismatch: %zu vs. %" PRId64 " (line %u, col %u)", enc_size,
				*bytes - orig_bytes, line_no[0], col_no[0]);
		cf_free(*buffer);
		return false;
	}

	// we now know the real decoded size (excluding the padding)
	*size = b64_cont.size;
	return true;
}

///
/// Reads and parses a key value from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the key value.
///
/// @result         `true`, if successful.
///
static bool
text_parse_key(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		as_record *rec)
{
	int32_t ch = read_char(fd, line_no, col_no, bytes);

	if (ch == EOF) {
		return false;
	}

	int64_t int_val;
	double fp_val;
	void *buffer;
	size_t size;

	switch (ch) {
	case 'I':
		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			return false;
		}

		if (!text_read_integer(fd, legacy, line_no, col_no, bytes, &int_val, "\n")) {
			err("Error while reading integer key value");
			return false;
		}

		if (as_integer_init(&rec->key.value.integer, int_val) == NULL) {
			err("Error while initializing integer key value");
			return false;
		}

		rec->key.valuep = &rec->key.value;
		break;

	case 'D':
		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			return false;
		}

		if (!text_read_double(fd, legacy, line_no, col_no, bytes, &fp_val, "\n")) {
			err("Error while reading floating-point key value");
			return false;
		}

		// XXX - should become &rec->key.value.double, as soon as doubles are supported
		if (as_double_init((as_double *)&rec->key.value, fp_val) == NULL) {
			err("Error while initializing floating-point key value");
			return false;
		}

		rec->key.valuep = &rec->key.value;
		break;

	case 'S':
	case 'X':
		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			return false;
		}

		if (ch == 'S' && !text_parse_string(fd, legacy, line_no, col_no, bytes,
				&buffer, &size, 1)) {
			err("Error while reading string key value");
			return false;
		}

		if (ch == 'X' && !text_parse_data_dec(fd, legacy, line_no, col_no, bytes,
				&buffer, &size, 1)) {
			err("Error while reading encoded string key value");
			return false;
		}

		((char *)buffer)[size] = 0;

		if (as_string_init_wlen(&rec->key.value.string, buffer, size, true) == NULL) {
			err("Error while initializing string key value");
			cf_free(buffer);
			return false;
		}

		rec->key.valuep = &rec->key.value;
		break;

	case 'B':
		if ((ch = read_char(fd, line_no, col_no, bytes)) == EOF) {
			return false;
		}

		bool compact = ch == '!';

		if (!compact && !push_char(ch, fd, line_no, col_no, bytes)) {
			return false;
		}

		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			return false;
		}

		if (compact &&
				!text_parse_data(fd, legacy, line_no, col_no, bytes, &buffer, &size, 0)) {
			err("Error while reading key bytes");
			return false;
		}

		if (!compact && !text_parse_data_dec(fd, legacy, line_no, col_no, bytes,
				&buffer, &size, 0)) {
			err("Error while reading encoded key bytes");
			return false;
		}

		if (size > UINT_MAX) {
			err("Key value too large (%zu bytes)", size);
			return false;
		}

		if (as_bytes_init_wrap(&rec->key.value.bytes, buffer, (uint32_t)size, true) == NULL) {
			err("Error while initializing key bytes");
			return false;
		}

		rec->key.valuep = &rec->key.value;
		break;

	default:
		err("Invalid key type character %s in block (line %u, col %u)", print_char(ch),
				line_no[0], col_no[0]);
		return false;
	}

	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Reads and parses a namespace from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param ns_vec   The (optional) source and (also optional) target namespace to be restored.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the namespace.
///
/// @result         `true`, if successful.
///
static bool
text_parse_namespace(FILE *fd, bool legacy, as_vector *ns_vec, uint32_t *line_no, uint32_t *col_no,
		int64_t *bytes, as_record *rec)
{
	if (!text_nul_read_token(fd, legacy, line_no, col_no, bytes, rec->key.ns, sizeof rec->key.ns,
			"\n")) {
		err("Error while reading namespace token");
		return false;
	}

	if (ns_vec->size > 0) {
		const char *ns = as_vector_get_ptr(ns_vec, 0);

		if (strcmp(ns, rec->key.ns) != 0) {
			err("Invalid namespace %s in backup record, expected: %s (line %u, col %u)",
					rec->key.ns, ns, line_no[0], col_no[0]);
			return false;
		}

		if (ns_vec->size > 1) {
			ns = as_vector_get_ptr(ns_vec, 1);
			as_strncpy(rec->key.ns, ns, AS_NAMESPACE_MAX_SIZE);
		}
	}

	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Reads and parses a key digest from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the key digest.
///
/// @result         `true`, if successful.
///
static bool
text_parse_digest(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, as_record *rec)
{
	b64_context b64_cont = { 0, 9999, { 99, 99 }};

	if (!read_block_dec(fd, line_no, col_no, bytes, rec->key.digest.value,
			sizeof rec->key.digest.value, &b64_cont)) {
		err("Error while reading encoded digest string");
		return false;
	}

	rec->key.digest.init = true;
	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Reads and parses a set from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the set.
///
/// @result         `true`, if successful.
///
static bool
text_parse_set(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		as_record *rec)
{
	if (!text_nul_read_token(fd, legacy, line_no, col_no, bytes, rec->key.set, sizeof rec->key.set,
			"\n")) {
		err("Error while reading set token");
		return false;
	}

	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Reads and parses a generation count from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the generation count.
///
/// @result         `true`, if successful.
///
static bool
text_parse_generation(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no,
		int64_t *bytes, as_record *rec)
{
	int64_t val;

	if (!text_read_integer(fd, legacy, line_no, col_no, bytes, &val, "\n")) {
		err("Error while reading generation count");
		return false;
	}

	if (val < 0 || val > 65535) {
		err("Invalid generation count %" PRId64 " (line %u, col %u)", val, line_no[0], col_no[0]);
		return false;
	}

	rec->gen = (uint16_t)val;
	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Reads and parses an expiration time from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the generation count.
/// @param expired  Indicates the the expiration time lies in the past.
///
/// @result         `true`, if successful.
///
static bool
text_parse_expiration(FILE *fd, bool legacy, uint32_t *line_no, uint32_t *col_no,
		int64_t *bytes, as_record *rec, bool *expired)
{
	int64_t val;

	if (!text_read_integer(fd, legacy, line_no, col_no, bytes, &val, "\n")) {
		err("Error while reading expiration time");
		return false;
	}

	if (val < 0 || val > UINT_MAX) {
		err("Invalid expiration time %" PRIu64 " (line %u, col %u)", val, line_no[0], col_no[0]);
		return false;
	}

	if (val == 0) {
		rec->ttl = (uint32_t)-1;
	} else {
		cf_clock now = cf_secs_since_clepoch();

		if ((uint32_t)now >= (uint32_t)val) {
			*expired = true;
		} else {
			rec->ttl = (uint32_t)val - (uint32_t)now;
		}
	}

	return expect_char(fd, line_no, col_no, bytes, '\n');
}

///
/// Maps a one-character label to the corresponding BLOB type.
///
/// @param label  The one-character label.
/// @param type   The BLOB type.
///
/// @result      `true`, if successful.
///
static bool
text_bytes_label_to_type(int32_t label, as_bytes_type *type)
{
	static as_bytes_type types[] = {
		AS_BYTES_BLOB,
		AS_BYTES_JAVA,
		AS_BYTES_CSHARP,
		AS_BYTES_PYTHON,
		AS_BYTES_RUBY,
		AS_BYTES_PHP,
		AS_BYTES_ERLANG,
		AS_BYTES_MAP,
		AS_BYTES_LIST
	};

	static char labels[] = {
		'B', 'J', 'C', 'P', 'R', 'H', 'E', 'M', 'L'
	};

	for (size_t i = 0; i < sizeof labels; ++i) {
		if (label == labels[i]) {
			*type = types[i];
			return true;
		}
	}

	return false;
}

///
/// Reads and parses a bin from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param bin_vec  The bins to be restored, as a vector of bin name strings.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the bin.
///
/// @result         `true`, if successful.
///
static bool
text_parse_bin(FILE *fd, bool legacy, as_vector *bin_vec, uint32_t *line_no, uint32_t *col_no,
		int64_t *bytes, as_record *rec)
{
	if (!expect_char(fd, line_no, col_no, bytes, '-') ||
			!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	int32_t ch = read_char(fd, line_no, col_no, bytes);

	if (ch == EOF) {
		return false;
	}

	if (strchr("NIDSXGBJCPRHEMLU", ch) == NULL) {
		err("Invalid bytes label %s (line %u, col %u)", print_char(ch), line_no[0], col_no[0]);
		return false;
	}

	int32_t ch2 = read_char(fd, line_no, col_no, bytes);

	if (ch2 == EOF) {
		return false;
	}

	bool compact = ch2 == '!';

	if (!compact && !push_char(ch2, fd, line_no, col_no, bytes)) {
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	char name[MAX_TOKEN_SIZE];

	if (!text_nul_read_token(fd, legacy, line_no, col_no, bytes, name, sizeof name, " \n")) {
		err("Error while reading bin name token");
		return false;
	}

	bool match = bin_vec->size == 0;

	if (!match) {
		for (uint32_t i = 0; i < bin_vec->size; ++i) {
			if (strcmp(name, as_vector_get_ptr(bin_vec, i)) == 0) {
				match = true;
				break;
			}
		}
	}

	if (ch == 'N') {
		if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
			return false;
		}

		if (match && !as_record_set_nil(rec, name)) {
			err("Error while setting NIL bin %s (line %u, col %u)", name, line_no[0], col_no[0]);
			return false;
		}

		return true;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return false;
	}

	if (ch == 'I') {
		int64_t val;

		if (!text_read_integer(fd, legacy, line_no, col_no, bytes, &val, "\n")) {
			err("Error while reading integer bin value");
			return false;
		}

		if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
			return false;
		}

		if (match && !as_record_set_int64(rec, name, val)) {
			err("Error while setting integer bin %s to %" PRId64 " (line %u, col %u)", name, val,
					line_no[0], col_no[0]);
			return false;
		}

		return true;
	}

	if (ch == 'D') {
		double val;

		if (!text_read_double(fd, legacy, line_no, col_no, bytes, &val, "\n")) {
			err("Error while reading floating-point bin value");
			return false;
		}

		if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
			return false;
		}

		if (match && !as_record_set_double(rec, name, val)) {
			err("Error while setting floating-point bin %s to %.17g (line %u, col %u)", name, val,
					line_no[0], col_no[0]);
			return false;
		}

		return true;
	}

	if (ch == 'S' || ch == 'X') {
		void *buffer;
		size_t size;

		if (ch == 'S' && !text_parse_string(fd, legacy, line_no, col_no, bytes,
				&buffer, &size, 1)) {
			err("Error while reading string bin value");
			return false;
		}

		if (ch == 'X' && !text_parse_data_dec(fd, legacy, line_no, col_no, bytes,
				&buffer, &size, 1)) {
			err("Error while reading encoded string bin value");
			return false;
		}

		if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
			return false;
		}

		if (!match) {
			cf_free(buffer);
			return true;
		}

		((char *)buffer)[size] = 0;
		as_string *string = as_string_new_wlen(buffer, size, true);

		if (string == NULL) {
			err("Error while allocating string bin value");
			cf_free(buffer);
			return false;
		}

		if (!as_record_set_string(rec, name, string)) {
			err("Error while setting string bin %s to %s (line %u, col %u)", name, (char *)buffer,
					line_no[0], col_no[0]);
			as_string_destroy(string);
			cf_free(buffer);
			return false;
		}

		return true;
	}

	if (ch == 'G') {
		void *buffer;
		size_t size;

		if (!text_parse_string(fd, legacy, line_no, col_no, bytes, &buffer, &size, 1)) {
			err("Error while reading geojson bin value");
			return false;
		}

		if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
			return false;
		}

		if (!match) {
			cf_free(buffer);
			return true;
		}

		((char *)buffer)[size] = 0;
		as_geojson *geojson = as_geojson_new_wlen(buffer, size, true);

		if (geojson == NULL) {
			err("Error while allocating geojson bin value");
			cf_free(buffer);
			return false;
		}

		if (!as_record_set_geojson(rec, name, geojson)) {
			err("Error while setting geojson bin %s to %s (line %u, col %u)", name, (char *)buffer,
					line_no[0], col_no[0]);
			as_geojson_destroy(geojson);
			cf_free(buffer);
			return false;
		}

		return true;
	}

	if (ch == 'U') {
		err("The backup contains LDTs - please use an older version of this tool to "
				"restore the backup (line %u, col %u)", line_no[0], col_no[0]);
		return false;
	}

	as_bytes_type type;
	void *buffer;
	size_t size;

	if (!text_bytes_label_to_type(ch, &type)) {
		err("Invalid bytes label %s (line %u, col %u) - should not happen", print_char(ch),
				line_no[0], col_no[0]);
		return false;
	}

	if (compact && !text_parse_data(fd, legacy, line_no, col_no, bytes, &buffer, &size, 0)) {
		err("Error while reading data bin value");
		return false;
	}

	if (!compact && !text_parse_data_dec(fd, legacy, line_no, col_no, bytes, &buffer, &size, 0)) {
		err("Error while reading encoded data bin value");
		return false;
	}

	if (size > UINT_MAX) {
		err("Data bin value too large (%zu bytes)", size);
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
		return false;
	}

	if (!match) {
		cf_free(buffer);
		return true;
	}

	if (!as_record_set_raw_typep(rec, name, buffer, (uint32_t)size, type, true)) {
		err("Error while setting encoded data bin %s (line %u, col %u)", name, line_no[0],
				col_no[0]);
		return false;
	}

	return true;
}

///
/// Reads and parses the bins of a record from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param bin_vec  The bins to be restored, as a vector of bin name strings.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to receive the bins.
///
/// @result         `true`, if successful.
///
static bool
text_parse_bins(FILE *fd, bool legacy, as_vector *bin_vec, uint32_t *line_no, uint32_t *col_no,
		int64_t *bytes, as_record *rec)
{
	int64_t val;

	if (!text_read_integer(fd, legacy, line_no, col_no, bytes, &val, "\n")) {
		err("Error while reading bin count");
		return false;
	}

	if (val < 0 || val > 65535) {
		err("Invalid bin count %" PRIu64 " (line %u, col %u)", val, line_no[0], col_no[0]);
		return false;
	}

	if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
		return false;
	}

	uint16_t n_bins = (uint16_t)val;

	if (n_bins > rec->bins.capacity) {
		cf_free(rec->bins.entries);
		rec->bins.entries = safe_malloc(n_bins * sizeof (as_bin));
		rec->bins.capacity = n_bins;
	}

	for (uint32_t i = 0; i < n_bins; ++i) {
		if (!text_parse_bin(fd, legacy, bin_vec, line_no, col_no, bytes, rec)) {
			return false;
		}
	}

	return true;
}

///
/// Reads and parses a record from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param legacy   Indicates a version 3.0 backup file.
/// @param ns_vec   The (optional) source and (also optional) target namespace to be restored.
/// @param bin_vec  The bins to be restored, as a vector of bin name strings.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param rec      The record to be populated.
/// @param expired  Indicates that the record is expired.
///
/// @result         See @ref decoder_status.
///
static decoder_status
text_parse_record(FILE *fd, bool legacy, as_vector *ns_vec, as_vector *bin_vec, uint32_t *line_no,
		uint32_t *col_no, int64_t *bytes, as_record *rec, bool *expired)
{
	decoder_status res = DECODER_ERROR;
	bool tmp_expired = false;

	if (rec == NULL || expired == NULL) {
		err("Unexpected record backup block (line %u)", line_no[0]);
		goto cleanup0;
	}

	static char EXPECTED[8] = "kndsgtb";
	as_record_init(rec, 100);

	for (uint32_t i = 0; i < 7; ++i) {
		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			goto cleanup1;
		}

		int32_t ch = read_char(fd, line_no, col_no, bytes);

		if (ch == EOF) {
			goto cleanup1;
		}

		// "+ k" and "+ s" lines are optional
		if (i == 0 && ch == EXPECTED[1]) {
			++i;
		} else if (i == 3 && ch == EXPECTED[4]) {
			++i;
		} else if (ch != EXPECTED[i]) {
			err("Unexpected character %s in backup block (line %u, col %u), expected %s",
					print_char(ch), line_no[0], col_no[0], print_char(EXPECTED[i]));
			goto cleanup1;
		}

		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			goto cleanup1;
		}

		bool ok = false; // for older GCCs

		switch (i) {
		case 0:
			ok = text_parse_key(fd, legacy, line_no, col_no, bytes, rec);
			break;

		case 1:
			ok = text_parse_namespace(fd, legacy, ns_vec, line_no, col_no, bytes, rec);
			break;

		case 2:
			ok = text_parse_digest(fd, line_no, col_no, bytes, rec);
			break;

		case 3:
			ok = text_parse_set(fd, legacy, line_no, col_no, bytes, rec);
			break;

		case 4:
			ok = text_parse_generation(fd, legacy, line_no, col_no, bytes, rec);
			break;

		case 5:
			ok = text_parse_expiration(fd, legacy, line_no, col_no, bytes, rec, &tmp_expired);
			break;

		case 6:
			ok = text_parse_bins(fd, legacy, bin_vec, line_no, col_no, bytes, rec);
			break;
		}

		if (!ok) {
			err("Error while parsing record");
			goto cleanup1;
		}

		if (i < 6) {
			if (!expect_char(fd, line_no, col_no, bytes, RECORD_META_PREFIX[0])) {
				goto cleanup1;
			}
		}
	}

	*expired = tmp_expired;
	res = DECODER_RECORD;
	goto cleanup0;

cleanup1:
	as_record_destroy(rec);

cleanup0:
	return res;
}

///
/// Reads and parses secondary index information from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param ns_vec   The (optional) source and (also optional) target namespace to be restored.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param index    The index_param to be populated.
///
/// @result         See @ref decoder_status.
///
static decoder_status
text_parse_index(FILE *fd, as_vector *ns_vec, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		index_param *index)
{
	decoder_status res = DECODER_ERROR;

	if (index == NULL) {
		err("Unexpected index backup block (line %u)", line_no[0]);
		goto cleanup0;
	}

	if (verbose) {
		ver("Parsing index in line %u", line_no[0]);
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	char ns[MAX_TOKEN_SIZE];
	char set[MAX_TOKEN_SIZE];
	char name[MAX_TOKEN_SIZE];
	size_t n_paths;

	if (!text_nul_read_token(fd, false, line_no, col_no, bytes, ns, sizeof ns, " ")) {
		goto cleanup0;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	if (!text_nul_read_token(fd, false, line_no, col_no, bytes, set, sizeof set, " ")) {
		goto cleanup0;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	if (!text_nul_read_token(fd, false, line_no, col_no, bytes, name, sizeof name, " ")) {
		goto cleanup0;
	}

	if (ns_vec->size > 1) {
		const char *ns2 = as_vector_get_ptr(ns_vec, 0);

		if (strcmp(ns2, ns) != 0) {
			err("Invalid namespace %s in index %s, expected: %s (line %u, col %u)", ns, name, ns2,
					line_no[0], col_no[0]);
			goto cleanup0;
		}

		if (ns_vec->size > 1) {
			ns2 = as_vector_get_ptr(ns_vec, 1);
			as_strncpy(ns, ns2, MAX_TOKEN_SIZE);
		}
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	int32_t ch = read_char(fd, line_no, col_no, bytes);

	if (ch == EOF) {
		goto cleanup0;
	}

	switch (ch) {
	case 'N':
		index->type = INDEX_TYPE_NONE;
		break;

	case 'L':
		index->type = INDEX_TYPE_LIST;
		break;

	case 'K':
		index->type = INDEX_TYPE_MAPKEYS;
		break;

	case 'V':
		index->type = INDEX_TYPE_MAPVALUES;
		break;

	default:
		err("Invalid index type character %s in block (line %u, col %u)", print_char(ch),
				line_no[0], col_no[0]);
		goto cleanup0;
	}

	index->ns = safe_strdup(ns);
	index->set = safe_strdup(set);
	index->name = safe_strdup(name);

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup1;
	}

	if (!text_read_size(fd, false, line_no, col_no, bytes, &n_paths, " ")) {
		goto cleanup1;
	}

	if (n_paths == 0) {
		err("Missing path(s) in index block (line %u, col %u)", line_no[0], col_no[0]);
		goto cleanup1;
	}

	as_vector_init(&index->path_vec, sizeof (path_param), 25);
	path_param path;

	for (size_t i = 0; i < n_paths; ++i) {
		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			goto cleanup2;
		}

		if (!text_nul_read_token(fd, false, line_no, col_no, bytes, name, sizeof name, " ")) {
			goto cleanup2;
		}

		path.path = safe_strdup(name);

		if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
			goto cleanup3;
		}

		ch = read_char(fd, line_no, col_no, bytes);

		if (ch == EOF) {
			goto cleanup3;
		}

		switch (ch) {
		case 'S':
			path.type = PATH_TYPE_STRING;
			break;

		case 'N':
			path.type = PATH_TYPE_NUMERIC;
			break;

		case 'G':
			path.type = PATH_TYPE_GEOJSON;
			break;

		default:
			err("Invalid path type character %s in block (line %u, col %u)", print_char(ch),
					line_no[0], col_no[0]);
			goto cleanup3;
		}

		if (!expect_char(fd, line_no, col_no, bytes, i == n_paths - 1 ? '\n' : ' ')) {
			goto cleanup3;
		}

		as_vector_append(&index->path_vec, &path);
	}

	if (verbose) {
		if (index->set[0] == 0) {
			ver("Index: %s", index->name);
		} else {
			ver("Index: %s (on set %s)", index->name, index->set);
		}
	}

	res = DECODER_INDEX;
	goto cleanup0;

cleanup3:
	cf_free(path.path);

cleanup2:
	for (uint32_t i = 0; i < index->path_vec.size; ++i) {
		path_param *param = as_vector_get(&index->path_vec, i);
		cf_free(param->path);
	}

	as_vector_destroy(&index->path_vec);

cleanup1:
	cf_free(index->name);
	cf_free(index->set);

cleanup0:
	return res;
}

///
/// Reads and parses UDF files from the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param udf      The udf_param to be populated.
///
/// @result         See @ref decoder_status.
///
static decoder_status
text_parse_udf(FILE *fd, uint32_t *line_no, uint32_t *col_no, int64_t *bytes, udf_param *udf)
{
	decoder_status res = DECODER_ERROR;

	if (udf == NULL) {
		err("Unexpected UDF backup block (line %u)", line_no[0]);
		goto cleanup0;
	}

	if (verbose) {
		ver("Parsing UDF file in line %u", line_no[0]);
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	int32_t ch = read_char(fd, line_no, col_no, bytes);

	if (ch == EOF) {
		goto cleanup0;
	}

	switch (ch) {
	case 'L':
		udf->type = AS_UDF_TYPE_LUA;
		break;

	default:
		err("Invalid UDF type character %s in block (line %u, col %u)", print_char(ch),
				line_no[0], col_no[0]);
		goto cleanup0;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	char name[MAX_TOKEN_SIZE];
	size_t size;

	if (!text_nul_read_token(fd, false, line_no, col_no, bytes, name, sizeof name, " ")) {
		goto cleanup0;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	if (!text_read_size(fd, false, line_no, col_no, bytes, &size, " ")) {
		goto cleanup0;
	}

	if (size > UINT_MAX) {
		err("UDF file %s is too large (%zu bytes)", name, size);
		goto cleanup0;
	}

	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		goto cleanup0;
	}

	udf->name = safe_strdup(name);
	udf->size = (uint32_t)size;
	udf->data = safe_malloc(size);

	if (!read_block(fd, line_no, col_no, bytes, udf->data, udf->size)) {
		goto cleanup1;
	}

	if (!expect_char(fd, line_no, col_no, bytes, '\n')) {
		goto cleanup1;
	}

	if (verbose) {
		ver("UDF file: %s", udf->name);
	}

	res = DECODER_UDF;
	goto cleanup0;

cleanup1:
	cf_free(udf->data);
	cf_free(udf->name);

cleanup0:
	return res;
}

///
/// Reads and parses an entity from the global section (secondary index information, UDF files)
/// in the backup file.
///
/// @param fd       The file descriptor of the backup file.
/// @param ns_vec   The (optional) source and (also optional) target namespace to be restored.
/// @param line_no  The current line number.
/// @param col_no   The current column number.
/// @param bytes    Increased by the number of bytes read from the file descriptor.
/// @param index    The index_param to be populated.
/// @param udf      The udf_param to be populated.
///
/// @result         See @ref decoder_status.
///
static decoder_status
text_parse_global(FILE *fd, as_vector *ns_vec, uint32_t *line_no, uint32_t *col_no, int64_t *bytes,
		index_param *index, udf_param *udf)
{
	if (!expect_char(fd, line_no, col_no, bytes, ' ')) {
		return DECODER_ERROR;
	}

	int32_t type = read_char(fd, line_no, col_no, bytes);

	if (type == EOF) {
		return DECODER_ERROR;
	}

	if (type == 'i') {
		return text_parse_index(fd, ns_vec, line_no, col_no, bytes, index);
	}

	if (type == 'u') {
		return text_parse_udf(fd, line_no, col_no, bytes, udf);
	}

	err("Invalid global type character %s in block (line %u, col %u)", print_char(type), line_no[0],
			col_no[0]);
	return DECODER_ERROR;
}

///
/// The interface exposed by the text backup file format decoder.
///
/// See backup_decoder.parse for details.
///
decoder_status
text_parse(FILE *fd, bool legacy, as_vector *ns_vec, as_vector *bin_vec, uint32_t *orig_line_no,
		cf_atomic64 *total, as_record *rec, bool *expired, index_param *index, udf_param *udf)
{
	decoder_status res = DECODER_ERROR;
	int64_t bytes = 0;

	uint32_t line_no[2] = { *orig_line_no, *orig_line_no };
	uint32_t col_no[2] = { 1, 2 };

	int32_t ch = getc_unlocked(fd);

	if (ch == EOF) {
		if (ferror(fd) != 0) {
			err("Error while reading backup block (line %u, col %u)", line_no[0], col_no[0]);
			goto out;
		}

		if (verbose) {
			ver("Encountered end of file (line %u, col %u)", line_no[0], col_no[0]);
		}

		res = DECODER_EOF;
		goto out;
	}

	++bytes;

	if (!legacy && ch == GLOBAL_PREFIX[0]) {
		res = text_parse_global(fd, ns_vec, line_no, col_no, &bytes, index, udf);
		goto out;
	}

	if (ch == RECORD_META_PREFIX[0]) {
		res = text_parse_record(fd, legacy, ns_vec, bin_vec, line_no, col_no, &bytes, rec,
				expired);
		goto out;
	}

	err("Invalid start character %s in block (line %u, col %u)", print_char(ch), line_no[0],
			col_no[0]);

out:
	if (total != NULL) {
		cf_atomic64_add(total, bytes);
	}

	*orig_line_no = line_no[1];
	return res;
}
