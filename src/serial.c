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

#include <serial.h>
#include <utils.h>

// #define VERY_VERBOSE

#if !defined VERY_VERBOSE
#define VERBOSE false
#else
#define VERBOSE verbose
#endif

#if !defined DECODE_BASE64
#define READ_CHAR(fd, line_no, col_no, bytes) read_char(fd, line_no, col_no, bytes)
#define READ_BLOCK(fd, line_no, col_no, bytes, buffer, size) \
		read_block(fd, line_no, col_no, bytes, buffer, size)
#define GET_LIST_SIZE(ser_cont, size) get_list_size(ser_cont, size)
#define UNPACK_VALUE(ser_cont, value) unpack_value(ser_cont, value)
#else
#define READ_CHAR(fd, line_no, col_no, bytes) \
		read_char_dec(fd, line_no, col_no, bytes, ser_cont->b64_cont)
#define READ_BLOCK(fd, line_no, col_no, bytes, buffer, size) \
		read_block_dec(fd, line_no, col_no, bytes, buffer, size, ser_cont->b64_cont)
#define GET_LIST_SIZE(ser_cont, size) get_list_size_dec(ser_cont, size)
#define UNPACK_VALUE(ser_cont, value) unpack_value_dec(ser_cont, value)
#endif

static inline const char *indent(serial_context *ser_cont)
{
	uint32_t indent = ser_cont->indent;

	if (indent > 50) {
		indent = 50;
	}

	//                1         2         3         4
	//      01234567890123456789012345678901234567890123456789
	return "                                                  " + (50 - indent);
}

// almost all functions adapted from as_msgpack.c

static inline bool
extract_uint8(serial_context *ser_cont, uint8_t *value)
{
	int32_t ch1 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (ch1 == EOF) {
		err("Error while reading 8-bit value");
		return false;
	}

	*value = (uint8_t)ch1;
	return true;
}

static inline bool
extract_uint16(serial_context *ser_cont, uint16_t *value)
{
	int32_t ch1 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);
	int32_t ch2 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (ch1 == EOF || ch2 == EOF) {
		err("Error while reading 16-bit value");
		return false;
	}

	*value = (uint16_t)(ch1 << 8 | ch2);
	return true;
}

static inline bool
extract_uint32(serial_context *ser_cont, uint32_t *value)
{
	int32_t ch1 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);
	int32_t ch2 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);
	int32_t ch3 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);
	int32_t ch4 = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (ch1 == EOF || ch2 == EOF || ch3 == EOF || ch4 == EOF) {
		err("Error while reading 32-bit value");
		return false;
	}

	*value = (uint32_t)(ch1 << 24 | ch2 << 16 | ch3 << 8 | ch4);
	return true;
}

static inline bool
extract_uint64(serial_context *ser_cont, uint64_t *value)
{
	uint32_t in1, in2;

	if (!extract_uint32(ser_cont, &in1) || !extract_uint32(ser_cont, &in2)) {
		err("Error while reading 64-bit value");
		return false;
	}

	*value = (uint64_t)in1 << 32 | in2;
	return true;
}

static inline bool
extract_float(serial_context *ser_cont, float *value)
{
	return extract_uint32(ser_cont, (uint32_t *)value);
}

static inline bool
extract_double(serial_context *ser_cont, double *value)
{
	return extract_uint64(ser_cont, (uint64_t *)value);
}

static inline bool
unpack_nil(serial_context *ser_cont, as_val **out)
{
	if (VERBOSE) {
		ver("%sNIL", indent(ser_cont));
	}

	*out = (as_val *)&as_nil;
	return true;
}

static inline bool
unpack_integer(serial_context *ser_cont, int64_t in, as_val **out)
{
	if (VERBOSE) {
		ver("%sInteger %" PRId64, indent(ser_cont), in);
	}

	as_val *tmp = (as_val *)as_integer_new(in);

	if (tmp == NULL) {
		err("Error while allocating integer");
		return false;
	}

	*out = tmp;
	return true;
}

static inline bool
unpack_double(serial_context *ser_cont, double in, as_val **out)
{
	if (VERBOSE) {
		ver("%sDouble %f", indent(ser_cont), in);
	}

	as_val *tmp = (as_val *)as_double_new(in);

	if (tmp == NULL) {
		err("Error while allocating double");
		return false;
	}

	*out = tmp;
	return true;
}

static inline bool
unpack_boolean(serial_context *ser_cont, bool in, as_val **out)
{
	if (VERBOSE) {
		ver("%sBoolean %s", indent(ser_cont), in ? "true" : "false");
	}

	return unpack_integer(ser_cont, in ? 1 : 0, out);
}

static bool
unpack_blob(serial_context *ser_cont, uint32_t size, as_val **value)
{
	int32_t type = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (type == EOF) {
		err("Error while reading BLOB type");
		return false;
	}

	--size;

	if (VERBOSE) {
		ver("%sBLOB, %u byte(s), type 0x%02x", indent(ser_cont), size, type);
	}

	// Waste one byte...
	void *buffer = safe_malloc(size + 1);

	// ... so that we can NUL-terminate all strings for as_string_val_hashcode().
	char *chars = buffer;
	chars[size] = 0;

	if (!READ_BLOCK(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes,
			buffer, size)) {
		err("Error while reading BLOB data");
		cf_free(buffer);
		return false;
	}

	if (type == AS_BYTES_STRING) {
		if (VERBOSE) {
			ver("%s  -> string BLOB: \"%s\"", indent(ser_cont), chars);
		}

		as_string *string = as_string_new_wlen(buffer, size, true);

		if (string == NULL) {
			err("Error while allocating string");
			cf_free(buffer);
			return false;
		}

		*value = (as_val *)string;
		return true;
	}

	if (type == AS_BYTES_GEOJSON) {
		if (VERBOSE) {
			ver("%s  -> geo BLOB: \"%s\"", indent(ser_cont), chars);
		}

		as_geojson *geo = as_geojson_new_wlen(buffer, size, true);

		if (geo == NULL) {
			err("Error while allocating geo value");
			cf_free(buffer);
			return false;
		}

		*value = (as_val *)geo;
		return true;
	}

	as_bytes *blob = as_bytes_new_wrap(buffer, size, true);

	if (blob == NULL) {
		err("Error while allocating BLOB");
		return false;
	}

	blob->type = (as_bytes_type)type;
	*value = (as_val *)blob;
	return true;
}

static bool
unpack_list(serial_context *ser_cont, uint32_t size, as_val **value)
{
	if (VERBOSE) {
		ver("%sList, %u element(s)", indent(ser_cont), size);
	}

	as_arraylist *list = as_arraylist_new(size, 8);

	if (list == NULL) {
		err("Error while allocating list");
		return false;
	}

	ser_cont->indent += 2;

	for (uint32_t i = 0; i < size; ++i) {
		as_val *element;

		if (!UNPACK_VALUE(ser_cont, &element)) {
			err("Error while unpacking list element");
			as_arraylist_destroy(list);
			return false;
		}

		if (as_arraylist_set(list, i, element) != AS_ARRAYLIST_OK) {
			err("Error while populating list");
			as_arraylist_destroy(list);
			return false;
		}
	}

	ser_cont->indent -= 2;
	*value = (as_val *)list;
	return true;
}

bool
GET_LIST_SIZE(serial_context *ser_cont, uint32_t *size)
{
	int32_t type = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (type == EOF) {
		err("Error while reading list type");
		return false;
	}

	if (type == 0xdc) {
		uint16_t tmp;

		if (!extract_uint16(ser_cont, &tmp)) {
			err("Error while reading 16-bit list size");
			return false;
		}

		*size = tmp;
		return true;
	}

	if (type == 0xdd) {
		uint32_t tmp;

		if (!extract_uint32(ser_cont, &tmp)) {
			err("Error while reading 32-bit list size");
			return false;
		}

		*size = tmp;
		return true;
	}

	if ((type & 0xf0) == 0x90) {
		*size = type & 0x0f;
		return true;
	}

	err("Serialized value is not a list");
	return false;
}

static bool
unpack_map(serial_context *ser_cont, uint32_t size, as_val **value)
{
	if (VERBOSE) {
		ver("%sMap, %u element(s)", indent(ser_cont), size);
	}

	as_hashmap *map = as_hashmap_new(size > 32 ? size : 32);

	if (map == NULL) {
		err("Error while allocating map");
		return false;
	}

	ser_cont->indent += 2;

	for (uint32_t i = 0; i < size; ++i) {
		as_val *key, *val;

		if (!UNPACK_VALUE(ser_cont, &key) || !UNPACK_VALUE(ser_cont, &val)) {
			err("Error while unpacking map key or value");
			as_hashmap_destroy(map);
			return false;
		}

		if (as_hashmap_set(map, key, val) < 0) {
			err("Error while populating map");
			as_hashmap_destroy(map);
			return false;
		}
	}

	ser_cont->indent -= 2;
	*value = (as_val *)map;
	return true;
}

bool
UNPACK_VALUE(serial_context *ser_cont, as_val **value)
{
	int32_t type = READ_CHAR(ser_cont->fd, ser_cont->line_no, ser_cont->col_no, ser_cont->bytes);

	if (type == EOF) {
		err("Error while reading value type");
		return false;
	}

	switch (type) {
	case 0xc0: // nil
		return unpack_nil(ser_cont, value);

	case 0xc3: // boolean true
		return unpack_boolean(ser_cont, true, value);

	case 0xc2: // boolean false
		return unpack_boolean(ser_cont, false, value);

	case 0xca: { // float
		float tmp;
		return extract_float(ser_cont, &tmp) && unpack_double(ser_cont, tmp, value);
	}

	case 0xcb: { // double
		double tmp;
		return extract_double(ser_cont, &tmp) && unpack_double(ser_cont, tmp, value);
	}

	case 0xd0: { // signed 8 bit integer
		int8_t tmp;
		return extract_uint8(ser_cont, (uint8_t *)&tmp) && unpack_integer(ser_cont, tmp, value);
	}
	case 0xcc: { // unsigned 8 bit integer
		uint8_t tmp;
		return extract_uint8(ser_cont, &tmp) && unpack_integer(ser_cont, tmp, value);
	}

	case 0xd1: { // signed 16 bit integer
		int16_t tmp;
		return extract_uint16(ser_cont, (uint16_t *)&tmp) && unpack_integer(ser_cont, tmp, value);
	}
	case 0xcd: { // unsigned 16 bit integer
		uint16_t tmp;
		return extract_uint16(ser_cont, &tmp) && unpack_integer(ser_cont, tmp, value);
	}

	case 0xd2: { // signed 32 bit integer
		int32_t tmp;
		return extract_uint32(ser_cont, (uint32_t *)&tmp) && unpack_integer(ser_cont, tmp, value);
	}
	case 0xce: { // unsigned 32 bit integer
		uint32_t tmp;
		return extract_uint32(ser_cont, &tmp) && unpack_integer(ser_cont, tmp, value);
	}

	case 0xd3: { // signed 64 bit integer
		int64_t tmp;
		return extract_uint64(ser_cont, (uint64_t *)&tmp) && unpack_integer(ser_cont, tmp, value);
	}
	case 0xcf: { // unsigned 64 bit integer
		uint64_t tmp;
		return extract_uint64(ser_cont, &tmp) && unpack_integer(ser_cont, (int64_t)tmp, value);
	}

	case 0xc4:
	case 0xd9: { // raw bytes with 8 bit header
		uint8_t size;
		return extract_uint8(ser_cont, &size) && unpack_blob(ser_cont, size, value);
	}
	case 0xc5:
	case 0xda: { // raw bytes with 16 bit header
		uint16_t size;
		return extract_uint16(ser_cont, &size) && unpack_blob(ser_cont, size, value);
	}
	case 0xc6:
	case 0xdb: { // raw bytes with 32 bit header
		uint32_t size;
		return extract_uint32(ser_cont, &size) && unpack_blob(ser_cont, size, value);
	}

	case 0xdc: { // list with 16 bit header
		uint16_t size;
		return extract_uint16(ser_cont, &size) && unpack_list(ser_cont, size, value);
	}
	case 0xdd: { // list with 32 bit header
		uint32_t size;
		return extract_uint32(ser_cont, &size) && unpack_list(ser_cont, size, value);
	}

	case 0xde: { // map with 16 bit header
		uint16_t size;
		return extract_uint16(ser_cont, &size) && unpack_map(ser_cont, size, value);
	}
	case 0xdf: { // map with 32 bit header
		uint32_t size;
		return extract_uint32(ser_cont, &size) && unpack_map(ser_cont, size, value);
	}

	default:
		if ((type & 0xe0) == 0xa0) { // raw bytes with 8 bit combined header
			return unpack_blob(ser_cont, type & 0x1f, value);
		}

		if ((type & 0xf0) == 0x80) { // map with 8 bit combined header
			return unpack_map(ser_cont, type & 0x0f, value);
		}

		if ((type & 0xf0) == 0x90) { // list with 8 bit combined header
			return unpack_list(ser_cont, type & 0x0f, value);
		}

		if (type < 0x80) { // 8 bit combined unsigned integer
			return unpack_integer(ser_cont, type, value);
		}

		if (type >= 0xe0) { // 8 bit combined signed integer
			return unpack_integer(ser_cont, type - 0xe0 - 32, value);
		}

		return false;
	}
}
