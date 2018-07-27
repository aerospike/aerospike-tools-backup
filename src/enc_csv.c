/*
 * Copyright 2018 Aerospike, Inc.
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

#include <enc_csv.h>
#include <utils.h>

static bool csv_output_value(uint64_t *bytes, FILE *fd, as_val *val);
char *sep;

///
/// Writes a signed 64-bit integer to the backup file.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param val      The integer value to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_integer(uint64_t *bytes, FILE *fd, as_val *val)
{
	as_integer *v = as_integer_fromval(val);

	if (fprintf_bytes(bytes, fd, "%" PRId64, v->value) < 0) {
		err_code("Error while writing integer to backup file");
		return false;
	}

	return true;
}

///
/// Writes out map bin to the backup file.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param val      The integer value to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_map(uint64_t *bytes, FILE *fd, as_val *val)
{
	if (! val) {
		fprintf_bytes(bytes, fd, "");
		return true;
	}

	as_iterator* i = (as_iterator*)as_map_iterator_new((as_map*)val);
	bool delim = false;
	fprintf_bytes(bytes, fd, "{");

	while (as_iterator_has_next(i)) {
		if (delim) {
			fprintf_bytes(bytes, fd, ",");
		}

		as_pair* kv = (as_pair*)as_iterator_next(i);
		csv_output_value(bytes, fd, as_pair_1(kv));
		fprintf_bytes(bytes, fd, ":");
		csv_output_value(bytes, fd, as_pair_2(kv));

		delim = true;
	}
	fprintf_bytes(bytes, fd, "}");
	return true;
}



///
/// Writes out list bin to the backup file.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param val      The integer value to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_list(uint64_t *bytes, FILE *fd, as_val *val)
{
	if (! val) {
		fprintf_bytes(bytes, fd, "");
	}

	as_iterator* i = (as_iterator*)as_list_iterator_new((as_list*)val);
	bool delim = false;
	fprintf_bytes(bytes, fd, "[");
	while (as_iterator_has_next(i)) {
		if (delim) {
			fprintf_bytes(bytes, fd, ",");
		}
		csv_output_value(bytes, fd, (as_val *)as_iterator_next(i));
		delim = true;
	}
	fprintf_bytes(bytes, fd, "]");

	return true;
}


///
/// Writes a double-precision floating-point value to the backup file.
///
/// Using 17 significant digits makes sure that we read back the same value that we wrote.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param prefix1  The first string prefix.
/// @param prefix2  The second string prefix.
/// @param val      The floating point value to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_double(uint64_t *bytes, FILE *fd, as_val *val)
{
	as_double *v = as_double_fromval(val);

	if (fprintf_bytes(bytes, fd, "%.17g", v->value) < 0) {
		err_code("Error while writing double to backup file");
		return false;
	}

	return true;
}

///
/// Writes a string to the backup file without quote.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param string   Raw string
///
/// @result         `true`, if successful.
///
static bool
csv_output_raw(uint64_t *bytes, FILE *fd, char *str)
{
	if (fprintf_bytes(bytes, fd, "%s", str) < 0) {
		err_code("Error while writing data to backup file [1]");
		return false;
	}
	return true;
}

///
/// Writes a string to the backup file.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param val      The string to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_string(uint64_t *bytes, FILE *fd, as_val *val)
{
	as_string *v = as_string_fromval(val);
	if (fprintf_bytes(bytes, fd, "\"%s\"", v->value) < 0) {
		err_code("Error while writing data to backup file [1]");
		return false;
	}
	return true;
}

///
/// Writes a bin to the backup file.
///
/// @param bytes     Increased by the number of bytes written to the backup file.
/// @param fd        The file descriptor of the backup file.
/// @param bin_name  The name of the bin to be written.
/// @param val       The bin value to be written.
///
/// @result         `true`, if successful.
///
static bool
csv_output_value(uint64_t *bytes, FILE *fd, as_val *val)
{
	if (val == NULL || val->type == AS_NIL) {
		// TODO May be print nothing not sure.
		// currently error
		return false;
	}

	switch (val->type) {
	case AS_INTEGER:
		return csv_output_integer(bytes, fd, val);

	case AS_DOUBLE:
		return csv_output_double(bytes, fd, val);

	case AS_STRING:
		return csv_output_string(bytes, fd, val);
	
	case AS_LIST:
		return csv_output_list(bytes, fd, val);
	case AS_MAP:
		return csv_output_map(bytes, fd, val);

	case AS_GEOJSON:
	case AS_BYTES:
	default:
		err("Unsupported or Invalid value type %d", (int32_t)val->type);
		return false;
	}
}


static bool
csv_put_bin(uint64_t *bytes, FILE *fd, char *userbinname, const as_record *rec)
{
	bool bin_present_in_data = false;
	as_bin *bin = NULL;
	for (int32_t i = 0; i < rec->bins.size; ++i) {
		bin = &rec->bins.entries[i];

		if (strcmp (userbinname, bin->name) != 0) {
			continue;
		} else {
			bin_present_in_data = true;
			break;
		}
	}

	if (! bin_present_in_data) {
		csv_output_raw(bytes, fd, "");
	} else {
		fprintf_bytes(bytes, fd, "\"%s\":", userbinname);
		if (! csv_output_value(bytes, fd, (as_val *)bin->valuep)) {
			err("Error while writing record bin %s", bin->name);
			return false;
		}
	}
	return true;
}

bool
csv_set_delimitor(char *delimitor)
{
	sep = delimitor;
	return true;
}

///
/// Part of the interface exposed by the text backup file format encoder.
///
/// See backup_encoder.put_record for details.
///
bool
csv_put_record(uint64_t *bytes, FILE *fd, bool compact, const as_record *rec, as_vector *bin_list)
{
	// ignore compilor warning
	compact = compact;
	fprintf_bytes(bytes, fd, "{");

	for (uint32_t j = 0; j < bin_list->size; ++j) {

		char *userbinname = as_vector_get_ptr(bin_list, j);

		if (! csv_put_bin(bytes, fd, userbinname, rec)) {
			return false;
		}

		if (j < bin_list->size - 1) {
			csv_output_raw(bytes, fd, sep);
		}
	}
	fprintf_bytes(bytes, fd, "}");

	csv_output_raw(bytes, fd, "\r\n");
	return true;
}

///
/// Writes a header to the backup file.
///
/// @param bytes    Increased by the number of bytes written to the backup file.
/// @param fd       The file descriptor of the backup file.
/// @param bin_list The list of bins in csv dump
///
/// @result         `true`, if successful.
///

bool
csv_put_header(uint64_t *bytes, FILE *fd, as_vector *bin_list)
{
	return true;
	for (uint32_t j = 0; j < bin_list->size; ++j) {

		char *userbinname = as_vector_get_ptr(bin_list, j);

		csv_output_raw(bytes, fd, userbinname);

		if (j < bin_list->size - 1) {
			csv_output_raw(bytes, fd, sep);
		}
	}

	csv_output_raw(bytes, fd, "\r\n");
	return true;
}

bool
csv_put_udf_file(uint64_t *bytes, FILE *fd, const as_udf_file *file)
{
	bytes = bytes;
	fd = fd;
	file = file;
	// NOOP
	return true;
}

bool
csv_put_secondary_index(uint64_t *bytes, FILE *fd, const index_param *index)
{
	bytes = bytes;
	fd = fd;
	index = index;
	// NOOP
	return true;
}
