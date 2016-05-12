/*
 * Aerospike Restore Deserializer
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
#include <utils.h>

typedef struct {
	FILE *fd;
	uint32_t *line_no;
	uint32_t *col_no;
	uint32_t indent;
	int64_t *bytes;
	b64_context *b64_cont;
} serial_context;

extern bool get_list_size(serial_context *ser_cont, uint32_t *size);
extern bool unpack_value(serial_context *ser_cont, as_val **value);
extern bool get_list_size_dec(serial_context *ser_cont, uint32_t *size);
extern bool unpack_value_dec(serial_context *ser_cont, as_val **value);
