/*
 * Aerospike Set Filler Parser API
 *
 * Copyright (c) 2008-2015 Aerospike, Inc. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

///
/// The data type of a type node.
///
enum node_type_e {
	NIL,        ///< A NIL value.
	INTEGER,    ///< A 64-bit integer value.
	DOUBLE,     ///< A double-precision floating-point value.
	STRING,     ///< A string value.
	BYTES,      ///< A BLOB value.
	LIST,       ///< A list value.
	MAP         ///< A map value.
};

typedef enum node_type_e node_type;     ///< The data type of a type node.

struct type_node_s;
typedef struct type_node_s type_node;   ///< A type node. The type of a bin is a tree of these.

///
/// A type node. The type of a bin is a tree of these.
///
/// A bin that is a map of size 3 with integer keys and 50-character string values could look like
/// this:
///
/// @code
/// {
///   type = MAP, count = 3,
///   children = {
///     &{ type = INTEGER, count = 0, children = { NULL, NULL } },
///     &{ type = STRING, count = 50, children = { NULL, NULL } }
///   }
/// }
/// @endcode
///
/// A bin that is a list of length 5 of lists of length 3 of 20-character strings  could look like
/// this:
///
/// @code
/// {
///   type = LIST, count = 5,
///   children = {
///     &{
///        type = LIST, count = 3,
///        children = {
///          &{ type = STRING, count = 20, children = { NULL, NULL } },
///          NULL
///        }
///     },
///     NULL
///   }
/// }
/// @endcode
///
struct type_node_s {
	node_type type;         ///< The data type of this type node.
	uint32_t count;         ///< Usage depends on @ref type, string length for @ref STRING, BLOB
	                        ///  size for @ref BYTES, list length for @ref LIST, map size for
	                        ///  @ref MAP.
	type_node *children[2]; ///< Usage depends on @ref type, children[0] = type of list elements for
	                        ///  @ref LIST, children[0] = type of map keys and children[1] = type of
	                        ///  map values for @ref MAP.
};

struct bin_node_s;
typedef struct bin_node_s bin_node;     ///< A bin node. A record specification is basically a list
                                        ///  of these.

///
/// A bin node. A record specification is basically a list of these.
///
/// Each bin node specifies a type and how many bins of this type to add to a record.
///
struct bin_node_s {
	bin_node *next;     ///< Pointer for the linked list of bin nodes.
	uint32_t count;     ///< The number of bins to be added to the record.
	type_node *type;    ///< The type of the bins to be added to the record.
};

struct rec_node_s;
typedef struct rec_node_s rec_node;     ///< A record specification. Describes the bins of a record.

///
/// A record specification. Describes the bins of a record.
///
struct rec_node_s {
	rec_node *next;     ///< Pointer for the linked list of record specifications.
	char name[64];      ///< The name under which this specification can be accessed.
	bin_node *bins;     ///< The linked list of bin nodes for this record specification.
};

///
/// The only function exposed by the Ragel parser. Parses a specification file into a list of
/// @ref rec_node record specifications.
///
/// @param input    The specification file, NUL-terminated.
/// @param rec_out  The resulting linked list of record specifications.
///
/// @result         `true`, if successful.
///
extern bool parse(char *input, rec_node **rec_out);
