/*
 * Aerospike Set Filler Parser
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

#include <spec.h>

#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wunused-variable"

#define STACK_SIZE 1000

static type_node **stack[STACK_SIZE];
static int32_t sp = 0;

static void *safe_malloc(size_t size)
{
	void *mem = malloc(size);

	if (mem == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	memset(mem, 0, size);
	return mem;
}

static void push(type_node **type_out)
{
	if (sp == STACK_SIZE) {
		fprintf(stderr, "stack overflow\n");
		exit(1);
	}

	stack[sp++] = type_out;
}

static type_node **pop()
{
	if (sp == 0) {
		fprintf(stderr, "stack underflow\n");
		exit(1);
	}

	return stack[--sp];
}

%%{
	machine spec;
	write data;

	action new_line {
		line = p;
		++line_no;
	}

	action new_type {
		*type_out = (type_node *)safe_malloc(sizeof (type_node));
	}

	action set_nil {
		(*type_out)->type = NIL;
	}

	action set_integer {
		(*type_out)->type = INTEGER;
	}

	action set_double {
		(*type_out)->type = DOUBLE;
	}

	action set_string {
		(*type_out)->type = STRING;
	}

	action set_bytes {
		(*type_out)->type = BYTES;
	}

	action set_list {
		(*type_out)->type = LIST;
	}

	action set_map {
		(*type_out)->type = MAP;
	}

	action set_llist {
		(*type_out)->type = LLIST;
	}

	action set_lmap {
		(*type_out)->type = LMAP;
	}

	action root_type {
		push(NULL);
		fhold; fcall type;
	}

	action child_type1 {
		push(type_out);
		type_out = &(*type_out)->children[0];
		fhold; fcall type;
	}

	action child_type2 {
		push(type_out);
		type_out = &(*type_out)->children[1];
		fhold; fcall type;
	}

	action finish_type {
		type_out = pop();
		fret;
	}

	action new_record {
		*rec_out = (rec_node *)safe_malloc(sizeof (rec_node));
		bin_out = &(*rec_out)->bins;
		token = p;
	}

	action finish_record {
		char saved = *p;
		*p = 0;
		strncpy((*rec_out)->name, token, sizeof (*rec_out)->name - 1);
		*p = saved;
		token = NULL;
		rec_out = &(*rec_out)->next;
	}

	action new_bin {
		*bin_out = (bin_node *)safe_malloc(sizeof (bin_node));
		type_out = &(*bin_out)->type;
		token = p;
	}

	action finish_bin {
		char saved = *p;
		*p = 0;
		(*bin_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
		bin_out = &(*bin_out)->next;
	}

	action start_count {
		token = p;
	}

	action end_count {
		char saved = *p;
		*p = 0;
		(*type_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
	}

	action print_error {
		int32_t length = 0;

		while (line + length < pe && line[length] != '\r' && line[length] != '\n') {
			++length;
		}

		fprintf(stderr, "spec parse error in line %d:\n", line_no);

		for (int32_t i = 0; i < length; ++i) {
			fputc(line[i] == '\t' ? ' ' : line[i], stderr);
		}

		fputc('\n', stderr);
		int32_t offset = (int32_t)(p - line);

		for (int32_t i = 0; i < offset; ++i) {
			fputc(' ', stderr);
		}

		fputc('^', stderr);
		fputc('\n', stderr);
	}

	_ = "\t" | " " | "\r" | "\n" %new_line;

	nil_type = "nil";
	integer_type = "integer";
	double_type = "double";

	string_length = digit+;
	string_type = "string" _+ string_length >start_count %end_count;

	bytes_length = digit+;
	bytes_type = "bytes" _+ bytes_length >start_count %end_count;

	list_length = digit+;
	list_type = "list" _+ list_length >start_count %end_count _* %child_type1 <: any;

	map_size = digit+;
	map_type = "map" _+ map_size >start_count %end_count _* %child_type1 <: any _* %child_type2 <: any;

	llist_type = "llist" _+ list_length >start_count %end_count _* %child_type1 <: any;
	lmap_type = "lmap" _+ map_size >start_count %end_count _* %child_type1 <: any _* %child_type2 <: any;

	type_spec = (
			nil_type %set_nil |
			integer_type %set_integer |
			double_type %set_double |
			string_type %set_string |
			bytes_type %set_bytes |
			list_type %set_list |
			map_type %set_map |
			llist_type %set_llist |
			lmap_type %set_lmap
		) %finish_type;

	type := (_* "(" %new_type _* type_spec _* ")" _*) $err print_error;

	bin_count = digit+;
	bin = bin_count >new_bin %finish_bin _* %root_type <: any;

	record_name = (alnum | "-")+;
	record = "(" _* "record" _* "\"" record_name >new_record %finish_record "\"" _* (bin _*)+ ")";
	record_list = _* (record _*)+;

	main := record_list $err print_error;
}%%

bool parse(char *input, rec_node **rec_out)
{
	bin_node **bin_out = NULL;
	type_node **type_out = NULL;
	char *token = NULL;
	int32_t line_no = 1;
	char *p = input;
	char *line = input;
	char *pe = input + strlen(input);
	char *eof = pe;
	int32_t cs;
	int32_t stack[STACK_SIZE];
	int32_t top;

%%{
	write init;
	write exec;
}%%

	if (cs == spec_error) {
		fprintf(stderr, "error while parsing spec\n");
		return false;
	}

	if (cs < spec_first_final) {
		fprintf(stderr, "unexpected end of spec\n");
		return false;
	}

	return true;
}
