
#line 1 "src/spec.rl"
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


#line 65 "src/spec.c"
static const char _spec_actions[] = {
	0, 1, 0, 1, 1, 1, 9, 1, 
	10, 1, 11, 1, 13, 1, 14, 1, 
	15, 1, 16, 1, 17, 1, 18, 1, 
	19, 2, 0, 9, 2, 0, 10, 2, 
	0, 11, 2, 0, 15, 2, 0, 17, 
	2, 2, 12, 2, 3, 12, 2, 4, 
	12, 2, 7, 12, 2, 8, 12, 2, 
	16, 9, 2, 18, 10, 3, 18, 5, 
	12, 3, 18, 6, 12
};

static const short _spec_key_offsets[] = {
	0, 0, 5, 10, 15, 20, 21, 22, 
	23, 24, 25, 30, 35, 42, 50, 56, 
	62, 68, 75, 82, 86, 90, 95, 100, 
	111, 122, 133, 134, 135, 136, 137, 141, 
	147, 153, 160, 165, 170, 171, 172, 173, 
	174, 175, 180, 181, 182, 183, 184, 185, 
	186, 191, 192, 193, 194, 198, 204, 210, 
	216, 221, 225, 229, 230, 231, 235, 241, 
	247, 253, 257, 262, 266, 270, 274, 275, 
	276, 281, 282, 283, 284, 285, 286, 290, 
	296, 302, 309, 314, 319, 323
};

static const char _spec_trans_keys[] = {
	9, 10, 13, 32, 40, 9, 10, 13, 
	32, 40, 9, 10, 13, 32, 114, 9, 
	10, 13, 32, 114, 101, 99, 111, 114, 
	100, 9, 10, 13, 32, 34, 9, 10, 
	13, 32, 34, 45, 48, 57, 65, 90, 
	97, 122, 34, 45, 48, 57, 65, 90, 
	97, 122, 9, 10, 13, 32, 48, 57, 
	9, 10, 13, 32, 48, 57, 9, 10, 
	13, 32, 48, 57, 9, 10, 13, 32, 
	41, 48, 57, 9, 10, 13, 32, 41, 
	48, 57, 9, 10, 13, 32, 9, 10, 
	13, 32, 9, 10, 13, 32, 40, 9, 
	10, 13, 32, 40, 9, 10, 13, 32, 
	98, 100, 105, 108, 109, 110, 115, 9, 
	10, 13, 32, 98, 100, 105, 108, 109, 
	110, 115, 9, 10, 13, 32, 98, 100, 
	105, 108, 109, 110, 115, 121, 116, 101, 
	115, 9, 10, 13, 32, 9, 10, 13, 
	32, 48, 57, 9, 10, 13, 32, 48, 
	57, 9, 10, 13, 32, 41, 48, 57, 
	9, 10, 13, 32, 41, 9, 10, 13, 
	32, 41, 111, 117, 98, 108, 101, 9, 
	10, 13, 32, 41, 110, 116, 101, 103, 
	101, 114, 9, 10, 13, 32, 41, 105, 
	115, 116, 9, 10, 13, 32, 9, 10, 
	13, 32, 48, 57, 9, 10, 13, 32, 
	48, 57, 9, 10, 13, 32, 48, 57, 
	9, 10, 13, 32, 41, 9, 10, 13, 
	32, 9, 10, 13, 32, 97, 112, 9, 
	10, 13, 32, 9, 10, 13, 32, 48, 
	57, 9, 10, 13, 32, 48, 57, 9, 
	10, 13, 32, 48, 57, 9, 10, 13, 
	32, 9, 10, 13, 32, 41, 9, 10, 
	13, 32, 9, 10, 13, 32, 9, 10, 
	13, 32, 105, 108, 9, 10, 13, 32, 
	41, 116, 114, 105, 110, 103, 9, 10, 
	13, 32, 9, 10, 13, 32, 48, 57, 
	9, 10, 13, 32, 48, 57, 9, 10, 
	13, 32, 41, 48, 57, 9, 10, 13, 
	32, 40, 9, 10, 13, 32, 40, 9, 
	10, 13, 32, 9, 10, 13, 32, 0
};

static const char _spec_single_lengths[] = {
	0, 5, 5, 5, 5, 1, 1, 1, 
	1, 1, 5, 5, 1, 2, 4, 4, 
	4, 5, 5, 4, 4, 5, 5, 11, 
	11, 11, 1, 1, 1, 1, 4, 4, 
	4, 5, 5, 5, 1, 1, 1, 1, 
	1, 5, 1, 1, 1, 1, 1, 1, 
	5, 1, 1, 1, 4, 4, 4, 4, 
	5, 4, 4, 1, 1, 4, 4, 4, 
	4, 4, 5, 4, 4, 4, 1, 1, 
	5, 1, 1, 1, 1, 1, 4, 4, 
	4, 5, 5, 5, 4, 4
};

static const char _spec_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 3, 3, 1, 1, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 1, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 0, 0, 0, 0
};

static const short _spec_index_offsets[] = {
	0, 0, 6, 12, 18, 24, 26, 28, 
	30, 32, 34, 40, 46, 51, 57, 63, 
	69, 75, 82, 89, 94, 99, 105, 111, 
	123, 135, 147, 149, 151, 153, 155, 160, 
	166, 172, 179, 185, 191, 193, 195, 197, 
	199, 201, 207, 209, 211, 213, 215, 217, 
	219, 225, 227, 229, 231, 236, 242, 248, 
	254, 260, 265, 270, 272, 274, 279, 285, 
	291, 297, 302, 308, 313, 318, 323, 325, 
	327, 333, 335, 337, 339, 341, 343, 348, 
	354, 360, 367, 373, 379, 384
};

static const unsigned char _spec_indicies[] = {
	1, 2, 1, 1, 3, 0, 4, 5, 
	4, 4, 6, 0, 3, 7, 3, 3, 
	8, 0, 6, 9, 6, 6, 10, 0, 
	11, 0, 12, 0, 13, 0, 14, 0, 
	15, 0, 15, 16, 15, 15, 17, 0, 
	18, 19, 18, 18, 20, 0, 21, 21, 
	21, 21, 0, 22, 23, 23, 23, 23, 
	0, 24, 25, 24, 24, 26, 0, 27, 
	28, 27, 27, 29, 0, 31, 32, 31, 
	31, 33, 30, 34, 35, 34, 34, 36, 
	26, 0, 37, 38, 37, 37, 39, 29, 
	0, 41, 42, 41, 41, 40, 44, 45, 
	44, 44, 43, 46, 47, 46, 46, 48, 
	0, 49, 50, 49, 49, 51, 0, 52, 
	53, 52, 52, 54, 55, 56, 57, 58, 
	59, 60, 0, 61, 62, 61, 61, 63, 
	64, 65, 66, 67, 68, 69, 0, 70, 
	71, 70, 70, 72, 73, 74, 75, 76, 
	77, 78, 0, 79, 0, 80, 0, 81, 
	0, 82, 0, 83, 84, 83, 83, 0, 
	83, 84, 83, 83, 85, 0, 86, 87, 
	86, 86, 88, 0, 89, 90, 89, 89, 
	91, 92, 0, 93, 94, 93, 93, 95, 
	0, 96, 97, 96, 96, 98, 0, 99, 
	0, 100, 0, 101, 0, 102, 0, 103, 
	0, 104, 105, 104, 104, 106, 0, 107, 
	0, 108, 0, 109, 0, 110, 0, 111, 
	0, 112, 0, 113, 114, 113, 113, 115, 
	0, 116, 0, 117, 0, 118, 0, 119, 
	120, 119, 119, 0, 119, 120, 119, 119, 
	121, 0, 122, 123, 122, 122, 124, 0, 
	126, 127, 126, 126, 128, 125, 129, 130, 
	129, 129, 131, 0, 133, 134, 133, 133, 
	132, 136, 137, 136, 136, 135, 138, 0, 
	139, 0, 140, 141, 140, 140, 0, 140, 
	141, 140, 140, 142, 0, 143, 144, 143, 
	143, 145, 0, 147, 148, 147, 147, 149, 
	146, 151, 152, 151, 151, 150, 153, 154, 
	153, 153, 155, 0, 157, 158, 157, 157, 
	156, 160, 161, 160, 160, 159, 163, 164, 
	163, 163, 162, 165, 0, 166, 0, 167, 
	168, 167, 167, 169, 0, 170, 0, 171, 
	0, 172, 0, 173, 0, 174, 0, 175, 
	176, 175, 175, 0, 175, 176, 175, 175, 
	177, 0, 178, 179, 178, 178, 180, 0, 
	181, 182, 181, 181, 183, 184, 0, 36, 
	185, 36, 36, 3, 0, 39, 186, 39, 
	39, 6, 0, 95, 187, 95, 95, 0, 
	98, 188, 98, 98, 0, 0
};

static const char _spec_trans_targs[] = {
	0, 1, 2, 3, 1, 2, 3, 4, 
	5, 4, 5, 6, 7, 8, 9, 10, 
	11, 12, 10, 11, 12, 13, 14, 13, 
	14, 15, 16, 14, 15, 16, 17, 19, 
	20, 16, 17, 18, 82, 17, 18, 82, 
	17, 19, 20, 17, 19, 20, 21, 22, 
	23, 21, 22, 23, 24, 25, 26, 36, 
	42, 49, 59, 70, 73, 24, 25, 26, 
	36, 42, 49, 59, 70, 73, 24, 25, 
	26, 36, 42, 49, 59, 70, 73, 27, 
	28, 29, 30, 31, 32, 33, 31, 32, 
	33, 34, 35, 84, 33, 34, 35, 84, 
	34, 35, 84, 37, 38, 39, 40, 41, 
	34, 35, 84, 43, 44, 45, 46, 47, 
	48, 34, 35, 84, 50, 51, 52, 53, 
	54, 55, 53, 54, 55, 56, 57, 58, 
	55, 34, 35, 84, 56, 57, 58, 56, 
	57, 58, 60, 61, 62, 63, 64, 62, 
	63, 64, 65, 68, 69, 64, 66, 65, 
	67, 34, 35, 84, 66, 65, 67, 65, 
	68, 69, 65, 68, 69, 71, 72, 34, 
	35, 84, 74, 75, 76, 77, 78, 79, 
	80, 81, 79, 80, 81, 34, 35, 84, 
	81, 83, 83, 85, 85
};

static const char _spec_trans_actions[] = {
	23, 0, 0, 0, 1, 1, 1, 0, 
	0, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 1, 11, 13, 0, 
	0, 0, 15, 1, 1, 34, 55, 17, 
	17, 0, 0, 0, 0, 1, 1, 1, 
	5, 0, 0, 25, 1, 1, 0, 0, 
	0, 1, 1, 1, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 19, 1, 1, 
	37, 65, 65, 65, 0, 0, 0, 0, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	46, 46, 46, 0, 0, 0, 0, 0, 
	0, 43, 43, 43, 0, 0, 0, 0, 
	0, 19, 1, 1, 37, 58, 21, 21, 
	0, 49, 49, 49, 7, 0, 0, 28, 
	1, 1, 0, 0, 0, 0, 19, 1, 
	1, 37, 58, 21, 21, 0, 9, 0, 
	0, 52, 52, 52, 31, 1, 1, 7, 
	0, 0, 28, 1, 1, 0, 0, 40, 
	40, 40, 0, 0, 0, 0, 0, 0, 
	0, 19, 1, 1, 37, 61, 61, 61, 
	0, 0, 1, 0, 1
};

static const char _spec_eof_actions[] = {
	0, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 0, 1, 0, 1
};

static const int spec_start = 1;
static const int spec_first_final = 82;
static const int spec_error = 0;

static const int spec_en_type = 21;
static const int spec_en_main = 1;


#line 228 "src/spec.rl"


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


#line 324 "src/spec.c"
	{
	cs = spec_start;
	top = 0;
	}

#line 330 "src/spec.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _spec_trans_keys + _spec_key_offsets[cs];
	_trans = _spec_index_offsets[cs];

	_klen = _spec_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _spec_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _spec_indicies[_trans];
	cs = _spec_trans_targs[_trans];

	if ( _spec_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _spec_actions + _spec_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 65 "src/spec.rl"
	{
		line = p;
		++line_no;
	}
	break;
	case 1:
#line 70 "src/spec.rl"
	{
		*type_out = (type_node *)safe_malloc(sizeof (type_node));
	}
	break;
	case 2:
#line 74 "src/spec.rl"
	{
		(*type_out)->type = NIL;
	}
	break;
	case 3:
#line 78 "src/spec.rl"
	{
		(*type_out)->type = INTEGER;
	}
	break;
	case 4:
#line 82 "src/spec.rl"
	{
		(*type_out)->type = DOUBLE;
	}
	break;
	case 5:
#line 86 "src/spec.rl"
	{
		(*type_out)->type = STRING;
	}
	break;
	case 6:
#line 90 "src/spec.rl"
	{
		(*type_out)->type = BYTES;
	}
	break;
	case 7:
#line 94 "src/spec.rl"
	{
		(*type_out)->type = LIST;
	}
	break;
	case 8:
#line 98 "src/spec.rl"
	{
		(*type_out)->type = MAP;
	}
	break;
	case 9:
#line 102 "src/spec.rl"
	{
		push(NULL);
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 10:
#line 107 "src/spec.rl"
	{
		push(type_out);
		type_out = &(*type_out)->children[0];
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 11:
#line 113 "src/spec.rl"
	{
		push(type_out);
		type_out = &(*type_out)->children[1];
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 12:
#line 119 "src/spec.rl"
	{
		type_out = pop();
		{cs = stack[--top]; goto _again;}
	}
	break;
	case 13:
#line 124 "src/spec.rl"
	{
		*rec_out = (rec_node *)safe_malloc(sizeof (rec_node));
		bin_out = &(*rec_out)->bins;
		token = p;
	}
	break;
	case 14:
#line 130 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		strncpy((*rec_out)->name, token, sizeof (*rec_out)->name - 1);
		*p = saved;
		token = NULL;
		rec_out = &(*rec_out)->next;
	}
	break;
	case 15:
#line 139 "src/spec.rl"
	{
		*bin_out = (bin_node *)safe_malloc(sizeof (bin_node));
		type_out = &(*bin_out)->type;
		token = p;
	}
	break;
	case 16:
#line 145 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		(*bin_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
		bin_out = &(*bin_out)->next;
	}
	break;
	case 17:
#line 154 "src/spec.rl"
	{
		token = p;
	}
	break;
	case 18:
#line 158 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		(*type_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
	}
	break;
	case 19:
#line 166 "src/spec.rl"
	{
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
	break;
#line 569 "src/spec.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	const char *__acts = _spec_actions + _spec_eof_actions[cs];
	unsigned int __nacts = (unsigned int) *__acts++;
	while ( __nacts-- > 0 ) {
		switch ( *__acts++ ) {
	case 0:
#line 65 "src/spec.rl"
	{
		line = p;
		++line_no;
	}
	break;
	case 19:
#line 166 "src/spec.rl"
	{
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
	break;
#line 618 "src/spec.c"
		}
	}
	}

	_out: {}
	}

#line 247 "src/spec.rl"


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
