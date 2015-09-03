
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


#line 72 "src/spec.c"
static const char _spec_actions[] = {
	0, 1, 0, 1, 1, 1, 11, 1, 
	12, 1, 13, 1, 15, 1, 16, 1, 
	17, 1, 18, 1, 19, 1, 20, 1, 
	21, 2, 0, 11, 2, 0, 12, 2, 
	0, 13, 2, 0, 17, 2, 0, 19, 
	2, 2, 14, 2, 3, 14, 2, 4, 
	14, 2, 7, 14, 2, 8, 14, 2, 
	9, 14, 2, 10, 14, 2, 18, 11, 
	2, 20, 12, 3, 20, 5, 14, 3, 
	20, 6, 14
};

static const short _spec_key_offsets[] = {
	0, 0, 5, 10, 15, 20, 21, 22, 
	23, 24, 25, 30, 35, 42, 50, 56, 
	62, 68, 75, 82, 86, 90, 95, 100, 
	111, 122, 133, 134, 135, 136, 137, 141, 
	147, 153, 160, 165, 170, 171, 172, 173, 
	174, 175, 180, 181, 182, 183, 184, 185, 
	186, 191, 194, 195, 196, 200, 206, 212, 
	218, 223, 227, 231, 232, 233, 234, 238, 
	244, 250, 256, 261, 265, 269, 270, 271, 
	275, 281, 287, 293, 297, 302, 306, 310, 
	314, 315, 316, 320, 326, 332, 338, 342, 
	347, 351, 355, 359, 360, 361, 366, 367, 
	368, 369, 370, 371, 375, 381, 387, 394, 
	399, 404, 408
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
	108, 109, 115, 116, 9, 10, 13, 32, 
	9, 10, 13, 32, 48, 57, 9, 10, 
	13, 32, 48, 57, 9, 10, 13, 32, 
	48, 57, 9, 10, 13, 32, 41, 9, 
	10, 13, 32, 9, 10, 13, 32, 105, 
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
	13, 32, 97, 112, 9, 10, 13, 32, 
	9, 10, 13, 32, 48, 57, 9, 10, 
	13, 32, 48, 57, 9, 10, 13, 32, 
	48, 57, 9, 10, 13, 32, 9, 10, 
	13, 32, 41, 9, 10, 13, 32, 9, 
	10, 13, 32, 9, 10, 13, 32, 105, 
	108, 9, 10, 13, 32, 41, 116, 114, 
	105, 110, 103, 9, 10, 13, 32, 9, 
	10, 13, 32, 48, 57, 9, 10, 13, 
	32, 48, 57, 9, 10, 13, 32, 41, 
	48, 57, 9, 10, 13, 32, 40, 9, 
	10, 13, 32, 40, 9, 10, 13, 32, 
	9, 10, 13, 32, 0
};

static const char _spec_single_lengths[] = {
	0, 5, 5, 5, 5, 1, 1, 1, 
	1, 1, 5, 5, 1, 2, 4, 4, 
	4, 5, 5, 4, 4, 5, 5, 11, 
	11, 11, 1, 1, 1, 1, 4, 4, 
	4, 5, 5, 5, 1, 1, 1, 1, 
	1, 5, 1, 1, 1, 1, 1, 1, 
	5, 3, 1, 1, 4, 4, 4, 4, 
	5, 4, 4, 1, 1, 1, 4, 4, 
	4, 4, 5, 4, 4, 1, 1, 4, 
	4, 4, 4, 4, 5, 4, 4, 4, 
	1, 1, 4, 4, 4, 4, 4, 5, 
	4, 4, 4, 1, 1, 5, 1, 1, 
	1, 1, 1, 4, 4, 4, 5, 5, 
	5, 4, 4
};

static const char _spec_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 3, 3, 1, 1, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 1, 1, 1, 
	0, 0, 0, 0, 0, 0, 0, 1, 
	1, 1, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 1, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 1, 1, 1, 0, 
	0, 0, 0
};

static const short _spec_index_offsets[] = {
	0, 0, 6, 12, 18, 24, 26, 28, 
	30, 32, 34, 40, 46, 51, 57, 63, 
	69, 75, 82, 89, 94, 99, 105, 111, 
	123, 135, 147, 149, 151, 153, 155, 160, 
	166, 172, 179, 185, 191, 193, 195, 197, 
	199, 201, 207, 209, 211, 213, 215, 217, 
	219, 225, 229, 231, 233, 238, 244, 250, 
	256, 262, 267, 272, 274, 276, 278, 283, 
	289, 295, 301, 307, 312, 317, 319, 321, 
	326, 332, 338, 344, 349, 355, 360, 365, 
	370, 372, 374, 379, 385, 391, 397, 402, 
	408, 413, 418, 423, 425, 427, 433, 435, 
	437, 439, 441, 443, 448, 454, 460, 467, 
	473, 479, 484
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
	0, 116, 117, 118, 0, 119, 0, 120, 
	0, 121, 122, 121, 121, 0, 121, 122, 
	121, 121, 123, 0, 124, 125, 124, 124, 
	126, 0, 128, 129, 128, 128, 130, 127, 
	131, 132, 131, 131, 133, 0, 135, 136, 
	135, 135, 134, 138, 139, 138, 138, 137, 
	140, 0, 141, 0, 142, 0, 143, 144, 
	143, 143, 0, 143, 144, 143, 143, 145, 
	0, 146, 147, 146, 146, 148, 0, 150, 
	151, 150, 150, 152, 149, 153, 154, 153, 
	153, 155, 0, 157, 158, 157, 157, 156, 
	160, 161, 160, 160, 159, 162, 0, 163, 
	0, 164, 165, 164, 164, 0, 164, 165, 
	164, 164, 166, 0, 167, 168, 167, 167, 
	169, 0, 171, 172, 171, 171, 173, 170, 
	175, 176, 175, 175, 174, 177, 178, 177, 
	177, 179, 0, 181, 182, 181, 181, 180, 
	184, 185, 184, 184, 183, 187, 188, 187, 
	187, 186, 189, 0, 190, 0, 191, 192, 
	191, 191, 0, 191, 192, 191, 191, 193, 
	0, 194, 195, 194, 194, 196, 0, 198, 
	199, 198, 198, 200, 197, 202, 203, 202, 
	202, 201, 204, 205, 204, 204, 206, 0, 
	208, 209, 208, 208, 207, 211, 212, 211, 
	211, 210, 214, 215, 214, 214, 213, 216, 
	0, 217, 0, 218, 219, 218, 218, 220, 
	0, 221, 0, 222, 0, 223, 0, 224, 
	0, 225, 0, 226, 227, 226, 226, 0, 
	226, 227, 226, 226, 228, 0, 229, 230, 
	229, 229, 231, 0, 232, 233, 232, 232, 
	234, 235, 0, 36, 236, 36, 36, 3, 
	0, 39, 237, 39, 39, 6, 0, 95, 
	238, 95, 95, 0, 98, 239, 98, 98, 
	0, 0
};

static const char _spec_trans_targs[] = {
	0, 1, 2, 3, 1, 2, 3, 4, 
	5, 4, 5, 6, 7, 8, 9, 10, 
	11, 12, 10, 11, 12, 13, 14, 13, 
	14, 15, 16, 14, 15, 16, 17, 19, 
	20, 16, 17, 18, 103, 17, 18, 103, 
	17, 19, 20, 17, 19, 20, 21, 22, 
	23, 21, 22, 23, 24, 25, 26, 36, 
	42, 49, 80, 91, 94, 24, 25, 26, 
	36, 42, 49, 80, 91, 94, 24, 25, 
	26, 36, 42, 49, 80, 91, 94, 27, 
	28, 29, 30, 31, 32, 33, 31, 32, 
	33, 34, 35, 105, 33, 34, 35, 105, 
	34, 35, 105, 37, 38, 39, 40, 41, 
	34, 35, 105, 43, 44, 45, 46, 47, 
	48, 34, 35, 105, 50, 59, 69, 51, 
	52, 53, 54, 55, 53, 54, 55, 56, 
	57, 58, 55, 34, 35, 105, 56, 57, 
	58, 56, 57, 58, 60, 61, 62, 63, 
	64, 65, 63, 64, 65, 66, 67, 68, 
	65, 34, 35, 105, 66, 67, 68, 66, 
	67, 68, 70, 71, 72, 73, 74, 72, 
	73, 74, 75, 78, 79, 74, 76, 75, 
	77, 34, 35, 105, 76, 75, 77, 75, 
	78, 79, 75, 78, 79, 81, 82, 83, 
	84, 85, 83, 84, 85, 86, 89, 90, 
	85, 87, 86, 88, 34, 35, 105, 87, 
	86, 88, 86, 89, 90, 86, 89, 90, 
	92, 93, 34, 35, 105, 95, 96, 97, 
	98, 99, 100, 101, 102, 100, 101, 102, 
	34, 35, 105, 102, 104, 104, 106, 106
};

static const char _spec_trans_actions[] = {
	23, 0, 0, 0, 1, 1, 1, 0, 
	0, 1, 1, 0, 0, 0, 0, 0, 
	0, 0, 1, 1, 1, 11, 13, 0, 
	0, 0, 15, 1, 1, 34, 61, 17, 
	17, 0, 0, 0, 0, 1, 1, 1, 
	5, 0, 0, 25, 1, 1, 0, 0, 
	0, 1, 1, 1, 3, 3, 3, 3, 
	3, 3, 3, 3, 3, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 19, 1, 1, 
	37, 71, 71, 71, 0, 0, 0, 0, 
	1, 1, 1, 0, 0, 0, 0, 0, 
	46, 46, 46, 0, 0, 0, 0, 0, 
	0, 43, 43, 43, 0, 0, 0, 0, 
	0, 0, 0, 19, 1, 1, 37, 64, 
	21, 21, 0, 49, 49, 49, 7, 0, 
	0, 28, 1, 1, 0, 0, 0, 0, 
	0, 19, 1, 1, 37, 64, 21, 21, 
	0, 55, 55, 55, 7, 0, 0, 28, 
	1, 1, 0, 0, 0, 0, 19, 1, 
	1, 37, 64, 21, 21, 0, 9, 0, 
	0, 58, 58, 58, 31, 1, 1, 7, 
	0, 0, 28, 1, 1, 0, 0, 0, 
	0, 19, 1, 1, 37, 64, 21, 21, 
	0, 9, 0, 0, 52, 52, 52, 31, 
	1, 1, 7, 0, 0, 28, 1, 1, 
	0, 0, 40, 40, 40, 0, 0, 0, 
	0, 0, 0, 0, 19, 1, 1, 37, 
	67, 67, 67, 0, 0, 1, 0, 1
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
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 23, 
	23, 23, 23, 23, 23, 23, 23, 0, 
	1, 0, 1
};

static const int spec_start = 1;
static const int spec_first_final = 103;
static const int spec_error = 0;

static const int spec_en_type = 21;
static const int spec_en_main = 1;


#line 248 "src/spec.rl"


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


#line 383 "src/spec.c"
	{
	cs = spec_start;
	top = 0;
	}

#line 389 "src/spec.c"
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
#line 72 "src/spec.rl"
	{
		line = p;
		++line_no;
	}
	break;
	case 1:
#line 77 "src/spec.rl"
	{
		*type_out = (type_node *)safe_malloc(sizeof (type_node));
	}
	break;
	case 2:
#line 81 "src/spec.rl"
	{
		(*type_out)->type = NIL;
	}
	break;
	case 3:
#line 85 "src/spec.rl"
	{
		(*type_out)->type = INTEGER;
	}
	break;
	case 4:
#line 89 "src/spec.rl"
	{
		(*type_out)->type = DOUBLE;
	}
	break;
	case 5:
#line 93 "src/spec.rl"
	{
		(*type_out)->type = STRING;
	}
	break;
	case 6:
#line 97 "src/spec.rl"
	{
		(*type_out)->type = BYTES;
	}
	break;
	case 7:
#line 101 "src/spec.rl"
	{
		(*type_out)->type = LIST;
	}
	break;
	case 8:
#line 105 "src/spec.rl"
	{
		(*type_out)->type = MAP;
	}
	break;
	case 9:
#line 109 "src/spec.rl"
	{
		(*type_out)->type = LLIST;
	}
	break;
	case 10:
#line 113 "src/spec.rl"
	{
		(*type_out)->type = LMAP;
	}
	break;
	case 11:
#line 117 "src/spec.rl"
	{
		push(NULL);
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 12:
#line 122 "src/spec.rl"
	{
		push(type_out);
		type_out = &(*type_out)->children[0];
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 13:
#line 128 "src/spec.rl"
	{
		push(type_out);
		type_out = &(*type_out)->children[1];
		p--; {stack[top++] = cs; cs = 21; goto _again;}
	}
	break;
	case 14:
#line 134 "src/spec.rl"
	{
		type_out = pop();
		{cs = stack[--top]; goto _again;}
	}
	break;
	case 15:
#line 139 "src/spec.rl"
	{
		*rec_out = (rec_node *)safe_malloc(sizeof (rec_node));
		bin_out = &(*rec_out)->bins;
		token = p;
	}
	break;
	case 16:
#line 145 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		strncpy((*rec_out)->name, token, sizeof (*rec_out)->name - 1);
		*p = saved;
		token = NULL;
		rec_out = &(*rec_out)->next;
	}
	break;
	case 17:
#line 154 "src/spec.rl"
	{
		*bin_out = (bin_node *)safe_malloc(sizeof (bin_node));
		type_out = &(*bin_out)->type;
		token = p;
	}
	break;
	case 18:
#line 160 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		(*bin_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
		bin_out = &(*bin_out)->next;
	}
	break;
	case 19:
#line 169 "src/spec.rl"
	{
		token = p;
	}
	break;
	case 20:
#line 173 "src/spec.rl"
	{
		char saved = *p;
		*p = 0;
		(*type_out)->count = (uint32_t)strtoul(token, NULL, 10);
		*p = saved;
		token = NULL;
	}
	break;
	case 21:
#line 181 "src/spec.rl"
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
#line 640 "src/spec.c"
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
#line 72 "src/spec.rl"
	{
		line = p;
		++line_no;
	}
	break;
	case 21:
#line 181 "src/spec.rl"
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
#line 689 "src/spec.c"
		}
	}
	}

	_out: {}
	}

#line 267 "src/spec.rl"


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
