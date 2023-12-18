/*
 * Aerospike Backup Tools Configuration
 *
 * Copyright (c) 2008-2022 Aerospike, Inc. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================
// Includes.
//

#include <stdbool.h>


//==========================================================
// Globals.
//

extern char *DEFAULT_PASSWORD;


//==========================================================
// Public API.
//

bool config_from_files(void *c, const char* instance, const char* cmd_config_fname, bool is_backup);
bool config_from_file(void *c, const char* instance, const char* fname, int level, bool is_backup);

bool tls_read_password(char* value, char** ptr);

#ifdef __cplusplus
}
#endif

