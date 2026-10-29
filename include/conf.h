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

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

#include <aerospike/as_vector.h>
#include <sa_client.h>


//==========================================================
// Typedefs & constants.
//

#define PASSWORD_OPT "--password"
#define PASSWORD_CONFIG_OPT "password in config file"
#define TLS_KEYFILE_PASSWORD_OPT "--tls-keyfile-password"
#define TLS_KEYFILE_PASSWORD_CONFIG_OPT "tls-keyfile-password in config file"

// OpenSSL's PEM_BUFSIZE: the C client cannot decrypt a key with a longer
// password.
#define TLS_KEYFILE_PASSWORD_MAX_LEN 1024

/*
 * The secret agent options given on the command line, and the long names of
 * the other options it gives. Config file keys with those names are skipped.
 */
typedef struct config_cli_s {
	const char* sa_address;
	const char* sa_port;
	const char* sa_timeout;
	const char* sa_ca_file;
	const char* sa_cafile;
	as_vector keys;
} config_cli_t;


//==========================================================
// Globals.
//

extern char *DEFAULT_PASSWORD;


//==========================================================
// Public API.
//

void config_cli_add(config_cli_t* cli, const struct option* options, int opt);
bool config_secret_agent_cli(sa_cfg* c, const config_cli_t* cli);

/*
 * Reads the [secret-agent] sections of every file, then the command line
 * secret agent options, then the other sections, so secrets in config files
 * are fetched with the final agent settings.
 */
bool config_from_files(void *c, const char* instance, const char* cmd_config_fname,
		bool only_cmd_config_file, const config_cli_t* cli, bool is_backup);
bool config_from_file(void *c, const char* instance, const char* fname, int level, bool is_backup);

bool tls_read_password(const char* opt_name, const char* value, char** ptr);
bool tls_read_secret(sa_client* sc, char** value, bool* is_secret);
bool tls_prompt_password(const char* opt_name, char** ptr);
char* password_prompt(const char* prompt, size_t max_len);
bool resolve_password(const char* opt_name, char** value, size_t max_len,
		bool first_line);
bool password_has_source(const char* value);
bool password_fits(const char* opt_name, const char* value, size_t max_len);
bool auth_mode_is_pki(const char* auth_mode);

#ifdef __cplusplus
}
#endif

