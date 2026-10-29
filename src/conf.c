/*
 * Copyright 2015-2022 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sa_client.h>
#include "toml.h"

#include <backup.h>
#include <restore.h>
#include <enc_text.h>
#include <utils.h>
#include <conf.h>


//==========================================================
// Typedefs & constants.
//

#define BACKUP_CONFIG_FILE ".aerospike/astools.conf"
#define ERR_BUF_SIZE 1024
#define PASSWORD_FILE_MAX_LEN 4999
#define PASSWORD_WHITESPACE " \t\n\v\f\r"
#define SA_ADDRESS_EXPECTED "<host>[:<port>] or [<ipv6>][:<port>]"
#define SA_PORT_EXPECTED "an integer from 1 to 65535"
#define SA_TIMEOUT_EXPECTED "an integer from 1 to 2147483647"
#define SA_CA_FILE_EXPECTED "a path to a CA certificate file"

typedef enum {
	CONFIG_PASS_MAIN,
	CONFIG_PASS_AGENT,
	// Only a rejected [secret-agent] section fails here. The main pass skips
	// any other bad include directory entry.
	CONFIG_PASS_AGENT_DIR
} config_pass_t;


//=========================================================
// Inline and Macros.
//

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif


//=========================================================
// Globals.
//

char *DEFAULT_PASSWORD = "SomeDefaultRandomPassword";

static volatile sig_atomic_t g_password_signal = 0;


//=========================================================
// Forward Declarations.
//

static bool config_str(const char *raw_val, void *ptr, const char* override);
static bool config_int32(const char *raw_val, int32_t *ptr, const char* override);
static bool config_int64(const char *raw_val, int64_t *ptr, const char* override);
static bool config_bool(const char *raw_val, void *ptr, const char* override);

static bool _config_str(const char *raw_val, void *ptr);
static bool _config_int32(const char *raw_val, int32_t *ptr);
static bool _config_int64(const char *raw_val, int64_t *ptr);
static bool _config_bool(const char *raw_val, void *ptr);

static bool config_parse_file(const char *fname, toml_table_t **tab, char errbuf[]);

static bool config_backup_cluster(toml_table_t *config_table, backup_config_t *c, const char *instance, char errbuf[], sa_client* sc, const config_cli_t *cli);
static bool config_backup(toml_table_t *config_table, backup_config_t *c, const char *instance, char errbuf[], sa_client* sc, const config_cli_t *cli);

static bool config_restore_cluster(toml_table_t *config_table, restore_config_t *c, const char *instance, char errbuf[], sa_client* sc, const config_cli_t *cli);
static bool config_restore(toml_table_t *config_table, restore_config_t *c, const char *instance, char errbuf[], sa_client* sc, const config_cli_t *cli);

static bool config_cli_sets(const config_cli_t *cli, const char *name);

static bool config_secret_agent(toml_table_t *config_table, sa_cfg *c, const char *instance, char errbuf[]);
static const char *sa_expected(const char *name);
static bool config_sa_number(const char *raw, int64_t max, int64_t *val);
static bool parse_sa_number(const char *s, int64_t max, int64_t *val);
static bool parse_sa_address(const char *address, char **host, int64_t *port);
static bool is_ipv6(const char *host, size_t len);
static void sa_cfg_set(sa_cfg *c, char *host, int64_t address_port, int64_t port, int64_t timeout);

static bool config_load_file(void *c, const char *instance, const char *fname, int level, bool is_backup, config_pass_t pass, const config_cli_t *cli);
static bool config_load_files(void *c, const char *instance, const char *cmd_config_fname, bool only_cmd_config_file, bool is_backup, config_pass_t pass, const config_cli_t *cli);
static bool config_include(toml_table_t *config_table, void *c, const char *instance, int level, bool is_backup, config_pass_t pass, const config_cli_t *cli);
static bool config_from_dir(void *c, const char *instance, char *dirname, int level, bool is_backup, config_pass_t pass, const config_cli_t *cli);

static const char *password_env_value(const char *opt_name, const char *var);
static bool password_env(const char *opt_name, const char *var, char **ptr);
static bool password_env_b64(const char *opt_name, const char *var, char **ptr);
static bool password_b64(const char *opt_name, const char *b64,
		const char *src_kind, const char *src_name, char **ptr);
static bool password_file(const char *opt_name, const char *path,
		size_t max_len, bool first_line, char **ptr);
static void password_trim(char *value);
static bool password_has_terminal(void);
static void password_on_signal(int sig);
static bool password_read_byte(char *c);
static char *password_read_prompt(const char *opt_name, const char *prompt,
		size_t max_len, bool *cut_off);

// returns 0 on success or if rtoml cannot be a secret path
// returns a value not equal to 0 on failure
// res is only set if a secret is successfully retrieved
static bool get_secret_rtoml(sa_client *sc, const char *rtoml, char **res, bool *is_secret);


//=========================================================
// Public API.
//

static bool
config_load_file(void *c, const char *instance, const char *fname,
		int level, bool is_backup, config_pass_t pass, const config_cli_t *cli)
{
	bool status = true;
	bool agent_pass = pass != CONFIG_PASS_MAIN;
	//fprintf(stderr, "Load file %d:%s\n", level, fname);
	toml_table_t *config_table = NULL;

	char errbuf[ERR_BUF_SIZE] = {""};
	if (! config_parse_file((char*)fname, &config_table, errbuf)) {
		if (pass == CONFIG_PASS_AGENT_DIR) {
			return true;
		}

		status = false;
	}
	else if (! config_table) {
		status = true;
	}

	if (status && config_table) {
		sa_set_log_function(&sa_log_err);
		sa_client sc;

		if (is_backup) {

			backup_config_set_heap_defaults((backup_config_t*)c);

			sa_cfg* secret_cfg = &((backup_config_t*)c)->secret_cfg;
			if (agent_pass && ! config_secret_agent(config_table, secret_cfg, instance, errbuf)) {
				status = false;
				goto cleanup;
			}

			sa_client_init(&sc, secret_cfg);

			if (! agent_pass && ! config_backup_cluster(config_table, (backup_config_t*)c, instance, errbuf, &sc, cli)) {
				status = false;
			} else if (! agent_pass && ! config_backup(config_table, (backup_config_t*)c, instance, errbuf, &sc, cli)) {
				status = false;
			} else if (! config_include(config_table, c, instance, level, is_backup, pass, cli)) {
				status = false;
			}
		} else {

			restore_config_set_heap_defaults((restore_config_t*)c);

			sa_cfg* secret_cfg = &((restore_config_t*)c)->secret_cfg;
			if (agent_pass && ! config_secret_agent(config_table, secret_cfg, instance, errbuf)) {
				status = false;
				goto cleanup;
			}

			sa_client_init(&sc, secret_cfg);

			if (! agent_pass && ! config_restore_cluster(config_table, (restore_config_t*)c, instance, errbuf, &sc, cli)) {
				status = false;
			} else if (! agent_pass && ! config_restore(config_table, (restore_config_t*)c, instance, errbuf, &sc, cli)) {
				status = false;
			} else if (! config_include(config_table, c, instance, level, is_backup, pass, cli)) {
				status = false;
			}
		}
	}

cleanup:
	toml_free(config_table);

	if (! status) {
		fprintf(stderr, "Parse error `%s` in file [%d:%s]\n", errbuf, level,
				fname);
	}
	return status;
}

bool
config_from_file(void *c, const char *instance, const char *fname,
		int level, bool is_backup)
{
	sa_ca_file_set(NULL, NULL);

	return config_load_file(c, instance, fname, level, is_backup,
			CONFIG_PASS_AGENT, NULL) &&
			config_load_file(c, instance, fname, level, is_backup,
			CONFIG_PASS_MAIN, NULL);
}

static bool
config_load_files(void *c, const char *instance, const char *cmd_config_fname,
		bool only_cmd_config_file, bool is_backup, config_pass_t pass,
		const config_cli_t *cli)
{
	if (! only_cmd_config_file) {
		// Load /etc/aerospike/astools.conf
		if (! config_load_file(c, instance, "/etc/aerospike/astools.conf", 0,
					is_backup, pass, cli)) {
			return false;
		}

		// Load $HOME/.aerospike/astools.conf
		char user_config_fname[128];
		snprintf(user_config_fname, 127, "%s/%s", getenv("HOME"), BACKUP_CONFIG_FILE);
		if (! config_load_file(c, instance, user_config_fname, 0, is_backup,
					pass, cli)) {
			return false;
		}
	}

	// Load user passed conf file
	if (cmd_config_fname) {
		if (! config_load_file(c, instance, cmd_config_fname, 0, is_backup,
					pass, cli)) {
			return false;
		}
	}
	return true;
}

bool
config_from_files(void *c, const char *instance, const char *cmd_config_fname,
		bool only_cmd_config_file, const config_cli_t *cli, bool is_backup)
{
	sa_cfg *secret_cfg = is_backup ? &((backup_config_t*)c)->secret_cfg :
			&((restore_config_t*)c)->secret_cfg;

	return config_load_files(c, instance, cmd_config_fname,
			only_cmd_config_file, is_backup, CONFIG_PASS_AGENT, NULL) &&
			config_secret_agent_cli(secret_cfg, cli) &&
			config_load_files(c, instance, cmd_config_fname,
			only_cmd_config_file, is_backup, CONFIG_PASS_MAIN, cli);
}

void
config_cli_add(config_cli_t *cli, const struct option *options, int opt)
{
	for (const struct option *o = options; o->name != NULL; o++) {
		if (o->val == opt) {
			as_vector_append(&cli->keys, (void*)&o->name);
		}
	}
}

bool
config_secret_agent_cli(sa_cfg *c, const config_cli_t *cli)
{
	const char *ca_option = cli->sa_ca_file != NULL ? "--sa-ca-file" : "--sa-cafile";
	const char *ca_file = cli->sa_ca_file != NULL ? cli->sa_ca_file : cli->sa_cafile;
	char *host = NULL;
	int64_t address_port = 0;
	int64_t port = 0;
	int64_t timeout = 0;

	if (cli->sa_cafile != NULL) {
		inf("Warning: Argument --sa-cafile is deprecated. Use --sa-ca-file instead.");
	}

	if (cli->sa_port != NULL && ! parse_sa_number(cli->sa_port, 65535, &port)) {
		err("--sa-port: invalid value \"%s\", expected " SA_PORT_EXPECTED,
				cli->sa_port);
		return false;
	}

	if (cli->sa_timeout != NULL &&
			! parse_sa_number(cli->sa_timeout, INT_MAX, &timeout)) {
		err("--sa-timeout: invalid value \"%s\", expected " SA_TIMEOUT_EXPECTED,
				cli->sa_timeout);
		return false;
	}

	if (cli->sa_address != NULL &&
			! parse_sa_address(cli->sa_address, &host, &address_port)) {
		err("--sa-address: invalid value \"%s\", expected " SA_ADDRESS_EXPECTED,
				cli->sa_address);
		return false;
	}

	if (ca_file != NULL && ca_file[0] == '\0') {
		err("%s: invalid value \"\", expected " SA_CA_FILE_EXPECTED, ca_option);
		cf_free(host);
		return false;
	}

	if (ca_file != NULL) {
		sa_ca_file_set(ca_file, ca_option);
	}

	sa_cfg_set(c, host, address_port, port, timeout);
	return true;
}

bool
tls_read_password(const char *opt_name, const char *value, char **ptr)
{
	*ptr = cf_strdup(value);

	if (*ptr == NULL) {
		err("%s: out of memory", opt_name);
		return false;
	}

	password_trim(*ptr);
	return resolve_password(opt_name, ptr, TLS_KEYFILE_PASSWORD_MAX_LEN, true);
}

bool
tls_read_secret(sa_client *sc, char **value, bool *is_secret)
{
	char *secret = NULL;

	*is_secret = false;
	password_trim(*value);

	if (get_secret_arg(sc, *value, &secret, is_secret) != 0) {
		return false;
	}

	if (*is_secret) {
		cf_free(*value);
		*value = secret;
	}

	return true;
}

bool
tls_prompt_password(const char *opt_name, char **ptr)
{
	bool cut_off;
	char *value = password_read_prompt(opt_name, "Enter TLS-Keyfile Password: ",
			TLS_KEYFILE_PASSWORD_MAX_LEN, &cut_off);

	*ptr = NULL;

	if (value == NULL) {
		return false;
	}

	if (cut_off) {
		err("%s: password is longer than %d bytes", opt_name,
				TLS_KEYFILE_PASSWORD_MAX_LEN);
		return false;
	}

	return tls_read_password(opt_name, value, ptr);
}

char *
password_prompt(const char *prompt, size_t max_len)
{
	bool cut_off;

	return password_read_prompt(PASSWORD_OPT, prompt, max_len, &cut_off);
}

bool
password_has_source(const char *value)
{
	return value != NULL && (strncmp(value, "env:", 4) == 0 ||
			strncmp(value, "env-b64:", 8) == 0 ||
			strncmp(value, "b64:", 4) == 0 ||
			strncmp(value, "file:", 5) == 0);
}

bool
password_fits(const char *opt_name, const char *value, size_t max_len)
{
	if (strlen(value) > max_len) {
		err("%s: password is longer than %zu bytes", opt_name, max_len);
		return false;
	}

	return true;
}

bool
auth_mode_is_pki(const char *auth_mode)
{
	return auth_mode != NULL && strcasecmp(auth_mode, "PKI") == 0;
}

bool
resolve_password(const char *opt_name, char **value, size_t max_len,
		bool first_line)
{
	const char *val = *value;
	const char *what;
	const char *name;
	char *res = NULL;
	bool ok;

	if (val == NULL) {
		return true;
	}

	if (strncmp(val, "env:", 4) == 0) {
		what = "value from environment variable ";
		name = val + 4;

		if (name[0] == '\0') {
			err("%s: env: requires a variable name", opt_name);
			return false;
		}

		ok = password_env(opt_name, name, &res);
	}
	else if (strncmp(val, "env-b64:", 8) == 0) {
		what = "decoded value from environment variable ";
		name = val + 8;

		if (name[0] == '\0') {
			err("%s: env-b64: requires a variable name", opt_name);
			return false;
		}

		ok = password_env_b64(opt_name, name, &res);
	}
	else if (strncmp(val, "b64:", 4) == 0) {
		what = "decoded b64: value";
		name = "";
		ok = password_b64(opt_name, val + 4, "b64: value", "", &res);
	}
	else if (strncmp(val, "file:", 5) == 0) {
		what = "value from file ";
		name = val + 5;

		if (name[0] == '\0') {
			err("%s: file: requires a path", opt_name);
			return false;
		}

		if (max_len == 0) {
			max_len = PASSWORD_FILE_MAX_LEN;
		}

		ok = password_file(opt_name, name, max_len, first_line, &res);
	}
	else {
		return max_len == 0 || password_fits(opt_name, val, max_len);
	}

	if (! ok) {
		return false;
	}

	if (max_len != 0 && strlen(res) > max_len) {
		err("%s: %s%s is longer than %zu bytes", opt_name, what, name, max_len);
		cf_free(res);
		return false;
	}

	cf_free(*value);
	*value = res;
	return true;
}


//=========================================================
// Local helpers.
//

static bool
config_str(const char *raw_val, void *ptr, const char *override)
{
	if (override != NULL) {
		// if the config already has a non NULL value
		// assume it is a heap allocated default and free it
		if (*((char**) ptr) != NULL) {
			cf_free(*((char**) ptr));
		}

		*((char**) ptr) = safe_strdup(override);
		return true;
	}

	return _config_str(raw_val, ptr);
}

static bool
_config_str(const char *raw_val, void *ptr)
{
	if (! raw_val) {
		return false;
	}

	char *sval;
	if (0 == toml_rtos(raw_val, &sval)) {
		if (*((char**) ptr) != NULL) {
			cf_free(*((char**) ptr));
		}
		*((char**) ptr) = sval;
		return true;
	}
	return false;
}

static bool
config_int32(const char *raw_val, int32_t *ptr, const char *override)
{
	if (override != NULL) {
		return _config_int32(override, ptr);
	}

	return _config_int32(raw_val, ptr);
}

static bool
_config_int32(const char *raw_val, int32_t *ptr)
{
	if (! raw_val) {
		return false;
	}

	int64_t ival;
	if (0 == toml_rtoi(raw_val, &ival)) {
		*ptr = (int32_t)ival;
		return true;
	}
	return false;
}

static bool
config_int64(const char *raw_val, int64_t *ptr, const char *override)
{
	if (override != NULL) {
		return _config_int64(override, ptr);
	}

	return _config_int64(raw_val, ptr);
}

static bool
_config_int64(const char *raw_val, int64_t *ptr)
{
	if (! raw_val) {
		return false;
	}

	int64_t ival;
	if (0 == toml_rtoi(raw_val, &ival)) {
		*ptr = ival;
		return true;
	}
	return false;
}

static bool
config_bool(const char *raw_val, void *ptr, const char *override)
{
	if (override != NULL) {
		return _config_bool(override, ptr);
	}

	return _config_bool(raw_val, ptr);
}

static bool
_config_bool(const char *raw_val, void *ptr)
{
	if (! raw_val) {
		return false;
	}

	int bval;
	if (0 == toml_rtob(raw_val, &bval)) {
		*((bool*)ptr) = bval ? true : false;
		return true;
	}
	return false;
}

static bool
config_secret_agent(toml_table_t *config_table, sa_cfg *c, const char *instance,
		char errbuf[])
{
	// Defaults to "secret-agent" section in case present.
	toml_table_t *current_table = toml_table_in(config_table, "secret-agent");

	char secret_agent[256] = {"secret-agent"};
	if (instance) {
		char instance_section[256];
		snprintf(instance_section, sizeof(instance_section), "secret-agent_%s",
				instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(config_table, instance_section)) {
			current_table = toml_table_in(config_table, instance_section);
			strcpy(secret_agent, instance_section);
		}
	}

	if (! current_table) {
		return true;
	}

	const char *name;
	char *host = NULL;
	char *ca_file = NULL;
	char *cafile = NULL;
	int64_t address_port = 0;
	int64_t port = 0;
	int64_t timeout = 0;
	bool status = true;

	for (uint8_t k = 0; status && 0 != (name = toml_key_in(current_table, k)); k++) {
		const char *config_value = toml_raw_in(current_table, name);

		if (! strcasecmp("sa-address", name)) {
			char *address = NULL;
			cf_free(host);
			host = NULL;
			status = config_str(config_value, (void*)&address, NULL) &&
					parse_sa_address(address, &host, &address_port);
			cf_free(address);
		}
		else if (! strcasecmp("sa-port", name)) {
			status = config_sa_number(config_value, 65535, &port);
		}
		else if (! strcasecmp("sa-timeout", name)) {
			status = config_sa_number(config_value, INT_MAX, &timeout);
		}
		else if (! strcasecmp("sa-ca-file", name)) {
			status = config_str(config_value, (void*)&ca_file, NULL) &&
					ca_file[0] != '\0';
		}
		else if (! strcasecmp("sa-cafile", name)) {
			status = config_str(config_value, (void*)&cafile, NULL) &&
					cafile[0] != '\0';
		}
		else {
			snprintf(errbuf, ERR_BUF_SIZE, "Unknown parameter `%s` in `%s` section\n",
					name, secret_agent);
			status = false;
		}
	}

	const char *ca_key = ca_file != NULL ? "sa-ca-file" : "sa-cafile";
	const char *ca_path = ca_file != NULL ? ca_file : cafile;

	if (status) {
		if (ca_path != NULL) {
			char source[300];
			snprintf(source, sizeof(source), "%s in the [%s] config section", ca_key,
					secret_agent);
			sa_ca_file_set(ca_path, source);
		}

		sa_cfg_set(c, host, address_port, port, timeout);
	}
	else {
		const char *expected = sa_expected(name);
		const char *raw = toml_raw_in(current_table, name);

		if (errbuf[0] == '\0' && expected != NULL && raw != NULL) {
			char *value = NULL;
			bool is_str = _config_str(raw, (void*)&value);

			snprintf(errbuf, ERR_BUF_SIZE,
					"invalid value \"%s\" for %s in the [%s] config section, expected %s\n",
					is_str ? value : raw, name, secret_agent, expected);
			cf_free(value);
		}
		else if (errbuf[0] == '\0') {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section\n",
					name, secret_agent);
		}

		cf_free(host);
	}

	cf_free(ca_file);
	cf_free(cafile);
	return status;
}

static const char *
sa_expected(const char *name)
{
	if (! strcasecmp("sa-address", name)) {
		return SA_ADDRESS_EXPECTED;
	}

	if (! strcasecmp("sa-port", name)) {
		return SA_PORT_EXPECTED;
	}

	if (! strcasecmp("sa-timeout", name)) {
		return SA_TIMEOUT_EXPECTED;
	}

	if (! strcasecmp("sa-ca-file", name) || ! strcasecmp("sa-cafile", name)) {
		return SA_CA_FILE_EXPECTED;
	}

	return NULL;
}

static bool
config_sa_number(const char *raw, int64_t max, int64_t *val)
{
	char *s = NULL;

	if (raw != NULL && toml_rtoi(raw, val) == 0) {
		return *val >= 1 && *val <= max;
	}

	if (! _config_str(raw, (void*)&s)) {
		return false;
	}

	bool status = parse_sa_number(s, max, val);
	cf_free(s);
	return status;
}

static bool
parse_sa_number(const char *s, int64_t max, int64_t *val)
{
	size_t len = strlen(s);

	if (len == 0 || len > 10 || strspn(s, "0123456789") != len) {
		return false;
	}

	*val = strtoll(s, NULL, 10);
	return *val >= 1 && *val <= max;
}

static bool
parse_sa_address(const char *address, char **host, int64_t *port)
{
	const char *start = address;
	const char *port_str = NULL;
	size_t len = strlen(address);

	*port = 0;

	if (address[0] == '[') {
		const char *end = strchr(address, ']');

		if (end == NULL || (end[1] != '\0' && end[1] != ':')) {
			return false;
		}

		start = address + 1;
		len = (size_t) (end - start);

		if (! is_ipv6(start, len)) {
			return false;
		}

		if (end[1] == ':') {
			port_str = end + 2;
		}
	}
	else {
		const char *colon = strchr(address, ':');

		if (colon != NULL && strchr(colon + 1, ':') == NULL) {
			len = (size_t) (colon - address);
			port_str = colon + 1;
		}
		else if (colon != NULL && ! is_ipv6(address, len)) {
			return false;
		}
	}

	if (len == 0 || (port_str != NULL && ! parse_sa_number(port_str, 65535, port))) {
		return false;
	}

	*host = cf_strndup(start, len);
	return true;
}

static bool
is_ipv6(const char *host, size_t len)
{
	const char *zone = memchr(host, '%', len);
	size_t addr_len = zone != NULL ? (size_t) (zone - host) : len;
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr addr;

	if (addr_len >= sizeof(buf) || (zone != NULL && addr_len + 1 == len)) {
		return false;
	}

	memcpy(buf, host, addr_len);
	buf[addr_len] = '\0';
	return inet_pton(AF_INET6, buf, &addr) == 1;
}

static void
sa_cfg_set(sa_cfg *c, char *host, int64_t address_port, int64_t port,
		int64_t timeout)
{
	if (host != NULL) {
		cf_free(c->addr);
		c->addr = host;
	}

	if (port == 0) {
		port = address_port;
	}

	if (port != 0) {
		char port_str[8];
		snprintf(port_str, sizeof(port_str), "%d", (int) port);
		cf_free(c->port);
		c->port = safe_strdup(port_str);
	}

	if (timeout != 0) {
		c->timeout = (int) timeout;
	}
}

static bool
config_cli_sets(const config_cli_t *cli, const char *name)
{
	if (cli == NULL) {
		return false;
	}

	for (uint32_t i = 0; i < cli->keys.size; i++) {
		const char *key = *(const char**) as_vector_get((as_vector*) &cli->keys, i);

		if (! strcasecmp(key, name)) {
			return true;
		}
	}

	return false;
}

static bool
config_restore_cluster(toml_table_t *config_table, restore_config_t *c, const char *instance,
		char errbuf[], sa_client* sc, const config_cli_t *cli)
{
	// Defaults to "cluster" section in case present.
	toml_table_t *current_table = toml_table_in(config_table, "cluster");

	char cluster[256] = {"cluster"};
	if (instance) {
		snprintf(cluster, 255, "cluster_%s", instance);
		// No override for cluster section.
		current_table = toml_table_in(config_table, cluster);
	}

	if (! current_table) {
		return true;
	}

	const char *name;

	for (uint8_t k = 0; 0 != (name = toml_key_in(current_table, k)); k++) {

		if (config_cli_sets(cli, name)) {
			continue;
		}

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (strcasecmp("tls-keyfile-password", name) != 0 &&
				!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
			return false;
		}

		bool status;
		if (! strcasecmp("host", name)) {
			status = config_str(config_value, (void*)&c->host, override);

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int32(config_value, (void*)&c->port, override);

		} else if (! strcasecmp("use-services-alternate",  name)) {
			status = config_bool(config_value,
					(void*)&c->use_services_alternate, override);

		} else if (! strcasecmp("user", name)) {
			status = config_str(config_value, (void*)&c->user, override);

		} else if (! strcasecmp("password", name)) {
			status = config_str(config_value, (void*)&c->password, override);
			c->password_from_secret_agent = arg_is_secret;
			c->password_from_config_file = true;

		} else if (! strcasecmp("auth", name)) {
			status = config_str(config_value, &c->auth_mode, override);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(config_value, (void*)&c->tls.enable, override);

		} else if (! strcasecmp("tls-name", name)) {
			status = config_str(config_value, (void*)&c->tls_name, override);

		} else if (! strcasecmp("tls-protocols", name)) {
			status = config_str(config_value, (void*)&c->tls.protocols, override);

		} else if (! strcasecmp("tls-cipher-suite", name)) {
			status = config_str(config_value, (void*)&c->tls.cipher_suite, override);

		} else if (! strcasecmp("tls-crl-check", name)) {
			status = config_bool(config_value, (void*)&c->tls.crl_check, override);

		} else if (! strcasecmp("tls-crl-check-all", name)) {
			status = config_bool(config_value, (void*)&c->tls.crl_check_all, override);

		} else if (! strcasecmp("tls-keyfile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.keystring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.keyfile, override);
			}

		} else if (! strcasecmp("tls-keyfile-password", name)) {
			status = config_str(config_value, (void*)&c->tls.keyfile_pw, NULL);
			if (status && !tls_read_secret(sc, &c->tls.keyfile_pw,
						&c->tls_keyfile_pw_from_secret_agent)) {
				err("failed requesting secret: %s", c->tls.keyfile_pw);
				return false;
			}
			c->tls_keyfile_pw_from_config_file = true;

		} else if (! strcasecmp("tls-cafile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.castring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.cafile, override);
			}

		} else if (! strcasecmp("tls-capath", name)) {
			status = config_str(config_value, (void*)&c->tls.capath, override);

		} else if (! strcasecmp("tls-certfile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.certstring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.certfile, override);
			}

		} else if (! strcasecmp("tls-cert-blacklist", name)) {
			status = config_str(config_value, (void*)&c->tls.cert_blacklist, override);
			fprintf(stderr, "Warning: --tls-cert-blacklist is deprecated and will be removed in the next release. Use a crl instead\n");

		} else {
			snprintf(errbuf, ERR_BUF_SIZE, "Unknown parameter `%s` in `%s` section.\n", name,
					cluster);
			return false;
		}

		if (arg_is_secret) {
			cf_free(override);
		}

		if (! status) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}
	}
	return true;
}


static bool
config_backup_cluster(toml_table_t *config_table, backup_config_t *c, const char *instance,
		char errbuf[], sa_client* sc, const config_cli_t *cli)
{
	// Defaults to "cluster" section in case present.
	toml_table_t *current_table = toml_table_in(config_table, "cluster");

	char cluster[256] = {"cluster"};
	if (instance) {
		snprintf(cluster, 255, "cluster_%s", instance);
		// No override for cluster section.
		current_table = toml_table_in(config_table, cluster);
	}

	if (! current_table) {
		return true;
	}

	const char *name;

	for (uint8_t i = 0; 0 != (name = toml_key_in(current_table, i)); i++) {

		if (config_cli_sets(cli, name)) {
			continue;
		}

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (strcasecmp("tls-keyfile-password", name) != 0 &&
				!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
			return false;
		}

		bool status;
		if (! strcasecmp("host", name)) {
			status = config_str(config_value, (void*)&c->host, override);

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int32(config_value, (void*)&c->port, override);
		
		} else if (! strcasecmp("use-services-alternate",  name)) {
			status = config_bool(config_value,
					(void*)&c->use_services_alternate, override);

		} else if (! strcasecmp("user", name)) {
			status = config_str(config_value, (void*)&c->user, override);

		} else if (! strcasecmp("password", name)) {
			status = config_str(config_value, (void*)&c->password, override);
			c->password_from_secret_agent = arg_is_secret;
			c->password_from_config_file = true;

		} else if (! strcasecmp("auth", name)) {
			status = config_str(config_value, &c->auth_mode, override);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(config_value, (void*)&c->tls.enable, override);

		} else if (! strcasecmp("tls-name", name)) {
			status = config_str(config_value, (void*)&c->tls_name, override);

		} else if (! strcasecmp("tls-protocols", name)) {
			status = config_str(config_value, (void*)&c->tls.protocols, override);

		} else if (! strcasecmp("tls-cipher-suite", name)) {
			status = config_str(config_value, (void*)&c->tls.cipher_suite, override);

		} else if (! strcasecmp("tls-crl-check", name)) {
			status = config_bool(config_value, (void*)&c->tls.crl_check, override);

		} else if (! strcasecmp("tls-crl-check-all", name)) {
			status = config_bool(config_value, (void*)&c->tls.crl_check_all, override);

		} else if (! strcasecmp("tls-keyfile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.keystring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.keyfile, override);
			}

		} else if (! strcasecmp("tls-keyfile-password", name)) {
			status = config_str(config_value, (void*)&c->tls.keyfile_pw, NULL);
			if (status && !tls_read_secret(sc, &c->tls.keyfile_pw,
						&c->tls_keyfile_pw_from_secret_agent)) {
				err("failed requesting secret: %s", c->tls.keyfile_pw);
				return false;
			}
			c->tls_keyfile_pw_from_config_file = true;

		} else if (! strcasecmp("tls-cafile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.castring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.cafile, override);
			}

		} else if (! strcasecmp("tls-capath", name)) {
			status = config_str(config_value, (void*)&c->tls.capath, override);

		} else if (! strcasecmp("tls-certfile", name)) {
			if (arg_is_secret) {
				status = config_str(config_value, (void*)&c->tls.certstring, override);
			}
			else {
				status = config_str(config_value, (void*)&c->tls.certfile, override);
			}

		} else if (! strcasecmp("tls-cert-blacklist", name)) {
			status = config_str(config_value, (void*)&c->tls.cert_blacklist, override);
			fprintf(stderr, "Warning: --tls-cert-blacklist is deprecated and will be removed in the next release. Use a crl instead\n");

		} else {
			snprintf(errbuf, ERR_BUF_SIZE, "Unknown parameter `%s` in `%s` section.\n", name,
					cluster);
			return false;
		}

		if (arg_is_secret) {
			cf_free(override);
		}

		if (! status) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}
	}
	return true;
}

static bool
config_from_dir(void *c, const char *instance, char *dirname,
		int level, bool is_backup, config_pass_t pass, const config_cli_t *cli)
{
	DIR *dp;
	struct dirent *entry;

	if ((dp = opendir(dirname)) == NULL) {
		if (pass == CONFIG_PASS_AGENT_DIR) {
			return true;
		}

		fprintf(stderr, "Failed to open directory %s\n", dirname);
		return false;
	}

	config_pass_t entry_pass = pass == CONFIG_PASS_MAIN ? CONFIG_PASS_MAIN :
			CONFIG_PASS_AGENT_DIR;

	while ((entry = readdir(dp)) != NULL) {

		if (strcmp(".", entry->d_name) == 0
				|| strcmp("..", entry->d_name) == 0) {
			continue;
		}

		char path[strlen(dirname) + 1 + strlen(entry->d_name) + 1];
		sprintf(path, "%s/%s", dirname, entry->d_name);

		struct stat statbuf;
		lstat(path, &statbuf);

		bool ok = true;

		if (S_ISDIR(statbuf.st_mode)) {
			ok = config_from_dir(c, instance, path, level, is_backup, entry_pass,
					cli);
		} else if (S_ISREG(statbuf.st_mode)) {
			ok = config_load_file(c, instance, path, level, is_backup, entry_pass,
					cli);
		}

		if (! ok) {
			if (pass != CONFIG_PASS_MAIN) {
				closedir(dp);
				return false;
			}

			// ignore file loading error inside include directory
			fprintf(stderr, "Skipped .....\n");
		}
	}

	closedir(dp);
	return true;
}

static bool
config_include(toml_table_t *config_table, void *c, const char *instance,
		int level, bool is_backup, config_pass_t pass, const config_cli_t *cli)
{
	bool skip_errors = pass == CONFIG_PASS_AGENT_DIR;

	if (level > 3) {
		if (skip_errors) {
			return true;
		}

		fprintf(stderr, "include max recursion level %d", level);
		return false;
	}

	// Get include section
	toml_table_t *current_table = toml_table_in(config_table, "include");
	if (! current_table) {
		return true;
	}

	const char *name;
	for (uint8_t i = 0; 0 != (name = toml_key_in(current_table, i)); i++) {

		const char* raw_config_value = toml_raw_in(current_table, name);
		if (! raw_config_value) {
			if (skip_errors) {
				continue;
			}

			fprintf(stderr, "Invalid parameter value for `%s` in `%s` section.\n",
					name, "include");
			return false;
		}

		bool status;

		if (! strcasecmp("file", name)) {
			char *fname = NULL;
			status = config_str(raw_config_value, (void*)&fname, NULL);

			if (status) {
				if (! config_load_file(c, instance, fname, level + 1, is_backup,
							pass, cli)) {
					cf_free(fname);
					return false;
				}
				cf_free(fname);
			}

		} else if (! strcasecmp("directory", name)) {
			char *dirname = NULL;
			status = config_str(raw_config_value, (void*)&dirname, NULL);
			if (status) {
				if (! config_from_dir(c, instance, dirname, level + 1, is_backup,
							pass, cli)) {
					cf_free(dirname);
					return false;
				}
				cf_free(dirname);
			}

		} else if (skip_errors) {
			continue;
		} else {
			fprintf(stderr, "Unknown parameter `%s` in `include` section.\n", name);
			return false;
		}

		if (! status && ! skip_errors) {
			fprintf(stderr, "Invalid parameter value for `%s` in `include` section.\n",
					name);
			return false;
		}
	}
	return true;
}

static bool
config_parse_file(const char *fname, toml_table_t **tab, char errbuf[])
{
	FILE *fp = fopen(fname, "r");

	if (! fp) {
		// it ok if file is not found
		return true;
	}

	*tab = toml_parse_file(fp, errbuf, ERR_BUF_SIZE);
	fclose(fp);

	if (! *tab) {
		return false;
	}

	return true;
}


static bool
config_backup(toml_table_t *config_table, backup_config_t *c, const char *instance,
		char errbuf[], sa_client* sc, const config_cli_t *cli)
{
	// Defaults to "asbackup" section in case present.
	toml_table_t *current_table = toml_table_in(config_table, "asbackup");

	char asbackup[256] = {"asbackup"};
	if (instance) {
		snprintf(asbackup, 255, "asbackup_%s", instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(config_table, asbackup)) {
			current_table = toml_table_in(config_table, asbackup);
		}
	}

	if (! current_table) {
		return true;
	}

	const char *name;

	char *s;
	int64_t i_val;

	for (uint8_t k = 0; 0 != (name = toml_key_in(current_table, k)); k++) {

		if (config_cli_sets(cli, name)) {
			continue;
		}

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, asbackup);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
			return false;
		}

		bool status;
		if (! strcasecmp("namespace", name)) {
			s = NULL;
			status = config_str(config_value, (void*)&s, override);
			if (status) {
				as_strncpy(c->ns, s, AS_NAMESPACE_MAX_SIZE);
				cf_free(s);
			}

		} else if (! strcasecmp("set", name)) {
			s = NULL;
			status = config_str(config_value, (void*)&s, override);
			if (status) {
				status = parse_set_list(&c->set_list, s);
				cf_free(s);
			}

		} else if (! strcasecmp("continue", name)) {
			status = config_str(config_value, (void*)&c->state_file, override);

		} else if (! strcasecmp("state-file-dst", name)) {
			status = config_str(config_value, (void*)&c->state_file_dst, override);

		} else if (! strcasecmp("remove-files", name)) {
			status = config_bool(config_value, (void*)&c->remove_files, override);

		} else if (! strcasecmp("remove-artifacts", name)) {
			status = config_bool(config_value, (void*)&c->remove_artifacts, override);

		} else if (! strcasecmp("directory", name)) {
			status = config_str(config_value, (void*)&c->directory, override);
		
		} else if (! strcasecmp("output-file-prefix", name)) {
			status = config_str(config_value, &c->prefix, override);

		} else if (! strcasecmp("no-ttl-only", name)) {
			status = config_bool(config_value, &c->ttl_zero, override);

		} else if (! strcasecmp("max-records", name)) {
			status = config_int64(config_value, (int64_t*) &c->max_records, override);

		} else if (! strcasecmp("output-file", name)) {
			status = config_str(config_value, (void*)&c->output_file, override);

		} else if (! strcasecmp("file-limit", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->file_limit = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("records-per-second", name)) {
			status = config_int32(config_value, (int32_t*)&c->records_per_second, override);

		} else if (! strcasecmp("no-bins", name)) {
			status = config_bool(config_value, (void*)&c->no_bins, override);

		} else if (! strcasecmp("compact", name)) {
			status = config_bool(config_value, (void*)&c->compact, override);

		} else if (! strcasecmp("parallel", name)) {

			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->parallel = (int32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("compress", name)) {
			char* compress_type = NULL;
			status = config_str(config_value, (void*) &compress_type, override);
			if (status) {
				status = parse_compression_type(compress_type, &c->compress_mode) == 0;
				cf_free(compress_type);
			}

		} else if (! strcasecmp("compression-level", name)) {
			status = config_int32(config_value, (void*)&c->compression_level, override);

		} else if (! strcasecmp("encrypt", name)) {
			char* encrypt_type = NULL;
			status = config_str(config_value, (void*) &encrypt_type, override);
			if (status) {
				status = parse_encryption_type(encrypt_type, &c->encrypt_mode) == 0;
				cf_free(encrypt_type);
			}

		} else if (! strcasecmp("encryption-key-file", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}

			char* key_file = NULL;
			status = config_str(config_value, (void*) &key_file, override);
			if (status) {
				c->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
				if (arg_is_secret) {
					status = read_private_key(key_file, c->pkey) == 0;
				}
				else {
					status = read_private_key_file(key_file, c->pkey) == 0;
				}

				cf_free(key_file);
			}

		} else if (! strcasecmp("encryption-key-env", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}
			else {
				char* env_var = NULL;
				status = config_str(config_value, (void*) &env_var, override);
				if (status) {
					c->pkey = parse_encryption_key_env(env_var);
					status = c->pkey != NULL;
					cf_free(env_var);
				}
			}

		} else if (! strcasecmp("bin-list", name)) {
			status = config_str(config_value, (void*)&c->bin_list, override);

		} else if (! strcasecmp("node-list", name)) {
			status = config_str(config_value, (void*)&c->node_list, override);

		} else if (! strcasecmp("partition-list", name)) {
			status = config_str(config_value, (void*)&c->partition_list, override);

		} else if (! strcasecmp("after-digest", name)) {
			status = config_str(config_value, (void*)&c->after_digest, override);

		} else if (! strcasecmp("filter-exp", name)) {
			status = config_str(config_value, (void*)&c->filter_exp, override);

		} else if (! strcasecmp("modified-after", name)) {
			char* mod_after_time = NULL;
			status = config_str(config_value, (void*) &mod_after_time, override);
			if (status) {
				status = parse_date_time(mod_after_time, &c->mod_after);
				cf_free(mod_after_time);
			}

		} else if (! strcasecmp("modified-before", name)) {
			char* mod_before_time = NULL;
			status = config_str(config_value, (void*) &mod_before_time, override);
			if (status) {
				status = parse_date_time(mod_before_time, &c->mod_before);
				cf_free(mod_before_time);
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(config_value, (void*)&c->machine, override);

		} else if (! strcasecmp("estimate", name)) {
			status = config_bool(config_value, (void*)&c->estimate, override);

		} else if (! strcasecmp("estimate-samples", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->n_estimate_samples = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("verbose", name)) {
			status = config_bool(config_value, (void*)&g_verbose, override);

		} else if (! strcasecmp("nice", name)) {

			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->bandwidth = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("no-records", name)) {
			status = config_bool(config_value, (void*)&c->no_records, override);

		} else if (! strcasecmp("no-indexes", name)) {
			status = config_bool(config_value, (void*)&c->no_indexes, override);

		} else if (! strcasecmp("no-udfs", name)) {
			status = config_bool(config_value, (void*)&c->no_udfs, override);

		} else if (! strcasecmp("socket-timeout", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->socket_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("total-timeout", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->total_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("max-retries", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->max_retries = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("retry-delay", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->retry_delay = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("sleep-between-retries", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->retry_delay = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("prefer-racks", name)) {
			status = config_str(config_value, (void*)&c->prefer_racks, override);

		} else if (! strcasecmp("s3-region", name)) {
			status = config_str(config_value, (void*)&c->s3_region, override);

		} else if (! strcasecmp("s3-profile", name)) {
			status = config_str(config_value, (void*)&c->s3_profile, override);

		} else if (! strcasecmp("s3-endpoint-override", name)) {
			status = config_str(config_value, (void*)&c->s3_endpoint_override, override);

		} else if (! strcasecmp("s3-min-part-size", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->s3_min_part_size = (uint64_t) i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-max-async-downloads", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_downloads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-max-async-uploads", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_uploads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-connect-timeout", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val >= 0 && i_val <= UINT_MAX) {
				c->s3_connect_timeout = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-log-level", name)) {
			s = NULL;
			status = config_str(config_value, (void*)&s, override);
			if (status && !s3_parse_log_level(s, &c->s3_log_level)) {
				err("Invalid S3 log level \"%s\"", s);
				status = false;
			}

		} else if (! strcasecmp("s3-allow-system-proxy", name)) {
			status = config_bool(config_value, (void*)&c->s3_allow_system_proxy,
					override);

		} else {
			fprintf(stderr, "Unknown parameter `%s` in `%s` section\n", name,
					asbackup);
			return false;
		}

		if (arg_is_secret) {
			cf_free(override);
		}

		if (! status) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section\n",
					name, asbackup);
			return false;
		}
	}
	return true;
}

static bool
config_restore(toml_table_t *config_table, restore_config_t *c, const char *instance,
		char errbuf[], sa_client* sc, const config_cli_t *cli)
{
	// Defaults to "asrestore" section in case present.
	toml_table_t *current_table = toml_table_in(config_table, "asrestore");

	char asrestore[256] = {"asrestore"};
	if (instance) {
		snprintf(asrestore, 255, "asrestore_%s", instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(config_table, asrestore)) {
			current_table = toml_table_in(config_table, asrestore);
		}
	}

	if (! current_table) {
		return true;
	}

	const char *name;

	int64_t i_val = 0;
	char* s;

	for (uint8_t k = 0; 0 != (name = toml_key_in(current_table, k)); k++) {

		if (config_cli_sets(cli, name)) {
			continue;
		}

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, asrestore);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
			return false;
		}

		bool status;
		if (! strcasecmp("namespace", name)) {
			// TODO limit check of namespace size
			status = config_str(config_value, (void*)&c->ns_list, override);

		} else if (! strcasecmp("directory", name)) {
			status = config_str(config_value, (void*)&c->directory, override);

		} else if (! strcasecmp("directory-list", name)) {
			status = config_str(config_value, (void*)&c->directory_list, override);

		} else if (! strcasecmp("parent-directory", name)) {
			status = config_str(config_value, (void*)&c->parent_directory, override);

		} else if (! strcasecmp("input-file", name)) {
			status = config_str(config_value, (void*)&c->input_file, override);

		} else if (! strcasecmp("compress", name)) {
			char* compress_type = NULL;
			status = config_str(config_value, (void*) &compress_type, override);
			if (status) {
				status = parse_compression_type(compress_type, &c->compress_mode) == 0;
				cf_free(compress_type);
			}

		} else if (! strcasecmp("encrypt", name)) {
			char* encrypt_type = NULL;
			status = config_str(config_value, (void*) &encrypt_type, override);
			if (status) {
				status = parse_encryption_type(encrypt_type, &c->encrypt_mode) == 0;
				cf_free(encrypt_type);
			}

		} else if (! strcasecmp("encryption-key-file", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}

			char* key_file = NULL;
			status = config_str(config_value, (void*) &key_file, override);
			if (status) {
				c->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
				if (arg_is_secret) {
					status = read_private_key(key_file, c->pkey) == 0;
				}
				else {
					status = read_private_key_file(key_file, c->pkey) == 0;
				}

				cf_free(key_file);
			}

		} else if (! strcasecmp("encryption-key-env", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}
			else {
				char* env_var = NULL;
				status = config_str(config_value, (void*) &env_var, override);
				if (status) {
					c->pkey = parse_encryption_key_env(env_var);
					status = c->pkey != NULL;
					cf_free(env_var);
				}
			}

		} else if (! strcasecmp("parallel", name) || ! strcasecmp("threads", name)) {

			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val >= 1 && i_val <= MAX_THREADS) {
				c->parallel = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(config_value, (void*)&c->machine, override);

		} else if (! strcasecmp("verbose", name)) {
			status = config_bool(config_value, (void*)&g_verbose, override);

		} else if (! strcasecmp("bin-list", name)) {
			status = config_str(config_value, (void*)&c->bin_list, override);

		} else if (! strcasecmp("set-list", name)) {
			status = config_str(config_value, (void*)&c->set_list, override);

		} else if (! strcasecmp("unique", name)) {
			status = config_bool(config_value, (void*)&c->unique, override);

		} else if (! strcasecmp("ignore-record-error", name)) {
			status = config_bool(config_value, (void*)&c->ignore_rec_error, override);

		} else if (! strcasecmp("replace", name)) {
			status = config_bool(config_value, (void*)&c->replace, override);

		} else if (! strcasecmp("no-generation", name)) {
			status = config_bool(config_value, (void*)&c->no_generation, override);

		} else if (! strcasecmp("extra-ttl", name)) {
			status = config_int32(config_value, (void*)&c->extra_ttl, override);

		} else if (! strcasecmp("bandwidth", name)) {

			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0) {
				c->bandwidth = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("tps", name)) {
			status = config_int32(config_value, (void*)&c->tps, override);

		} else if (! strcasecmp("nice", name)) {
			status = config_str(config_value, (void*)&c->nice_list, override);

		} else if (! strcasecmp("no-records", name)) {
			status = config_bool(config_value, (void*)&c->no_records, override);
		
		} else if (! strcasecmp("validate", name)) {
			status = config_bool(config_value, (void*)&c->validate, override);

		} else if (! strcasecmp("no-indexes", name)) {
			status = config_bool(config_value, (void*)&c->no_indexes, override);

		} else if (! strcasecmp("indexes-last", name)) {
			status = config_bool(config_value, (void*)&c->indexes_last, override);

		} else if (! strcasecmp("no-udfs", name)) {
			status = config_bool(config_value, (void*)&c->no_udfs, override);

		} else if (! strcasecmp("wait", name)) {
			status = config_bool(config_value, (void*)&c->wait, override);

		} else if (! strcasecmp("timeout", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val >= 0) {
				c->timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("socket-timeout", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if (i_val >= 0) {
				c->socket_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("total-timeout", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->total_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("max-retries", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->max_retries = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("sleep-between-retries", name)) {
				fprintf(stderr, "Warning: `--sleep-between-retries` is deprecated and has no "
			"effect, use `--retry-scale-factor` to configure the amount "
			"to back off when retrying transactions.");
			status = true;

		} else if (! strcasecmp("retry-delay", name)) {
				fprintf(stderr, "Warning: `--retry-delay` is deprecated and has no "
			"effect, use `--retry-scale-factor` to configure the amount "
			"to back off when retrying transactions.");
			status = true;

		} else if (! strcasecmp("batch-size", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->batch_size = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("event-loops", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->event_loops = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("max-async-batches", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->max_async_batches = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("retry-scale-factor", name)) {
			status = config_int32(config_value, (int32_t*)&i_val, override);
			if ((int32_t) i_val >= 0) {
				c->retry_scale_factor = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("disable-batch-writes", name)) {
			status = config_bool(config_value, (void*)&c->disable_batch_writes, override);

		} else if (! strcasecmp("s3-region", name)) {
			status = config_str(config_value, (void*)&c->s3_region, override);

		} else if (! strcasecmp("s3-profile", name)) {
			status = config_str(config_value, (void*)&c->s3_profile, override);

		} else if (! strcasecmp("s3-endpoint-override", name)) {
			status = config_str(config_value, (void*)&c->s3_endpoint_override, override);

		} else if (! strcasecmp("s3-connect-timeout", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val >= 0 && i_val <= UINT_MAX) {
				c->s3_connect_timeout = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-max-async-downloads", name)) {
			status = config_int64(config_value, (void*)&i_val, override);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_downloads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-log-level", name)) {
			s = NULL;
			status = config_str(config_value, (void*)&s, override);
			if (status && !s3_parse_log_level(s, &c->s3_log_level)) {
				err("Invalid S3 log level \"%s\"", s);
				status = false;
			}

		} else if (! strcasecmp("s3-allow-system-proxy", name)) {
			status = config_bool(config_value, (void*)&c->s3_allow_system_proxy,
					override);

		} else {
			fprintf(stderr, "Unknown parameter `%s` in `%s` section\n", name,
					asrestore);
			return false;
		}

		if (arg_is_secret) {
			cf_free(override);
		}

		if (! status) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section\n",
					name, asrestore);
			return false;
		}
	}
	return true;
}

static const char *
password_env_value(const char *opt_name, const char *var)
{
	const char *val = getenv(var);

	if (val == NULL || val[0] == '\0') {
		err("%s: environment variable %s is not set or empty", opt_name, var);
		return NULL;
	}

	return val;
}

static bool
password_env(const char *opt_name, const char *var, char **ptr)
{
	const char *val = password_env_value(opt_name, var);

	if (val == NULL) {
		return false;
	}

	*ptr = cf_strdup(val);

	if (*ptr == NULL) {
		err("%s: out of memory reading environment variable %s", opt_name, var);
		return false;
	}

	return true;
}

static bool
password_env_b64(const char *opt_name, const char *var, char **ptr)
{
	const char *val = password_env_value(opt_name, var);

	if (val == NULL) {
		return false;
	}

	return password_b64(opt_name, val, "environment variable ", var, ptr);
}

static bool
password_b64(const char *opt_name, const char *b64, const char *src_kind,
		const char *src_name, char **ptr)
{
	size_t b64_len = strlen(b64);
	char *buf = cf_malloc(b64_len + 1);
	size_t enc_len = 0;

	if (buf == NULL) {
		err("%s: out of memory decoding %s%s", opt_name, src_kind, src_name);
		return false;
	}

	// Go's base64.StdEncoding skips line breaks, so do the same.
	for (size_t i = 0; i < b64_len; i++) {
		if (b64[i] != '\r' && b64[i] != '\n') {
			buf[enc_len++] = b64[i];
		}
	}

	uint32_t dec_len = 0;

	if (enc_len != 0 && ! cf_b64_validate_and_decode_in_place((uint8_t*) buf,
				(uint32_t) enc_len, &dec_len)) {
		err("%s: invalid base64 in %s%s", opt_name, src_kind, src_name);
		cf_free(buf);
		return false;
	}

	if (memchr(buf, '\0', dec_len) != NULL) {
		err("%s: %s%s decodes to a value containing a NUL byte", opt_name,
				src_kind, src_name);
		cf_free(buf);
		return false;
	}

	if (dec_len > 0 && buf[dec_len - 1] == '\n') {
		dec_len--;
	}

	buf[dec_len] = '\0';

	if (dec_len == 0) {
		err("%s: password from %s%s is empty", opt_name, src_kind, src_name);
		cf_free(buf);
		return false;
	}

	*ptr = buf;
	return true;
}

static bool
password_file(const char *opt_name, const char *path, size_t max_len,
		bool first_line, char **ptr)
{
	FILE *fh = fopen(path, "r");

	if (fh == NULL) {
		err("%s: cannot read file %s: %s", opt_name, path, strerror(errno));
		return false;
	}

	// Room for a trailing \r\n and one byte more, so an over-long value is
	// caught without reading the rest of the file.
	size_t cap = max_len + 3;
	char *buf = cf_malloc(cap + 1);

	if (buf == NULL) {
		err("%s: out of memory reading file %s", opt_name, path);
		fclose(fh);
		return false;
	}

	size_t len = 0;
	int c = EOF;

	while (len < cap && (c = getc(fh)) != EOF && c != '\0') {
		if (first_line && (c == '\n' || c == '\r')) {
			break;
		}

		buf[len++] = (char) c;
	}

	int read_errno = errno;
	bool read_failed = ferror(fh) != 0;

	fclose(fh);

	if (read_failed) {
		err("%s: cannot read file %s: %s", opt_name, path, strerror(read_errno));
		cf_free(buf);
		return false;
	}

	if (c == '\0') {
		err("%s: file %s contains a NUL byte", opt_name, path);
		cf_free(buf);
		return false;
	}

	if (len > 0 && buf[len - 1] == '\n') {
		len--;

		if (len > 0 && buf[len - 1] == '\r') {
			len--;
		}
	}

	buf[len] = '\0';

	if (len == 0) {
		err("%s: password from %sfile %s is empty", opt_name,
				first_line && c != EOF ? "first line of " : "", path);
		cf_free(buf);
		return false;
	}

	*ptr = buf;
	return true;
}

static void
password_trim(char *value)
{
	size_t start = strspn(value, PASSWORD_WHITESPACE);
	size_t end = strlen(value);

	while (end > start && strchr(PASSWORD_WHITESPACE, value[end - 1]) != NULL) {
		end--;
	}

	memmove(value, value + start, end - start);
	value[end - start] = '\0';
}

static bool
password_has_terminal(void)
{
	int fd = open(ctermid(NULL), O_RDONLY);

	if (fd < 0) {
		return false;
	}

	close(fd);
	return true;
}

static void
password_on_signal(int sig)
{
	g_password_signal = sig;
}

static bool
password_read_byte(char *c)
{
	while (true) {
		ssize_t n = read(STDIN_FILENO, c, 1);

		if (n == 1) {
			return true;
		}

		if (n < 0 && errno == EINTR && g_password_signal == 0) {
			continue;
		}

		return false;
	}
}

static char *
password_read_prompt(const char *opt_name, const char *prompt, size_t max_len,
		bool *cut_off)
{
	static char buf[TLS_KEYFILE_PASSWORD_MAX_LEN + 4];
	static const int signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM };

	*cut_off = false;

	if (password_has_terminal()) {
		return getpass(prompt);
	}

	size_t cap = max_len + 3;

	if (cap >= sizeof(buf)) {
		cap = sizeof(buf) - 1;
	}

	size_t n_signals = sizeof(signals) / sizeof(signals[0]);
	struct sigaction saved_sa[sizeof(signals) / sizeof(signals[0])];
	struct termios saved_term;
	bool typed = isatty(STDIN_FILENO) != 0;
	bool guarded = typed && tcgetattr(STDIN_FILENO, &saved_term) == 0;
	bool echo_off = false;

	fputs(prompt, stderr);
	g_password_signal = 0;

	// While echo is off, a signal restores the terminal before it takes effect.
	if (guarded) {
		struct sigaction sa;
		struct termios term = saved_term;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = password_on_signal;
		sigemptyset(&sa.sa_mask);

		for (size_t i = 0; i < n_signals; i++) {
			sigaction(signals[i], NULL, &saved_sa[i]);

			if (saved_sa[i].sa_handler != SIG_IGN) {
				sigaction(signals[i], &sa, NULL);
			}
		}

		term.c_lflag &= ~(tcflag_t) (ECHO | ECHONL);
		echo_off = tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == 0;
	}

	size_t len = 0;
	char c;

	// One byte at a time, so input after the line is left on stdin.
	while (len < cap && password_read_byte(&c)) {
		buf[len++] = c;

		if (c == '\n') {
			break;
		}
	}

	// A line that fills the bound is complete only if the input ends or the
	// line does.
	bool cut = len == cap && buf[len - 1] != '\n' && password_read_byte(&c) &&
			c != '\n';

	buf[len] = '\0';

	if (echo_off) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_term);
		fputc('\n', stderr);
	}

	if (guarded) {
		for (size_t i = 0; i < n_signals; i++) {
			sigaction(signals[i], &saved_sa[i], NULL);
		}

		if (g_password_signal != 0) {
			raise(g_password_signal);
			return NULL;
		}
	}

	if (memchr(buf, 0, len) != NULL) {
		err("%s: password from stdin contains a NUL byte", opt_name);
		return NULL;
	}

	// A cut-off line stays as read so the length check rejects it.
	if (cut) {
		*cut_off = true;
		return buf;
	}

	if (! typed) {
		password_trim(buf);
	}
	else if (len != 0 && buf[len - 1] == '\n') {
		buf[len - 1] = '\0';
	}

	return buf;
}

static bool
get_secret_rtoml(sa_client *sc, const char *rtoml, char **res, bool *is_secret)
{
	*is_secret = false;

	char *secret_str = NULL;
	if (toml_rtos(rtoml, &secret_str) != 0) {
		// this is not a string so it can't be a secret, skip it
		return true;
	}

	if (get_secret_arg(sc, secret_str, res, is_secret) != 0) {
		err("failed requesting secret: %s", secret_str);
		cf_free(secret_str);
		return false;
	}

	cf_free(secret_str);

	return true;
}
