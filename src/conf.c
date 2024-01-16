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
#include <dirent.h>
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

static bool config_backup_cluster(toml_table_t *config_table, backup_config_t *c, const char *instance, char errbuf[], sa_client* sc);
static bool config_backup(toml_table_t *config_table, backup_config_t *c, const char *instance, char errbuf[], sa_client* sc);

static bool config_restore_cluster(toml_table_t *config_table, restore_config_t *c, const char *instance, char errbuf[], sa_client* sc);
static bool config_restore(toml_table_t *config_table, restore_config_t *c, const char *instance, char errbuf[], sa_client* sc);

static bool config_secret_agent(toml_table_t *config_table, sa_cfg *c, const char *instance, char errbuf[]);

static bool config_include(toml_table_t *config_table, void *c, const char *instance, int level, bool is_backup);
static bool config_from_dir(void *c, const char *instance, char *dirname, int level, bool is_backup);

static bool password_env(const char *var, char **ptr);
static bool password_file(const char *path, char **ptr);

// returns 0 on success or if rtoml cannot be a secret path
// returns a value not equal to 0 on failure
// res is only set if a secret is successfully retrieved
static bool get_secret_rtoml(sa_client *sc, const char *rtoml, char **res, bool *is_secret);


//=========================================================
// Public API.
//

bool
config_from_file(void *c, const char *instance, const char *fname,
		int level, bool is_backup)
{
	bool status = true;
	//fprintf(stderr, "Load file %d:%s\n", level, fname);
	toml_table_t *config_table = NULL;

	char errbuf[ERR_BUF_SIZE] = {""};
	if (! config_parse_file((char*)fname, &config_table, errbuf)) {
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
			if (! config_secret_agent(config_table, secret_cfg, instance, errbuf)) {
				status = false;
				goto cleanup;
			}

			sa_client_init(&sc, secret_cfg);

			if (! config_backup_cluster(config_table, (backup_config_t*)c, instance, errbuf, &sc)) {
				status = false;
			} else if (! config_backup(config_table, (backup_config_t*)c, instance, errbuf, &sc)) {
				status = false;
			} else if (! config_include(config_table, c, instance, level, is_backup)) {
				status = false;
			}
		} else {

			restore_config_set_heap_defaults((restore_config_t*)c);

			sa_cfg* secret_cfg = &((restore_config_t*)c)->secret_cfg;
			if (! config_secret_agent(config_table, secret_cfg, instance, errbuf)) {
				status = false;
				goto cleanup;
			}

			sa_client_init(&sc, secret_cfg);

			if (! config_restore_cluster(config_table, (restore_config_t*)c, instance, errbuf, &sc)) {
				status = false;
			} else if (! config_restore(config_table, (restore_config_t*)c, instance, errbuf, &sc)) {
				status = false;
			} else if (! config_include(config_table, c, instance, level, is_backup)) {
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
config_from_files(void *c, const char *instance,
		const char *cmd_config_fname, bool is_backup)
{
	// Load /etc/aerospike/astools.conf
	if (! config_from_file(c, instance, "/etc/aerospike/astools.conf", 0,
				is_backup)) {
		return false;
	}

	// Load $HOME/.aerospike/astools.conf
	char user_config_fname[128];
	snprintf(user_config_fname, 127, "%s/%s", getenv("HOME"), BACKUP_CONFIG_FILE);
	if (! config_from_file(c, instance, user_config_fname, 0, is_backup)) {
		return false;
	}

	// Load user passed conf file
	if (cmd_config_fname) {
		if (! config_from_file(c, instance, cmd_config_fname, 0, is_backup)) {
			return false;
		}
	}
	return true;
}

bool
tls_read_password(char *value, char **ptr)
{
	if (strncmp(value, "env:", 4) == 0) {
		return password_env(value + 4, ptr);
	}

	if (strncmp(value, "file:", 5) == 0) {
		return password_file(value + 5, ptr);
	}

	*ptr = safe_strdup(value);
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
		snprintf(secret_agent, 255, "secret-agent_%s", instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(config_table, secret_agent)) {
			current_table = toml_table_in(config_table, secret_agent);
		}
	}

	if (! current_table) {
		return true;
	}

	const char *name;
	bool used_sa_port_arg = false;

	for (uint8_t k = 0; 0 != (name = toml_key_in(current_table, k)); k++) {
		char* config_value = (char*) toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, secret_agent);
			return false;
		}

		bool status = false;
		if (! strcasecmp("sa-address", name)) {
			// if the default was set, it is freed in config_str
			status = config_str(config_value, (void*)&c->addr, NULL);
		}
		else if (! strcasecmp("sa-port", name)) {
			used_sa_port_arg = true;
			// if the default was set, it is freed in config_str
			status = config_str(config_value, (void*)&c->port, NULL);
		}
		else if (! strcasecmp("sa-timeout", name)) {
			status = config_int64(config_value, (void*)&c->timeout, NULL);
		}
		else if (! strcasecmp("sa-cafile", name)) {
			char* tmp = NULL;
			status = config_str(config_value, (void*)&tmp, NULL);
			if (status) {
				c->tls.ca_string = read_file_as_string(tmp);
				cf_free(tmp);

				c->tls.enabled = true;

				if (c->tls.ca_string == NULL) {
					status = false;
					c->tls.enabled = false;
				}
			}
		}
		else {
			fprintf(stderr, "Unknown parameter `%s` in `%s` section\n", name,
					secret_agent);
			return false;
		}

		if (! status) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section\n",
					name, secret_agent);
			return false;
		}
	}

	// if the user supplied the secret_agent address
	// with an attached port, ex 127.0.0.1:3005
	// then parse and use the addr and port only
	// if the user did not also provide an explicit port
	char* sa_addr = NULL;
	char* sa_port = NULL;
	char *sa_addr_p = c->addr;
	bool is_addr_and_port = parse_host(&c->addr, &sa_addr, &sa_port);
	if (is_addr_and_port && !used_sa_port_arg) {
		cf_free(c->port);
		c->addr = safe_strdup(sa_addr);
		c->port = safe_strdup(sa_port);
		cf_free(sa_addr_p);
	}

	return true;
}

static bool
config_restore_cluster(toml_table_t *config_table, restore_config_t *c, const char *instance,
		char errbuf[], sa_client* sc)
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

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
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
			status = config_str(config_value, (void*)&c->tls.keyfile_pw, override);

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
		char errbuf[], sa_client* sc)
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

		const char *config_value = toml_raw_in(current_table, name);
		if (! config_value) {
			snprintf(errbuf, ERR_BUF_SIZE, "Invalid parameter value for `%s` in `%s` section.\n",
					name, cluster);
			return false;
		}

		bool arg_is_secret = false;
		char *override = NULL;
		if (!get_secret_rtoml(sc, config_value, &override, &arg_is_secret)) {
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
			status = config_str(config_value, (void*)&c->tls.keyfile_pw, override);

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
		int level, bool is_backup)
{
	DIR *dp;
	struct dirent *entry;

	if ((dp = opendir(dirname)) == NULL) {
		fprintf(stderr, "Failed to open directory %s\n", dirname);
		return false;
	}

	while ((entry = readdir(dp)) != NULL) {

		if (strcmp(".", entry->d_name) == 0
				|| strcmp("..", entry->d_name) == 0) {
			continue;
		}

		char path[strlen(dirname) + 1 + strlen(entry->d_name)];
		sprintf(path, "%s/%s", dirname, entry->d_name);

		struct stat statbuf;
		lstat(path, &statbuf);

		if (S_ISDIR(statbuf.st_mode)) {
			if (! config_from_dir(c, instance, path, level, is_backup)) {
				// ignore file loading error inside include directory
				fprintf(stderr, "Skipped .....\n");
			}

		} else if (S_ISREG(statbuf.st_mode)) {
			if (! config_from_file(c, instance, path, level, is_backup)) {
				// ignore file loading error inside include directory
				fprintf(stderr, "Skipped .....\n");
			}
		}
	}

	closedir(dp);
	return true;
}

static bool
config_include(toml_table_t *config_table, void *c, const char *instance,
		int level, bool is_backup)
{
	if (level > 3) {
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
			fprintf(stderr, "Invalid parameter value for `%s` in `%s` section.\n",
					name, "include");
			return false;
		}

		bool status;

		if (! strcasecmp("file", name)) {
			char *fname = NULL;
			status = config_str(raw_config_value, (void*)&fname, NULL);

			if (status) {
				if (! config_from_file(c, instance, fname, level + 1, is_backup)) {
					cf_free(fname);
					return false;
				}
				cf_free(fname);
			}

		} else if (! strcasecmp("directory", name)) {
			char *dirname = NULL;
			status = config_str(raw_config_value, (void*)&dirname, NULL);
			if (status) {
				if (! config_from_dir(c, instance, dirname, level + 1, is_backup)) {
					cf_free(dirname);
					return false;
				}
				cf_free(dirname);
			}

		} else {
			fprintf(stderr, "Unknown parameter `%s` in `include` section.\n", name);
			return false;
		}

		if (! status) {
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
		char errbuf[], sa_client* sc)
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
		char errbuf[], sa_client* sc)
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

static bool
password_env(const char *var, char **ptr)
{
	char *pw = getenv(var);

	if (pw == NULL) {
		err("missing TLS key password environment variable %s\n", var);
		return false;
	}

	if (pw[0] == 0) {
		err("empty TLS key password environment variable %s\n", var);
		return false;
	}

	*ptr = strdup(pw);
	return true;
}

static bool
password_file(const char *path, char **ptr)
{
	FILE *fh = fopen(path, "r");

	if (fh == NULL) {
		err("missing TLS key password file %s\n", path);
		return false;
	}

	char pw[5000];
	char *res = fgets(pw, sizeof(pw), fh);

	fclose(fh);

	if (res == NULL) {
		err("error while reading TLS key password file %s\n", path);
		return false;
	}

	int32_t pw_len;

	for (pw_len = 0; pw[pw_len] != 0; pw_len++) {
		if (pw[pw_len] == '\n' || pw[pw_len] == '\r') {
			break;
		}
	}

	if (pw_len == sizeof(pw) - 1) {
		err("TLS key password in file %s too long\n", path);
		return false;
	}

	pw[pw_len] = 0;

	if (pw_len == 0) {
		err("empty TLS key password file %s\n", path);
		return false;
	}

	*ptr = strdup(pw);
	return true;
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
