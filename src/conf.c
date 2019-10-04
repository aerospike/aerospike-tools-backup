/*
 * Copyright 2015-2018 Aerospike, Inc.
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
char *DEFAULTPASSWORD = "SomeDefaultRandomPassword";

//=========================================================
// Forward Declarations.
//

static bool config_str(toml_table_t *curtab, const char *name, void *ptr);
static bool config_int(toml_table_t *curtab, const char *name, void *ptr);
static bool config_bool(toml_table_t *curtab, const char *name, void *ptr);
static bool config_parse_file(const char *fname, toml_table_t **tab, char errbuf[]);


static bool config_backup_cluster(toml_table_t *conftab, backup_config *c, const char *instance, char errbuf[]);
static bool config_backup(toml_table_t *conftab, backup_config *c, const char *instance, char errbuf[]);

static bool config_restore_cluster(toml_table_t *conftab, restore_config *c, const char *instance, char errbuf[]);
static bool config_restore(toml_table_t *conftab, restore_config *c, const char *instance, char errbuf[]);

static bool config_include(toml_table_t *conftab, void *c, const char *instance, int level, bool is_backup);
static bool config_from_dir(void *c, const char *instance, char *dirname, int level, bool is_backup);

static bool password_env(const char *var, char **ptr);
static bool password_file(const char *path, char **ptr);

//=========================================================
// Public API.
//

bool
config_from_file(void *c, const char *instance, const char *fname,
		int level, bool is_backup)
{
	bool status = true;
	//fprintf(stderr, "Load file %d:%s\n", level, fname);
	toml_table_t *conftab = NULL;

	char errbuf[ERR_BUF_SIZE] = {""};
	if (! config_parse_file((char*)fname, &conftab, errbuf)) {
		status = false;
	}
	else if (! conftab) {
		status = true;
	}
	else if (is_backup) {

		if (! config_backup_cluster(conftab, (backup_config*) c, instance, errbuf)) {
			status = false;
		} else if (! config_backup(conftab, (backup_config*)c, instance, errbuf)) {
			status = false;
		} else if (! config_include(conftab, c, instance, level, is_backup)) {
			status = false;
		}
	} else {
		if (! config_restore_cluster(conftab, (restore_config*)c, instance, errbuf)) {
			status = false;
		} else if (! config_restore(conftab, (restore_config*)c, instance, errbuf)) {
			status = false;
		} else if (! config_include(conftab, c, instance, level, is_backup)) {
			status = false;
		}
	}

	toml_free(conftab);

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

	*ptr = value;
	return true;
}


//=========================================================
// Local API.
//

static bool
config_str(toml_table_t *curtab, const char *name, void *ptr)
{
	const char *value = toml_raw_in(curtab, name);
	if (! value) {
		return false;
	}

	char *sval;
	if (0 == toml_rtos(value, &sval)) {
		*((char**)ptr) = sval;
		return true;
	}
	return false;
}

static bool
config_int(toml_table_t *curtab, const char *name, void *ptr)
{
	const char *value = toml_raw_in(curtab, name);
	if (! value) {
		return false;
	}

	int64_t ival;
	if (0 == toml_rtoi(value, &ival)) {
		*((int*)ptr) = (int)ival;
		return true;
	}
	return false;
}

static bool
config_bool(toml_table_t *curtab, const char *name, void *ptr)
{
	const char *value = toml_raw_in(curtab, name);
	if (! value) {
		return false;
	}

	int bval;
	if (0 == toml_rtob(value, &bval)) {
		*((bool*)ptr) = bval ? true : false;
		return true;
	}
	return false;
}

static bool
config_restore_cluster(toml_table_t *conftab, restore_config *c, const char *instance,
		char errbuf[])
{
	// Defaults to "cluster" section in case present.
	toml_table_t *curtab = toml_table_in(conftab, "cluster");

	char cluster[256] = {"cluster"};
	if (instance) {
		snprintf(cluster, 255, "cluster_%s", instance);
		// No override for cluster section.
		curtab = toml_table_in(conftab, cluster);
	}

	if (! curtab) {
		return true;
	}

	const char *name;

	for (uint8_t k = 0; 0 != (name = toml_key_in(curtab, k)); k++) {

		bool status;

		if (! strcasecmp("host", name)) {
			status = config_str(curtab, name, (void*)&c->host);

		} else if (! strcasecmp("services-alternate",  name)) {
			status = config_bool(curtab, name,
					(void*)&c->use_services_alternate);

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int(curtab, name, (void*)&c->port);

		} else if (! strcasecmp("user", name)) {
			status = config_str(curtab, name, (void*)&c->user);

		} else if (! strcasecmp("password", name)) {
			status = config_str(curtab, name, (void*)&c->password);
		
		} else if (! strcasecmp("auth", name)) {
			status = config_str(curtab, name, &c->auth_mode);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.enable);

		} else if (! strcasecmp("tls-protocols", name)) {
			status = config_str(curtab, name, (void*)&c->tls.protocols);

		} else if (! strcasecmp("tls-cipher-suite", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cipher_suite);

		} else if (! strcasecmp("tls-crl-check", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.crl_check);

		} else if (! strcasecmp("tls-crl-check-all", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.crl_check_all);

		} else if (! strcasecmp("tls-keyfile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.keyfile);

		} else if (! strcasecmp("tls-keyfile-password", name)) {
			status = config_str(curtab, name, (void*)&c->tls.keyfile_pw);

		} else if (! strcasecmp("tls-cafile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cafile);

		} else if (! strcasecmp("tls-capath", name)) {
			status = config_str(curtab, name, (void*)&c->tls.capath);

		} else if (! strcasecmp("tls-certfile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.certfile);

		} else if (! strcasecmp("tls-cert-blacklist", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cert_blacklist);

		} else {
			snprintf(errbuf, ERR_BUF_SIZE, "Unknown parameter `%s` in `%s` section.\n", name,
					cluster);
			return false;
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
config_backup_cluster(toml_table_t *conftab, backup_config *c, const char *instance,
		char errbuf[])
{
	// Defaults to "cluster" section in case present.
	toml_table_t *curtab = toml_table_in(conftab, "cluster");

	char cluster[256] = {"cluster"};
	if (instance) {
		snprintf(cluster, 255, "cluster_%s", instance);
		// No override for cluster section.
		curtab = toml_table_in(conftab, cluster);
	}

	if (! curtab) {
		return true;
	}

	const char *name;

	for (uint8_t i = 0; 0 != (name = toml_key_in(curtab, i)); i++) {

		bool status;

		if (! strcasecmp("host", name)) {
			status = config_str(curtab, name, (void*)&c->host);
		
		} else if (! strcasecmp("services-alternate",  name)) {
			status = config_bool(curtab, name,
					(void*)&c->use_services_alternate);

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int(curtab, name, (void*)&c->port);

		} else if (! strcasecmp("user", name)) {
			status = config_str(curtab, name, (void*)&c->user);

		} else if (! strcasecmp("password", name)) {
			status = config_str(curtab, name, (void*)&c->password);
		
		} else if (! strcasecmp("auth", name)) {
			status = config_str(curtab, name, &c->auth_mode);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.enable);

		} else if (! strcasecmp("tls-protocols", name)) {
			status = config_str(curtab, name, (void*)&c->tls.protocols);

		} else if (! strcasecmp("tls-cipher-suite", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cipher_suite);

		} else if (! strcasecmp("tls-crl-check", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.crl_check);

		} else if (! strcasecmp("tls-crl-check-all", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.crl_check_all);

		} else if (! strcasecmp("tls-keyfile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.keyfile);

		} else if (! strcasecmp("tls-keyfile-password", name)) {
			status = config_str(curtab, name, (void*)&c->tls.keyfile_pw);

		} else if (! strcasecmp("tls-cafile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cafile);

		} else if (! strcasecmp("tls-capath", name)) {
			status = config_str(curtab, name, (void*)&c->tls.capath);

		} else if (! strcasecmp("tls-certfile", name)) {
			status = config_str(curtab, name, (void*)&c->tls.certfile);

		} else if (! strcasecmp("tls-cert-blacklist", name)) {
			status = config_str(curtab, name, (void*)&c->tls.cert_blacklist);

		} else {
			snprintf(errbuf, ERR_BUF_SIZE, "Unknown parameter `%s` in `%s` section.\n", name,
					cluster);
			return false;
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
config_include(toml_table_t *conftab, void *c, const char *instance,
		int level, bool is_backup)
{
	if (level > 3) {
		fprintf(stderr, "include max recursion level %d", level);
		return false;
	}

	// Get include section
	toml_table_t *curtab = toml_table_in(conftab, "include");
	if (! curtab) {
		return true;
	}

	const char *name;
	for (uint8_t i = 0; 0 != (name = toml_key_in(curtab, i)); i++) {

		bool status;

		if (! strcasecmp("file", name)) {
			char *fname;
			status = config_str(curtab, name, (void*)&fname);

			if (status) {
				if (! config_from_file(c, instance, fname, level + 1, is_backup)) {
					free(fname);
					return false;
				}
				free(fname);
			}

		} else if (! strcasecmp("directory", name)) {
			char *dirname;
			status = config_str(curtab, name, (void*)&dirname);
			if (status) {
				if (! config_from_dir(c, instance, dirname, level + 1, is_backup)) {
					free(dirname);
					return false;
				}
				free(dirname);
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

	if (! *tab) {
		return false;
	}

	return true;
}


static bool
config_backup(toml_table_t *conftab, backup_config *c, const char *instance,
		char errbuf[])
{
	// Defaults to "asbackup" section in case present.
	toml_table_t *curtab = toml_table_in(conftab, "asbackup");

	char asbackup[256] = {"asbackup"};
	if (instance) {
		snprintf(asbackup, 255, "asbackup_%s", instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(conftab, asbackup)) {
			curtab = toml_table_in(conftab, asbackup);
		}
	}

	if (! curtab) {
		return true;
	}

	const char *name;
	const char *value;

	char *s;
	int64_t i_val;

	for (uint8_t k = 0; 0 != (name = toml_key_in(curtab, k)); k++) {

		value = toml_raw_in(curtab, name);
		if (!value) {
			continue;
		}
		bool status;

		if (! strcasecmp("namespace", name)) {
			status = config_str(curtab, name, (void*)&s);
			if (status) {
				as_strncpy(c->scan->ns, s, AS_NAMESPACE_MAX_SIZE);
				free(s);
			}

		} else if (! strcasecmp("set", name)) {

			status = config_str(curtab, name, (void*)&s);
			if (status) {
				as_strncpy(c->scan->set, s, AS_SET_MAX_SIZE);
				free(s);
			}

		} else if (! strcasecmp("directory", name)) {
			status = config_str(curtab, name, (void*)&c->directory);

		} else if (! strcasecmp("output-file", name)) {
			status = config_str(curtab, name, (void*)&c->output_file);

		} else if (! strcasecmp("file-limit", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->file_limit = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("priority", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val > 0 && i_val <= 3) {
				c->scan->priority = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("records-per-second", name)) {

			status = config_int(curtab, name, (void*)&c->policy->records_per_second);

		}else if (! strcasecmp("no-cluster-change", name)) {
			status = config_bool(curtab, name,
					(void*)&c->policy->fail_on_cluster_change);

		} else if (! strcasecmp("no-bins", name)) {
			status = config_bool(curtab, name, (void*)&c->scan->no_bins);

		} else if (! strcasecmp("compact", name)) {
			status = config_bool(curtab, name, (void*)&c->compact);

		} else if (! strcasecmp("bin_list", name)) {
			status = config_str(curtab, name, (void*)&c->bin_list);

		} else if (! strcasecmp("parallel", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val >= 1 && i_val <= MAX_PARALLEL) {
				c->parallel = (int32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("node-list", name)) {
			status = config_str(curtab, name, (void*)&c->node_list);

		} else if (! strcasecmp("percent", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val >= 1 && i_val <= 100) {
				c->scan->percent = (uint8_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(curtab, name, (void*)&c->machine);

		} else if (! strcasecmp("estimate", name)) {
			status = config_bool(curtab, name, (void*)&c->estimate);

		} else if (! strcasecmp("bandwidth", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->bandwidth = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("no-records", name)) {
			status = config_bool(curtab, name, (void*)&c->no_records);

		} else if (! strcasecmp("no-indexes", name)) {
			status = config_bool(curtab, name, (void*)&c->no_indexes);

		} else if (! strcasecmp("no-udfs", name)) {
			status = config_bool(curtab, name, (void*)&c->no_udfs);

		} else {
			fprintf(stderr, "Unknown parameter `%s` in `%s` section\n", name,
					asbackup);
			return false;
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
config_restore(toml_table_t *conftab, restore_config *c, const char *instance,
		char errbuf[])
{
	// Defaults to "asrestore" section in case present.
	toml_table_t *curtab = toml_table_in(conftab, "asrestore");

	char asrestore[256] = {"asrestore"};
	if (instance) {
		snprintf(asrestore, 255, "asrestore_%s", instance);
		// override if it exists otherwise use
		// default section
		if (toml_table_in(conftab, asrestore)) {
			curtab = toml_table_in(conftab, asrestore);
		}
	}

	if (! curtab) {
		return true;
	}

	const char *name;
	const char *value;

	int64_t i_val = 0;

	for (uint8_t k = 0; 0 != (name = toml_key_in(curtab, k)); k++) {

		value = toml_raw_in(curtab, name);
		if (!value) {
			continue;
		}
		bool status;

		if (! strcasecmp("namespace", name)) {
			// TODO limit check of namespace size
			status = config_str(curtab, name, (void*)&c->ns_list);

		} else if (! strcasecmp("directory", name)) {
			status = config_str(curtab, name, (void*)&c->directory);

		} else if (! strcasecmp("input-file", name)) {
			status = config_str(curtab, name, (void*)&c->input_file);

		} else if (! strcasecmp("threads", name)) {

			status = config_int(curtab, name, (void*)&i_val);
			if (i_val >= 1 && i_val <= MAX_THREADS) {
				c->threads = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(curtab, name, (void*)&c->machine);

		} else if (! strcasecmp("bin-list", name)) {
			status = config_str(curtab, name, (void*)&c->bin_list);

		} else if (! strcasecmp("set-list", name)) {
			status = config_str(curtab, name, (void*)&c->set_list);

		} else if (! strcasecmp("unique", name)) {
			status = config_bool(curtab, name, (void*)&c->unique);

		} else if (! strcasecmp("ignore-record-error", name)) {
			status = config_bool(curtab, name, (void*)&c->ignore_rec_error);

		} else if (! strcasecmp("replace", name)) {
			status = config_bool(curtab, name, (void*)&c->replace);

		} else if (! strcasecmp("no-generation", name)) {
			status = config_bool(curtab, name, (void*)&c->no_generation);

		} else if (! strcasecmp("nice-list", name)) {
			status = config_str(curtab, name, (void*)&c->nice_list);

		} else if (! strcasecmp("no-records", name)) {
			status = config_bool(curtab, name, (void*)&c->no_records);

		} else if (! strcasecmp("no-indexes", name)) {
			status = config_bool(curtab, name, (void*)&c->no_indexes);

		} else if (! strcasecmp("indexes-last", name)) {
			status = config_bool(curtab, name, (void*)&c->indexes_last);

		} else if (! strcasecmp("no-udfs", name)) {
			status = config_bool(curtab, name, (void*)&c->no_udfs);

		} else if (! strcasecmp("wait", name)) {
			status = config_bool(curtab, name, (void*)&c->wait);

		} else if (! strcasecmp("timeout", name)) {
			status = config_int(curtab, name, (void*)&i_val);
			if (i_val >= 0) {
				c->timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else {
			fprintf(stderr, "Unknown parameter `%s` in `%s` section\n", name,
					asrestore);
			return false;
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
