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
static bool config_int32(toml_table_t *curtab, const char *name, int32_t *ptr);
static bool config_int64(toml_table_t *curtab, const char *name, int64_t *ptr);
static bool config_bool(toml_table_t *curtab, const char *name, void *ptr);
static bool config_parse_file(const char *fname, toml_table_t **tab, char errbuf[]);

static bool config_backup_cluster(toml_table_t *conftab, backup_config_t *c, const char *instance, char errbuf[]);
static bool config_backup(toml_table_t *conftab, backup_config_t *c, const char *instance, char errbuf[]);

static bool config_restore_cluster(toml_table_t *conftab, restore_config_t *c, const char *instance, char errbuf[]);
static bool config_restore(toml_table_t *conftab, restore_config_t *c, const char *instance, char errbuf[]);

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

		if (! config_backup_cluster(conftab, (backup_config_t*) c, instance, errbuf)) {
			status = false;
		} else if (! config_backup(conftab, (backup_config_t*)c, instance, errbuf)) {
			status = false;
		} else if (! config_include(conftab, c, instance, level, is_backup)) {
			status = false;
		}
	} else {
		if (! config_restore_cluster(conftab, (restore_config_t*)c, instance, errbuf)) {
			status = false;
		} else if (! config_restore(conftab, (restore_config_t*)c, instance, errbuf)) {
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

	*ptr = safe_strdup(value);
	return true;
}


//=========================================================
// Local helpers.
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
		if (*((char**) ptr) != NULL) {
			cf_free(*((char**) ptr));
		}
		*((char**) ptr) = sval;
		return true;
	}
	return false;
}

static bool
config_int32(toml_table_t *curtab, const char *name, int32_t *ptr)
{
	const char *value = toml_raw_in(curtab, name);
	if (! value) {
		return false;
	}

	int64_t ival;
	if (0 == toml_rtoi(value, &ival)) {
		*ptr = (int32_t)ival;
		return true;
	}
	return false;
}

static bool
config_int64(toml_table_t *curtab, const char *name, int64_t *ptr)
{
	const char *value = toml_raw_in(curtab, name);
	if (! value) {
		return false;
	}

	int64_t ival;
	if (0 == toml_rtoi(value, &ival)) {
		*ptr = ival;
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
config_restore_cluster(toml_table_t *conftab, restore_config_t *c, const char *instance,
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

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int32(curtab, name, (void*)&c->port);

		} else if (! strcasecmp("use-services-alternate",  name)) {
			status = config_bool(curtab, name,
					(void*)&c->use_services_alternate);

		} else if (! strcasecmp("user", name)) {
			status = config_str(curtab, name, (void*)&c->user);

		} else if (! strcasecmp("password", name)) {
			status = config_str(curtab, name, (void*)&c->password);
		
		} else if (! strcasecmp("auth", name)) {
			status = config_str(curtab, name, &c->auth_mode);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.enable);

		} else if (! strcasecmp("tls-name", name)) {
			status = config_str(curtab, name, (void*)&c->tls_name);

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
			fprintf(stderr, "Warning: --tls-cert-blacklist is deprecated and will be removed in the next release. Use a crl instead\n");

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
config_backup_cluster(toml_table_t *conftab, backup_config_t *c, const char *instance,
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

		} else if (! strcasecmp("port", name)) {
			// TODO make limits check for int for all int
			status = config_int32(curtab, name, (void*)&c->port);
		
		} else if (! strcasecmp("use-services-alternate",  name)) {
			status = config_bool(curtab, name,
					(void*)&c->use_services_alternate);

		} else if (! strcasecmp("user", name)) {
			status = config_str(curtab, name, (void*)&c->user);

		} else if (! strcasecmp("password", name)) {
			status = config_str(curtab, name, (void*)&c->password);
		
		} else if (! strcasecmp("auth", name)) {
			status = config_str(curtab, name, &c->auth_mode);

		} else if (! strcasecmp("tls-enable", name)) {
			status = config_bool(curtab, name, (void*)&c->tls.enable);

		} else if (! strcasecmp("tls-name", name)) {
			status = config_str(curtab, name, (void*)&c->tls_name);

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
			fprintf(stderr, "Warning: --tls-cert-blacklist is deprecated and will be removed in the next release. Use a crl instead\n");

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
			char *fname = NULL;
			status = config_str(curtab, name, (void*)&fname);

			if (status) {
				if (! config_from_file(c, instance, fname, level + 1, is_backup)) {
					cf_free(fname);
					return false;
				}
				cf_free(fname);
			}

		} else if (! strcasecmp("directory", name)) {
			char *dirname = NULL;
			status = config_str(curtab, name, (void*)&dirname);
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
config_backup(toml_table_t *conftab, backup_config_t *c, const char *instance,
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
			s = NULL;
			status = config_str(curtab, name, (void*)&s);
			if (status) {
				as_strncpy(c->ns, s, AS_NAMESPACE_MAX_SIZE);
				cf_free(s);
			}

		} else if (! strcasecmp("set", name)) {
			s = NULL;
			status = config_str(curtab, name, (void*)&s);
			if (status) {
				status = parse_set_list(&c->set_list, s);
				cf_free(s);
			}

		} else if (! strcasecmp("continue", name)) {
			status = config_str(curtab, name, (void*)&c->state_file);

		} else if (! strcasecmp("state-file-dst", name)) {
			status = config_str(curtab, name, (void*)&c->state_file_dst);

		} else if (! strcasecmp("remove-files", name)) {
			status = config_bool(curtab, name, (void*)&c->remove_files);

		} else if (! strcasecmp("remove-artifacts", name)) {
			status = config_bool(curtab, name, (void*)&c->remove_artifacts);

		} else if (! strcasecmp("directory", name)) {
			status = config_str(curtab, name, (void*)&c->directory);
		
		} else if (! strcasecmp("output-file-prefix", name)) {
			status = config_str(curtab, name, &c->prefix);

		} else if (! strcasecmp("no-ttl-only", name)) {
			status = config_bool(curtab, name, &c->ttl_zero);

		} else if (! strcasecmp("max-records", name)) {
			status = config_int64(curtab, name, (int64_t*) &c->max_records);

		} else if (! strcasecmp("output-file", name)) {
			status = config_str(curtab, name, (void*)&c->output_file);

		} else if (! strcasecmp("file-limit", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->file_limit = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("records-per-second", name)) {
			status = config_int32(curtab, name, (int32_t*)&c->records_per_second);

		} else if (! strcasecmp("no-bins", name)) {
			status = config_bool(curtab, name, (void*)&c->no_bins);

		} else if (! strcasecmp("compact", name)) {
			status = config_bool(curtab, name, (void*)&c->compact);

		} else if (! strcasecmp("parallel", name)) {

			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->parallel = (int32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("compress", name)) {
			char* compress_type = NULL;
			status = config_str(curtab, name, (void*) &compress_type);
			if (status) {
				status = parse_compression_type(compress_type, &c->compress_mode) == 0;
				cf_free(compress_type);
			}

		} else if (! strcasecmp("compression-level", name)) {
			status = config_int32(curtab, name, (void*)&c->compression_level);

		} else if (! strcasecmp("encrypt", name)) {
			char* encrypt_type = NULL;
			status = config_str(curtab, name, (void*) &encrypt_type);
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
			else {
				char* key_file = NULL;
				status = config_str(curtab, name, (void*) &key_file);
				if (status) {
					c->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
					status = io_proxy_read_private_key_file(key_file, c->pkey) == 0;
					cf_free(key_file);
				}
			}

		} else if (! strcasecmp("encryption-key-env", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}
			else {
				char* env_var = NULL;
				status = config_str(curtab, name, (void*) &env_var);
				if (status) {
					c->pkey = parse_encryption_key_env(env_var);
					status = c->pkey != NULL;
					cf_free(env_var);
				}
			}

		} else if (! strcasecmp("bin-list", name)) {
			status = config_str(curtab, name, (void*)&c->bin_list);

		} else if (! strcasecmp("node-list", name)) {
			status = config_str(curtab, name, (void*)&c->node_list);

		} else if (! strcasecmp("partition-list", name)) {
			status = config_str(curtab, name, (void*)&c->partition_list);

		} else if (! strcasecmp("after-digest", name)) {
			status = config_str(curtab, name, (void*)&c->after_digest);

		} else if (! strcasecmp("filter-exp", name)) {
			status = config_str(curtab, name, (void*)&c->filter_exp);

		} else if (! strcasecmp("modified-after", name)) {
			char* mod_after_time = NULL;
			status = config_str(curtab, name, (void*) &mod_after_time);
			if (status) {
				status = parse_date_time(mod_after_time, &c->mod_after);
				cf_free(mod_after_time);
			}

		} else if (! strcasecmp("modified-before", name)) {
			char* mod_before_time = NULL;
			status = config_str(curtab, name, (void*) &mod_before_time);
			if (status) {
				status = parse_date_time(mod_before_time, &c->mod_before);
				cf_free(mod_before_time);
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(curtab, name, (void*)&c->machine);

		} else if (! strcasecmp("estimate", name)) {
			status = config_bool(curtab, name, (void*)&c->estimate);

		} else if (! strcasecmp("estimate-samples", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->n_estimate_samples = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("verbose", name)) {
			status = config_bool(curtab, name, (void*)&g_verbose);

		} else if (! strcasecmp("nice", name)) {

			status = config_int64(curtab, name, (void*)&i_val);
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

		} else if (! strcasecmp("socket-timeout", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->socket_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("total-timeout", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->total_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("max-retries", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->max_retries = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("retry-delay", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->retry_delay = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-region", name)) {
			status = config_str(curtab, name, (void*)&c->s3_region);

		} else if (! strcasecmp("s3-bucket", name)) {
			status = config_str(curtab, name, (void*)&c->s3_bucket);

		} else if (! strcasecmp("s3-profile", name)) {
			status = config_str(curtab, name, (void*)&c->s3_profile);

		} else if (! strcasecmp("s3-endpoint-override", name)) {
			status = config_str(curtab, name, (void*)&c->s3_endpoint_override);

		} else if (! strcasecmp("s3-min-part-size", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->s3_min_part_size = (uint64_t) i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-max-async-downloads", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_downloads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-max-async-uploads", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_uploads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-log-level", name)) {
			s = NULL;
			status = config_str(curtab, name, (void*)&s);
			if (status && !s3_parse_log_level(s, &c->s3_log_level)) {
				err("Invalid S3 log level \"%s\"", s);
				status = false;
			}

		} else if (! strcasecmp("s3-use-virtual-addresses", name)) {
			status = config_bool(curtab, name,
					(void*)&c->s3_use_virtual_addresses);

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
config_restore(toml_table_t *conftab, restore_config_t *c, const char *instance,
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
	char* s;

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

		} else if (! strcasecmp("directory-list", name)) {
			status = config_str(curtab, name, (void*)&c->directory_list);

		} else if (! strcasecmp("parent-directory", name)) {
			status = config_str(curtab, name, (void*)&c->parent_directory);

		} else if (! strcasecmp("input-file", name)) {
			status = config_str(curtab, name, (void*)&c->input_file);

		} else if (! strcasecmp("compress", name)) {
			char* compress_type = NULL;
			status = config_str(curtab, name, (void*) &compress_type);
			if (status) {
				status = parse_compression_type(compress_type, &c->compress_mode) == 0;
				cf_free(compress_type);
			}

		} else if (! strcasecmp("encrypt", name)) {
			char* encrypt_type = NULL;
			status = config_str(curtab, name, (void*) &encrypt_type);
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
			else {
				char* key_file = NULL;
				status = config_str(curtab, name, (void*) &key_file);
				if (status) {
					c->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
					status = io_proxy_read_private_key_file(key_file, c->pkey) == 0;
					cf_free(key_file);
				}
			}

		} else if (! strcasecmp("encryption-key-env", name)) {
			if (c->pkey != NULL) {
				fprintf(stderr, "Cannot specify both encryption-key-file and "
						"encryption-key-env\n");
				return false;
			}
			else {
				char* env_var = NULL;
				status = config_str(curtab, name, (void*) &env_var);
				if (status) {
					c->pkey = parse_encryption_key_env(env_var);
					status = c->pkey != NULL;
					cf_free(env_var);
				}
			}

		} else if (! strcasecmp("parallel", name) || ! strcasecmp("threads", name)) {

			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val >= 1 && i_val <= MAX_THREADS) {
				c->parallel = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("machine", name)) {
			status = config_str(curtab, name, (void*)&c->machine);

		} else if (! strcasecmp("verbose", name)) {
			status = config_bool(curtab, name, (void*)&g_verbose);

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

		} else if (! strcasecmp("extra-ttl", name)) {
			status = config_int32(curtab, name, (void*)&c->extra_ttl);

		} else if (! strcasecmp("bandwidth", name)) {

			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0) {
				c->bandwidth = (uint64_t)i_val * 1024 * 1024;
			} else {
				status = false;
			}

		} else if (! strcasecmp("tps", name)) {
			status = config_int32(curtab, name, (void*)&c->tps);

		} else if (! strcasecmp("nice", name)) {
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
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val >= 0) {
				c->timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("socket-timeout", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if (i_val >= 0) {
				c->socket_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("total-timeout", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->total_timeout = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("max-retries", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->max_retries = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("retry-delay", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->retry_delay = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("retry-scale-factor", name)) {
			status = config_int32(curtab, name, (int32_t*)&i_val);
			if ((int32_t) i_val >= 0) {
				c->retry_scale_factor = (uint32_t)i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("disable-batch-writes", name)) {
			status = config_bool(curtab, name, (void*)&c->disable_batch_writes);

		} else if (! strcasecmp("s3-region", name)) {
			status = config_str(curtab, name, (void*)&c->s3_region);

		} else if (! strcasecmp("s3-bucket", name)) {
			status = config_str(curtab, name, (void*)&c->s3_bucket);

		} else if (! strcasecmp("s3-profile", name)) {
			status = config_str(curtab, name, (void*)&c->s3_profile);

		} else if (! strcasecmp("s3-endpoint-override", name)) {
			status = config_str(curtab, name, (void*)&c->s3_endpoint_override);

		} else if (! strcasecmp("s3-max-async-downloads", name)) {
			status = config_int64(curtab, name, (void*)&i_val);
			if (i_val > 0 && i_val <= UINT_MAX) {
				c->s3_max_async_downloads = (uint32_t) i_val;
			} else {
				status = false;
			}

		} else if (! strcasecmp("s3-log-level", name)) {
			s = NULL;
			status = config_str(curtab, name, (void*)&s);
			if (status && !s3_parse_log_level(s, &c->s3_log_level)) {
				err("Invalid S3 log level \"%s\"", s);
				status = false;
			}

		} else if (! strcasecmp("s3-use-virtual-addresses", name)) {
			status = config_bool(curtab, name,
					(void*)&c->s3_use_virtual_addresses);

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
