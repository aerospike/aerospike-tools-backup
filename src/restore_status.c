/*
 * Copyright 2022 Aerospike, Inc.
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

#include <restore_status.h>

#include <conf.h>
#include <encode.h>
#include <dec_text.h>


//==========================================================
// Forward Declarations.
//

static void add_default_tls_host(as_config *as_conf, const char* tls_name);


//==========================================================
// Public API.
//

bool
restore_status_init(restore_status_t* status, const restore_config_t* conf)
{
	status->decoder = (backup_decoder_t){ text_parse };

	as_vector_init(&status->file_vec, sizeof(void*), 25);
	as_vector_init(&status->index_vec, sizeof(index_param), 25);
	as_vector_init(&status->udf_vec, sizeof(udf_param), 25);
	as_vector_init(&status->ns_vec, sizeof(void*), 25);
	as_vector_init(&status->bin_vec, sizeof(void*), 25);
	as_vector_init(&status->set_vec, sizeof(void*), 25);

	status->bytes_limit = conf->bandwidth;
	status->records_limit = conf->tps;

	if (pthread_mutex_init(&status->idx_udf_lock, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup1;
	}

	if (conf->ns_list != NULL && !restore_config_parse_list("namespace",
				AS_MAX_NAMESPACE_SIZE, conf->ns_list, &status->ns_vec)) {
		err("Error while parsing namespace list");
		goto cleanup2;
	}

	if (status->ns_vec.size > 2) {
		err("Invalid namespace option");
		goto cleanup2;
	}

	if (conf->bin_list != NULL && !restore_config_parse_list("bin",
				AS_BIN_NAME_MAX_SIZE, conf->bin_list, &status->bin_vec)) {
		err("Error while parsing bin list");
		goto cleanup2;
	}

	if (conf->set_list != NULL && !restore_config_parse_list("set",
				AS_SET_MAX_SIZE, conf->set_list, &status->set_vec)) {
		err("Error while parsing set list");
		goto cleanup2;
	}

	as_config as_conf;
	as_config_init(&as_conf);
	as_conf.conn_timeout_ms = conf->timeout;
	as_conf.use_services_alternate = conf->use_services_alternate;
	tls_config_clone(&as_conf.tls, &conf->tls);

	if (!as_config_add_hosts(&as_conf, conf->host, (uint16_t) conf->port)) {
		err("Invalid host(s) string %s", conf->host);
		goto cleanup3;
	}

	if (conf->tls_name != NULL) {
		add_default_tls_host(&as_conf, conf->tls_name);
	}

	if (conf->auth_mode && !as_auth_mode_from_string(&as_conf.auth_mode, conf->auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / "
				"EXTERNAL / EXTERNAL_INSECURE / PKI\n",
				conf->auth_mode);
		goto cleanup3;
	}

	char* password;
	if (conf->user) {
		if (strcmp(conf->password, DEFAULTPASSWORD) == 0) {
			password = getpass("Enter Password: ");
		}
		else {
			password = conf->password;
		}

		if (!as_config_set_user(&as_conf, conf->user, password)) {
			printf("Invalid password for user name `%s`\n", conf->user);
			goto cleanup3;
		}
	}

	if (conf->tls.keyfile && conf->tls.keyfile_pw) {
		char* keyfile_pw;
		if (strcmp(conf->tls.keyfile_pw, DEFAULTPASSWORD) == 0) {
			keyfile_pw = getpass("Enter TLS-Keyfile Password: ");
		}
		else {
			keyfile_pw = conf->tls.keyfile_pw;
		}

		// we'll be overwriting the old keyfile_pw string
		cf_free(as_conf.tls.keyfile_pw);
		if (!tls_read_password(keyfile_pw, &as_conf.tls.keyfile_pw)) {
			goto cleanup3;
		}
	}

	status->as = cf_malloc(sizeof(aerospike));
	if (status->as == NULL) {
		err("Failed to malloc aerospike struct");
		goto cleanup3;
	}

	aerospike_init(status->as, &as_conf);
	as_error ae;

	ver("Connecting to cluster");

	if (aerospike_connect(status->as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d",
				conf->host, conf->port, ae.code, ae.message, ae.file, ae.line);
		goto cleanup4;
	}

	status->estimated_bytes = 0;
	as_store_uint64(&status->total_bytes, 0);
	as_store_uint64(&status->total_records, 0);
	as_store_uint64(&status->expired_records, 0);
	as_store_uint64(&status->skipped_records, 0);
	as_store_uint64(&status->ignored_records, 0);
	as_store_uint64(&status->inserted_records, 0);
	as_store_uint64(&status->existed_records, 0);
	as_store_uint64(&status->fresher_records, 0);
	as_store_uint64(&status->backoff_count, 0);
	as_store_uint32(&status->index_count, 0);
	as_store_uint32(&status->skipped_indexes, 0);
	as_store_uint32(&status->matched_indexes, 0);
	as_store_uint32(&status->mismatched_indexes, 0);
	as_store_uint32(&status->udf_count, 0);

	return true;

cleanup4:
	aerospike_destroy(status->as);
	cf_free(status->as);

cleanup3:
	tls_config_destroy(&as_conf.tls);

cleanup2:
	pthread_mutex_destroy(&status->idx_udf_lock);

cleanup1:
	as_vector_destroy(&status->file_vec);
	as_vector_destroy(&status->index_vec);
	as_vector_destroy(&status->udf_vec);
	as_vector_destroy(&status->ns_vec);
	as_vector_destroy(&status->bin_vec);
	as_vector_destroy(&status->set_vec);

	return false;
}

void
restore_status_destroy(restore_status_t* status)
{
	as_error ae;
	aerospike_close(status->as, &ae);
	aerospike_destroy(status->as);
	cf_free(status->as);

	pthread_mutex_destroy(&status->idx_udf_lock);

	free_indexes(&status->index_vec);
	free_udfs(&status->udf_vec);

	for (uint32_t i = 0; i < status->file_vec.size; ++i) {
		cf_free(as_vector_get_ptr(&status->file_vec, i));
	}

	as_vector_destroy(&status->file_vec);
	as_vector_destroy(&status->index_vec);
	as_vector_destroy(&status->udf_vec);
	as_vector_destroy(&status->ns_vec);
	as_vector_destroy(&status->bin_vec);
	as_vector_destroy(&status->set_vec);
}


//==========================================================
// Local helpers.
//

/*
 * Sets the tls name of all hosts which don't have a set tls name.
 *
 * @param as_conf   The as_conf with an already parsed list of hosts.
 * @param tls_name  The tls name to set.
 */
static void
add_default_tls_host(as_config *as_conf, const char* tls_name)
{
	as_host* host;
	uint32_t num_hosts = as_conf->hosts->capacity;

	for (uint32_t i = 0; i < num_hosts; i++) {
		host = (as_host*) as_vector_get(as_conf->hosts, i);

		if(host->tls_name == NULL) {
			host->tls_name = strdup(tls_name);
		}
	}
}

