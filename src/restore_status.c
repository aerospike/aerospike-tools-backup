/*
 * Copyright 2023 Aerospike, Inc.
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
#include <sys/resource.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_event.h>

#pragma GCC diagnostic pop

#include <conf.h>
#include <dec_text.h>
#include <encode.h>
#include <file_proxy.h>
#include <utils.h>


//==========================================================
// Forward Declarations.
//

static bool _init_as_config(as_config* as_conf, const restore_config_t* conf,
		const as_config* prior_as_conf);
static void _batch_complete_cb(batch_status_t*, void* restore_status_ptr);
static bool set_resource_limit(const restore_config_t*, uint32_t batch_size,
		bool batch_writes_enabled);
static void add_default_tls_host(as_config *as_conf, const char* tls_name);


//==========================================================
// Public API.
//

bool
restore_status_init(restore_status_t* status, const restore_config_t* conf)
{
	// The aeropsike instance used just to determine server version and
	// supported features.
	aerospike* info_as;
	as_error ae;

	status->decoder = (backup_decoder_t){ text_parse };

	as_vector_init(&status->file_vec, sizeof(void*), 25);
	as_vector_init(&status->index_vec, sizeof(index_param), 25);
	as_vector_init(&status->udf_vec, sizeof(udf_param), 25);
	as_vector_init(&status->ns_vec, sizeof(void*), 25);
	as_vector_init(&status->bin_vec, sizeof(void*), 25);
	as_vector_init(&status->set_vec, sizeof(void*), 25);

	status->estimated_bytes = 0;
	status->validate = conf->validate;
	atomic_init(&status->total_bytes, 0);
	atomic_init(&status->total_records, 0);
	atomic_init(&status->expired_records, 0);
	atomic_init(&status->skipped_records, 0);
	atomic_init(&status->ignored_records, 0);
	atomic_init(&status->inserted_records, 0);
	atomic_init(&status->existed_records, 0);
	atomic_init(&status->fresher_records, 0);
	atomic_init(&status->index_count, 0);
	atomic_init(&status->skipped_indexes, 0);
	atomic_init(&status->matched_indexes, 0);
	atomic_init(&status->mismatched_indexes, 0);
	atomic_init(&status->udf_count, 0);
	atomic_init(&status->finished, false);
	atomic_init(&status->stop, false);

	status->bytes_limit = conf->bandwidth;
	status->records_limit = conf->tps;

	if (pthread_mutex_init(&status->idx_udf_lock, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup1;
	}

	if (pthread_mutex_init(&status->stop_lock, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup_mutex1;
	}

	if (pthread_cond_init(&status->stop_cond, NULL) != 0) {
		err("Failed to initialize condition variable");
		goto cleanup_mutex2;
	}

	if (pthread_mutex_init(&status->file_read_mutex, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup_mutex3;
	}

	if (pthread_mutex_init(&status->limit_mutex, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup_mutex4;
	}

	if (pthread_cond_init(&status->limit_cond, NULL) != 0) {
		err("Failed to initialize condition variable");
		goto cleanup_mutex5;
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

	if (conf->validate) {
		status->as = NULL;
		return true;
	}

	as_config info_as_conf;
	if (!_init_as_config(&info_as_conf, conf, NULL)) {
		goto cleanup2;
	}

	info_as = (aerospike*) cf_malloc(sizeof(aerospike));
	aerospike_init(info_as, &info_as_conf);

#if AS_EVENT_LIB_DEFINED
	if (!as_event_create_loops(conf->event_loops)) {
		err("Failed to create %d event loop(s)", conf->event_loops);
		goto cleanup3;
	}
#else
#error "Must define an event library when building"
#endif

	ver("Connecting to cluster");

	if (aerospike_connect(info_as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d",
				conf->host, conf->port, ae.code, ae.message, ae.file, ae.line);
		goto cleanup4;
	}

	if (get_server_version(info_as, &status->version_info) != 0) {
		goto cleanup5;
	}

	ver("Connected to server version %u.%u.%u.%u",
			status->version_info.major,
			status->version_info.minor,
			status->version_info.patch,
			status->version_info.build_id);

	if (conf->disable_batch_writes) {
		status->batch_writes_enabled = false;
	}
	else if (!server_has_batch_writes(info_as, &status->version_info,
				&status->batch_writes_enabled)) {
		goto cleanup5;
	}

	if (conf->batch_size == BATCH_SIZE_UNDEFINED) {
		if (status->batch_writes_enabled) {
			status->batch_size = DEFAULT_BATCH_SIZE;
		}
		else {
			status->batch_size = DEFAULT_KEY_REC_BATCH_SIZE;
		}
	}
	else {
		status->batch_size = conf->batch_size;
	}

	if (!set_resource_limit(conf, status->batch_size, status->batch_writes_enabled)) {
		goto cleanup5;
	}

	if (SERVER_VERSION_BEFORE(&status->version_info, 4, 9)) {
		err("Aerospike Server version 4.9 or greater is required to run "
				"asrestore, but version %" PRIu32 ".%" PRIu32 " is in use.",
				status->version_info.major, status->version_info.minor);
		goto cleanup5;
	}

	as_config as_conf;
	if (!_init_as_config(&as_conf, conf, &info_as_conf)) {
		goto cleanup5;
	}

	if (status->batch_writes_enabled) {
		as_conf.async_max_conns_per_node = conf->max_async_batches;
	}
	else {
		as_conf.async_max_conns_per_node = conf->max_async_batches * status->batch_size;
	}

	aerospike_close(info_as, &ae);
	aerospike_destroy(info_as);

	cf_free(info_as);
	info_as = NULL;

	status->as = cf_malloc(sizeof(aerospike));
	aerospike_init(status->as, &as_conf);

	if (aerospike_connect(status->as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d",
				conf->host, conf->port, ae.code, ae.message, ae.file, ae.line);
		goto cleanup6;
	}

	if (batch_uploader_init(&status->batch_uploader, status->as, conf,
				status->batch_writes_enabled) != 0) {
		goto cleanup7;
	}

	batch_uploader_set_callback(&status->batch_uploader, _batch_complete_cb,
			status);

	return true;

cleanup7:
	aerospike_close(status->as, &ae);

cleanup6:
	aerospike_destroy(status->as);
	cf_free(status->as);

cleanup5:
	if (info_as != NULL) {
		aerospike_close(info_as, &ae);
	}

cleanup4:
	as_event_close_loops();

cleanup3:
	if (info_as != NULL) {
		aerospike_destroy(info_as);
		cf_free(info_as);
	}

cleanup2:
	pthread_cond_destroy(&status->limit_cond);
cleanup_mutex5:
	pthread_mutex_destroy(&status->limit_mutex);
cleanup_mutex4:
	pthread_mutex_destroy(&status->file_read_mutex);
cleanup_mutex3:
	pthread_cond_destroy(&status->stop_cond);
cleanup_mutex2:
	pthread_mutex_destroy(&status->stop_lock);
cleanup_mutex1:
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

	// the client is never created if
	// restore is operating in validate mode
	if (status->as != NULL) {
		aerospike_close(status->as, &ae);
		aerospike_destroy(status->as);
		cf_free(status->as);
	}

	as_event_close_loops();

	if (!status->validate) {
		batch_uploader_free(&status->batch_uploader);
	}

	pthread_mutex_destroy(&status->idx_udf_lock);
	pthread_mutex_destroy(&status->stop_lock);
	pthread_cond_destroy(&status->stop_cond);
	pthread_mutex_destroy(&status->file_read_mutex);
	pthread_mutex_destroy(&status->limit_mutex);
	pthread_cond_destroy(&status->limit_cond);

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

bool
restore_status_has_finished(const restore_status_t* status)
{
	return status->finished;
}

void
restore_status_finish(restore_status_t* status)
{
	// sets the finished variable. No need to grab a lock since condidition
	// variables all used timed waits, so deadlock is impossible.
	status->finished = true;

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&status->stop_cond);

	s3_disable_request_processing();
}

bool
restore_status_has_stopped(const restore_status_t* status)
{
	return status->stop;
}

void
restore_status_stop(restore_status_t* status)
{
	// sets the stop variable. No need to grab a lock since condidition
	// variables all used timed waits, so deadlock is impossible.
	status->stop = true;

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&status->stop_cond);

	s3_disable_request_processing();
}

void
restore_status_sleep_for(restore_status_t* status, uint64_t n_secs,
		bool sleep_through_stop)
{
	struct timespec t;
	get_current_time(&t);
	t.tv_sec += (int64_t) n_secs;

	pthread_mutex_lock(&status->stop_lock);
	while (!restore_status_has_finished(status) &&
			(sleep_through_stop || !restore_status_has_stopped(status)) &&
			timespec_has_not_happened(&t)) {
		pthread_cond_timedwait(&status->stop_cond, &status->stop_lock, &t);
	}
	pthread_mutex_unlock(&status->stop_lock);
}


//==========================================================
// Local helpers.
//

static bool
_init_as_config(as_config* as_conf, const restore_config_t* conf,
		const as_config* prior_as_conf)
{
	as_config_init(as_conf);
	as_conf->conn_timeout_ms = conf->timeout;
	as_conf->use_services_alternate = conf->use_services_alternate;
	tls_config_clone(&as_conf->tls, &conf->tls);

	if (!as_config_add_hosts(as_conf, conf->host, (uint16_t) conf->port)) {
		err("Invalid host(s) string %s", conf->host);
		goto cleanup1;
	}

	if (conf->tls_name != NULL) {
		add_default_tls_host(as_conf, conf->tls_name);
	}

	if (conf->auth_mode && !as_auth_mode_from_string(&as_conf->auth_mode, conf->auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / "
				"EXTERNAL / EXTERNAL_INSECURE / PKI\n",
				conf->auth_mode);
		goto cleanup1;
	}

	char* password;
	if (conf->user) {
		if (strcmp(conf->password, DEFAULT_PASSWORD) == 0) {
			password = getpass("Enter Password: ");
		}
		else {
			password = conf->password;
		}

		if (!as_config_set_user(as_conf, conf->user, password)) {
			printf("Invalid password for user name `%s`\n", conf->user);
			goto cleanup1;
		}
	}

	if (prior_as_conf != NULL) {
		as_conf->tls.keyfile_pw = safe_strdup(prior_as_conf->tls.keyfile_pw);
	}
	else if (conf->tls.keyfile && conf->tls.keyfile_pw) {
		char* keyfile_pw;
		if (strcmp(conf->tls.keyfile_pw, DEFAULT_PASSWORD) == 0) {
			keyfile_pw = getpass("Enter TLS-Keyfile Password: ");
		}
		else {
			keyfile_pw = conf->tls.keyfile_pw;
		}

		// we'll be overwriting the old keyfile_pw string
		cf_free(as_conf->tls.keyfile_pw);
		if (!tls_read_password(keyfile_pw, &as_conf->tls.keyfile_pw)) {
			goto cleanup1;
		}
	}

	return true;

cleanup1:
	tls_config_destroy(&as_conf->tls);

	return false;
}

static void
_batch_complete_cb(batch_status_t* batch_status, void* restore_status_ptr)
{
	restore_status_t* status = (restore_status_t*) restore_status_ptr;

	status->ignored_records += batch_status->ignored_records;
	status->inserted_records += batch_status->inserted_records;
	status->existed_records += batch_status->existed_records;
	status->fresher_records += batch_status->fresher_records;
}

static bool
set_resource_limit(const restore_config_t* conf, uint32_t batch_size, bool batch_writes_enabled)
{
	struct rlimit l;
	rlim_t max_open_files;
	rlim_t max_async_client_sockets;

	if (batch_writes_enabled) {
		max_async_client_sockets = (rlim_t) conf->max_async_batches;
	}
	else {
		max_async_client_sockets = (rlim_t) (conf->max_async_batches * batch_size);
	}

	if (restore_config_from_cloud(conf)) {
		rlim_t max_s3_sockets = (rlim_t) conf->s3_max_async_downloads;
		// add 3 for stdin/stdout/stderr
		max_open_files = max_async_client_sockets + max_s3_sockets + 3;
	}
	else {
		rlim_t max_open_bup_files = (rlim_t) conf->parallel;
		// add 3 for stdin/stdout/stderr
		max_open_files = max_async_client_sockets + max_open_bup_files + 3;
	}

	if (getrlimit(RLIMIT_NOFILE, &l) != 0) {
		err_code("Failed to get file descriptor limit of process");
		return false;
	}

	ver("Process file descriptor limit: %" PRIu64, l.rlim_cur);

	if (l.rlim_cur < max_open_files) {
		l.rlim_cur = max_open_files;
		l.rlim_max = MAX(max_open_files, l.rlim_max);

		if (setrlimit(RLIMIT_NOFILE, &l) != 0) {
			fprintf(stderr, "Failed to set file destriptor limit of process: %s\n", strerror(errno));
			return false;
		}

		ver("Changed file descriptor limit to %" PRIu64, max_open_files);
	}

	return true;
}

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

