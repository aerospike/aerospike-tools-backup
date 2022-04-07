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

#include <backup_status.h>

#include <backup_state.h>
#include <conf.h>


//==========================================================
// Typedefs & constants.
//

//==========================================================
// Forward Declarations.
//

static bool sort_partition_filters(as_vector* partition_ranges);
static bool parse_partition_range(char *str, as_partition_filter *range);
static bool parse_digest(const char *str, as_partition_filter *filter);
static bool parse_partition_list(char *partition_list, as_vector *partition_filters);
static bool parse_after_digest(char *str, as_vector* partition_filters);
static bool parse_node_list(char *node_list, node_spec **node_specs,
		uint32_t *n_node_specs);
static bool parse_sets(const as_vector* set_list, char* set_name,
		exp_component_t* set_list_expr);
static bool calc_node_list_partitions(as_cluster *clust, const as_namespace ns,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names,
		as_vector* partition_filters);
static void add_default_tls_host(as_config *as_conf, const char* tls_name);
static bool check_for_ldt_callback(void *context_, const char *key, const char *value);
static bool check_for_ldt(aerospike *as, const char *namespace,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, bool *has_ldt);
static bool ns_count_callback(void *context_, const char *key, const char *value);
static bool set_count_callback(void *context_, const char *key_, const char *value_);
static bool get_object_count(aerospike *as, const char *namespace, as_vector* set_list,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, uint64_t *obj_count);


//==========================================================
// Public API.
//

bool
backup_status_init(backup_status_t* status, backup_config_t* conf)
{
	status->node_specs = NULL;
	status->n_node_specs = 0;

	status->as = NULL;

	status->policy = (as_policy_scan*) cf_malloc(sizeof(as_policy_scan));
	as_policy_scan_init(status->policy);
	status->policy->base.socket_timeout = conf->socket_timeout;
	status->policy->base.total_timeout = conf->total_timeout;
	status->policy->base.max_retries = conf->max_retries;
	status->policy->base.sleep_between_retries = conf->retry_delay;
	status->policy->max_records = conf->max_records;
	status->policy->records_per_second = conf->records_per_second;

	memset(status->set, 0, sizeof(as_set));

	status->encoder = (backup_encoder_t) {
		text_put_record, text_put_udf_file, text_put_secondary_index
	};

	status->rec_count_estimate = 0;
	status->rec_count_total = 0;
	status->byte_count_total = 0;
	status->file_count = 0;

	status->rec_count_total_committed = 0;
	status->byte_count_total_committed = 0;
	status->byte_count_limit = 0;
	status->index_count = 0;
	status->udf_count = 0;

	as_vector_init(&status->partition_filters, sizeof(as_partition_filter), 1);

	status->started = false;
	status->finished = false;
	status->stop = false;
	status->backup_state = NULL;
	status->one_shot_done = false;

	status->n_estimate_samples = 0;
	if (conf->estimate) {
		status->estimate_samples = (uint64_t*)
			cf_calloc(conf->n_estimate_samples, sizeof(uint64_t));

		if (status->estimate_samples == NULL) {
			err("Failed to calloc %zu bytes for estimate samples",
					conf->n_estimate_samples * sizeof(uint64_t));
			goto cleanup1;
		}
	}
	else {
		status->estimate_samples = NULL;
	}

	if (pthread_mutex_init(&status->stop_lock, NULL) != 0) {
		err("Failed to initialize stop_lock mutex");
		goto cleanup1;
	}

	if (pthread_cond_init(&status->stop_cond, NULL) != 0) {
		err("Failed to initialize stop_cond condition variable");
		goto cleanup_mutex1;
	}

	if (pthread_mutex_init(&status->dir_file_init_mutex, NULL) != 0) {
		err("Failed to initialize dir_file_init_mutex mutex");
		goto cleanup_mutex2;
	}

	if (pthread_mutex_init(&status->file_write_mutex, NULL) != 0) {
		err("Failed to initialize file_write_mutex mutex");
		goto cleanup_mutex3;
	}

	if (pthread_mutex_init(&status->bandwidth_mutex, NULL) != 0) {
		err("Failed to initialize bandwidth_mutex mutex");
		goto cleanup_mutex4;
	}

	if (pthread_cond_init(&status->bandwidth_cond, NULL) != 0) {
		err("Failed to initialize bandwidth_cond condition variable");
		goto cleanup_mutex5;
	}

	if (pthread_mutex_init(&status->committed_count_mutex, NULL) != 0) {
		err("Failed to initialize committed_count_mutex mutex");
		goto cleanup_mutex6;
	}

	char* host = conf->host;
	uint32_t port = (uint32_t) conf->port;

	char* tls_name = conf->tls_name;

	if (conf->partition_list != NULL) {
		ver("Parsing partition-list '%s'", conf->partition_list);

		if (!parse_partition_list(conf->partition_list, &status->partition_filters)) {
			err("Error while parsing partition-list '%s'", conf->partition_list);
			goto cleanup2;
		}
	}
	else if (conf->after_digest != NULL) {
		ver("Parsing after-digest '%s'", conf->after_digest);

		if (!parse_after_digest(conf->after_digest, &status->partition_filters)) {
			err("Error while parsing after-digest '%s'", conf->after_digest);
			goto cleanup2;
		}
	}
	else if (conf->node_list != NULL) {
		ver("Parsing node list %s", conf->node_list);

		if (!parse_node_list(conf->node_list, &status->node_specs,
					&status->n_node_specs)) {
			err("Error while parsing node list");
			goto cleanup2;
		}

		host = status->node_specs[0].addr_string;
		port = ntohs(status->node_specs[0].port);

		if (status->node_specs[0].family == AF_INET6) {
			if (strnlen(host, IP_ADDR_SIZE) > IP_ADDR_SIZE - 3) {
				err("Hostname \"%.*s\" too long (max is %d characters)",
						IP_ADDR_SIZE, host, IP_ADDR_SIZE - 3);
				goto cleanup2;
			}
			snprintf(host, IP_ADDR_SIZE, "[%.*s]", IP_ADDR_SIZE - 3, host);
		}

		if (status->node_specs[0].tls_name_str != NULL &&
				strcmp(status->node_specs[0].tls_name_str, "")) {
			tls_name = status->node_specs[0].tls_name_str;
		}
	}

	if (conf->filter_exp != NULL) {
		uint32_t b64_len = (uint32_t) strlen(conf->filter_exp);
		as_exp* expr = (as_exp*) cf_malloc(sizeof(as_exp) +
				cf_b64_decoded_buf_size(b64_len));

		if (!cf_b64_validate_and_decode(conf->filter_exp, b64_len,
					expr->packed, &expr->packed_sz)) {
			err("Invalide base64 encoded string: %s", conf->filter_exp);
			cf_free(expr);
			goto cleanup2;
		}

		status->policy->base.filter_exp = expr;

		// Still need to parse the set name. We can safely pass NULL as the
		// set_list_expr, since multiset backup is mutually exclusive with
		// filter-exp.
		if (!parse_sets(&conf->set_list, status->set, NULL)) {
			goto cleanup2;
		}
	}
	else {
		// set-list selector expression for multi-set backup.
		exp_component_t set_list_expr;
		// Modified-before/-after selector expressions.
		exp_component_t mod_before_expr;
		exp_component_t mod_after_expr;
		// no-ttl-only selector expression.
		exp_component_t no_ttl_only_expr;

		exp_component_init_nil(&set_list_expr);
		exp_component_init_nil(&mod_before_expr);
		exp_component_init_nil(&mod_after_expr);
		exp_component_init_nil(&no_ttl_only_expr);

		if (!parse_sets(&conf->set_list, status->set, &set_list_expr)) {
			goto cleanup2;
		}

		if (conf->mod_before > 0) {
			exp_component_init(&mod_before_expr,
					as_exp_cmp_lt(as_exp_last_update(), as_exp_int(conf->mod_before)));
			//as_scan_predexp_add(scan, as_predexp_rec_last_update());
			//as_scan_predexp_add(scan, as_predexp_integer_value(conf->mod_before));
			//as_scan_predexp_add(scan, as_predexp_integer_less());
		}

		if (conf->mod_after > 0) {
			exp_component_init(&mod_after_expr,
					as_exp_cmp_ge(as_exp_last_update(), as_exp_int(conf->mod_after)));
			//as_scan_predexp_add(scan, as_predexp_rec_last_update());
			//as_scan_predexp_add(scan, as_predexp_integer_value(conf->mod_after));
			//as_scan_predexp_add(scan, as_predexp_integer_greatereq());
		}

		if (conf->ttl_zero) {
			exp_component_init(&no_ttl_only_expr,
					as_exp_cmp_eq(as_exp_ttl(), as_exp_int(-1)));
			//as_scan_predexp_add(scan, as_predexp_rec_void_time());
			//as_scan_predexp_add(scan, as_predexp_integer_value(0));
			//as_scan_predexp_add(scan, as_predexp_integer_equal());
		}

		as_exp* combined_expr = exp_component_join_and_compile(_AS_EXP_CODE_AND,
				4, (exp_component_t*[]) {
					&set_list_expr,
					&mod_before_expr,
					&mod_after_expr,
					&no_ttl_only_expr
				});

		exp_component_free(&set_list_expr);
		exp_component_free(&mod_before_expr);
		exp_component_free(&mod_after_expr);
		exp_component_free(&no_ttl_only_expr);

		if (combined_expr == EXP_ERR) {
			goto cleanup2;
		}
		else if (combined_expr != NULL) {
			status->policy->base.filter_exp = combined_expr;
		}
	}

	as_config as_conf;
	as_config_init(&as_conf);
	as_conf.conn_timeout_ms = TIMEOUT;
	as_conf.use_services_alternate = conf->use_services_alternate;
	tls_config_clone(&as_conf.tls, &conf->tls);

	if (!as_config_add_hosts(&as_conf, host, (uint16_t) port)) {
		err("Invalid conf->host(s) string %s", host);
		goto cleanup2;
	}

	if (tls_name != NULL) {
		add_default_tls_host(&as_conf, tls_name);
	}

	if (conf->auth_mode && ! as_auth_mode_from_string(&as_conf.auth_mode,
				conf->auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / "
				"EXTERNAL / EXTERNAL_INSECURE / PKI",
				conf->auth_mode);
		goto cleanup2;
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
			err("Invalid password for user name `%s`", conf->user);
			goto cleanup2;
		}
	}

	if (conf->tls.keyfile && conf->tls.keyfile_pw) {
		char* tls_keyfile_pw;
		if (strcmp(conf->tls.keyfile_pw, DEFAULTPASSWORD) == 0) {
			tls_keyfile_pw = getpass("Enter TLS-Keyfile Password: ");
		}
		else {
			tls_keyfile_pw = conf->tls.keyfile_pw;
		}

		// we'll be overwriting the old keyfile_pw string
		cf_free(as_conf.tls.keyfile_pw);
		if (!tls_read_password(tls_keyfile_pw, &as_conf.tls.keyfile_pw)) {
			goto cleanup2;
		}
	}

	status->as = cf_malloc(sizeof(aerospike));
	if (status->as == NULL) {
		err("Failed to malloc aerospike struct");
		goto cleanup2;
	}

	aerospike_init(status->as, &as_conf);
	as_error ae;

	ver("Connecting to cluster");

	if (aerospike_connect(status->as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d", host, port,
				ae.code, ae.message, ae.file, ae.line);
		goto cleanup2;
	}

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names;
	get_node_names(status->as->cluster, status->node_specs, status->n_node_specs,
			&node_names, &n_node_names);

	if (n_node_names < status->n_node_specs) {
		err("Invalid node list. Potentially duplicate nodes or nodes from different clusters.");
		goto cleanup3;
	}

	if (conf->node_list != NULL && conf->state_file == NULL) {
		// calculate partitions from these nodes, unless continuing a failed
		// backup, in which case we use the same partitions from the given nodes
		// that was calculated in the first run
		as_vector_init(&status->partition_filters, sizeof(as_partition_filter), 8);
		if (!calc_node_list_partitions(status->as->cluster, conf->ns, node_names,
					n_node_names, &status->partition_filters)) {
			goto cleanup3;
		}

		if (conf->parallel == 0) {
			conf->parallel = DEFAULT_NODE_BACKUP_PARALLEL;
		}
	}

	inf("Processing %u node(s)", n_node_names);

	if (!get_object_count(status->as, conf->ns, &conf->set_list, node_names,
				n_node_names, &status->rec_count_estimate)) {
		err("Error while counting cluster objects");
		goto cleanup3;
	}

	inf("Namespace contains %" PRIu64 " record(s)", status->rec_count_estimate);

	bool has_ldt;

	if (!check_for_ldt(status->as, conf->ns, node_names, n_node_names, &has_ldt)) {
		err("Error while checking for LDT");
		goto cleanup3;
	}

	if (has_ldt) {
		err("The cluster has LDT enabled for namespace %s; please use an older version of "
				"this tool to create a backup", conf->ns);
		goto cleanup3;
	}

	if (conf->estimate && status->rec_count_estimate > conf->n_estimate_samples) {
		status->rec_count_estimate = conf->n_estimate_samples;
	}
	if (conf->max_records > 0 && status->rec_count_estimate > conf->max_records) {
		status->rec_count_estimate = conf->max_records;
	}

	if (node_names != NULL) {
		cf_free(node_names);
	}

	return true;

cleanup3:
	if (node_names != NULL) {
		cf_free(node_names);
	}

cleanup2:
	if (status->as != NULL) {
		aerospike_destroy(status->as);
		cf_free(status->as);
	}

	pthread_mutex_destroy(&status->committed_count_mutex);
cleanup_mutex6:
	pthread_cond_destroy(&status->bandwidth_cond);
cleanup_mutex5:
	pthread_mutex_destroy(&status->bandwidth_mutex);
cleanup_mutex4:
	pthread_mutex_destroy(&status->file_write_mutex);
cleanup_mutex3:
	pthread_mutex_destroy(&status->dir_file_init_mutex);
cleanup_mutex2:
	pthread_cond_destroy(&status->stop_cond);
cleanup_mutex1:
	pthread_mutex_destroy(&status->stop_lock);

cleanup1:
	as_exp_destroy(status->policy->base.filter_exp);
	cf_free(status->node_specs);
	cf_free(status->estimate_samples);

	for (uint32_t i = 0; i < status->partition_filters.size; i++) {
		as_partition_filter* filt = (as_partition_filter*)
			as_vector_get(&status->partition_filters, i);
		if (filt->parts_all != NULL) {
			as_partitions_status_release(filt->parts_all);
		}
	}
	as_vector_destroy(&status->partition_filters);
	return false;
}

void
backup_status_destroy(backup_status_t* status)
{
	as_error ae;
	aerospike_close(status->as, &ae);
	aerospike_destroy(status->as);
	cf_free(status->as);

	as_exp_destroy(status->policy->base.filter_exp);
	cf_free(status->policy);

	cf_free(status->node_specs);

	for (uint32_t i = 0; i < status->partition_filters.size; i++) {
		as_partition_filter* filt = (as_partition_filter*)
			as_vector_get(&status->partition_filters, i);
		if (filt->parts_all != NULL) {
			as_partitions_status_release(filt->parts_all);
		}
	}
	as_vector_destroy(&status->partition_filters);

	pthread_mutex_destroy(&status->stop_lock);
	pthread_cond_destroy(&status->stop_cond);
	pthread_mutex_destroy(&status->dir_file_init_mutex);
	pthread_mutex_destroy(&status->file_write_mutex);
	pthread_mutex_destroy(&status->bandwidth_mutex);
	pthread_cond_destroy(&status->bandwidth_cond);
	pthread_mutex_destroy(&status->committed_count_mutex);

	cf_free(status->estimate_samples);

	if (status->backup_state != NULL && status->backup_state != BACKUP_STATE_ABORTED) {
		backup_state_free(status->backup_state);
		cf_free(status->backup_state);
	}
}

/*
 * Should be called if more than one thread will run backup tasks/if there is
 * more than one backup tasks in total.
 *
 * n_tasks is the total number of backup jobs
 * n_threads is the max number of active threads
 */
void
backup_status_set_n_threads(backup_status_t* status, const backup_config_t* conf,
		uint32_t n_tasks, uint32_t n_threads)
{
	status->policy->max_records = (conf->max_records + n_tasks - 1) / n_tasks;
	status->policy->records_per_second = conf->records_per_second / n_threads;

	// don't allow this to set rps to 0 if n_threads > rps (this would mean no
	// throttling will be done)
	if (status->policy->records_per_second == 0 && conf->records_per_second > 0) {
		status->policy->records_per_second = 1;
	}
}

bool
backup_status_has_started(backup_status_t* status)
{
	return as_load_bool(&status->started);
}

void
backup_status_start(backup_status_t* status)
{
	as_store_bool(&status->started, true);
}

bool
backup_status_one_shot_done(const backup_status_t* status)
{
	return as_load_uint8((uint8_t*) &status->one_shot_done);
}

void
backup_status_wait_one_shot(backup_status_t* status)
{
	if (!backup_status_one_shot_done(status)) {
		safe_lock(&status->stop_lock);

		while (!backup_status_one_shot_done(status) && !backup_status_has_stopped(status)) {
			safe_wait(&status->stop_cond, &status->stop_lock);
		}

		safe_unlock(&status->stop_lock);
	}
}

void
backup_status_signal_one_shot(backup_status_t* status)
{
	safe_lock(&status->stop_lock);
	as_store_uint8((uint8_t*) &status->one_shot_done, 1);
	safe_signal(&status->stop_cond);
	safe_unlock(&status->stop_lock);
}

bool
backup_status_has_stopped(const backup_status_t* status)
{
	return as_load_uint8((uint8_t*) &status->stop);
}

void
backup_status_stop(const backup_config_t* conf, backup_status_t* status)
{
	if (backup_status_has_started(status) && backup_config_can_resume(conf)) {
		// try initializing the backup file, which may have already been done
		backup_status_init_backup_state_file(conf->state_file_dst, status);
	}
	else {
		as_store_ptr(&status->backup_state, BACKUP_STATE_ABORTED);
	}

	// sets the stop variable
	as_store_uint8((uint8_t*) &status->stop, 1);

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&status->stop_cond);
	pthread_cond_broadcast(&status->bandwidth_cond);
}

bool
backup_status_has_finished(const backup_status_t* status)
{
	return (bool) as_load_uint8((uint8_t*) &status->finished);
}

void
backup_status_finish(backup_status_t* status)
{
	pthread_mutex_lock(&status->stop_lock);

	// sets the stop variable
	as_store_uint8((uint8_t*) &status->finished, 1);

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&status->stop_cond);

	pthread_mutex_unlock(&status->stop_lock);
}

void
backup_status_abort_backup(backup_status_t* status)
{
	pthread_mutex_lock(&status->stop_lock);

	// sets the stop variable
	as_store_uint8((uint8_t*) &status->stop, 1);

	backup_state_t* prev_state =
		(backup_state_t*) as_fas_uint64((uint64_t*) &status->backup_state,
				(uint64_t) BACKUP_STATE_ABORTED);

	if (prev_state != NULL && prev_state != BACKUP_STATE_ABORTED) {
		backup_state_free(prev_state);
		cf_free(prev_state);
	}

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&status->stop_cond);

	pthread_mutex_unlock(&status->stop_lock);
}

void
backup_status_abort_backup_unsafe(backup_status_t* status)
{
	as_store_ptr(&status->backup_state, BACKUP_STATE_ABORTED);
}

/*
 * Sleep on the stop condition, exiting from the sleep early if the program is
 * stopped
 */
void
backup_status_sleep_for(backup_status_t* status, uint64_t n_secs)
{
#ifdef __APPLE__
	// MacOS uses gettimeofday instead of the monotonic clock for timed waits on
	// condition variables
	struct timespec t;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	TIMEVAL_TO_TIMESPEC(&tv, &t);
#else
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
#endif /* __APPLE__ */

	t.tv_sec += (int64_t) n_secs;

	pthread_mutex_lock(&status->stop_lock);
	while (!backup_status_has_stopped(status) && !backup_status_has_finished(status) &&
			timespec_has_not_happened(&t)) {
		pthread_cond_timedwait(&status->stop_cond, &status->stop_lock, &t);
	}
	pthread_mutex_unlock(&status->stop_lock);
}

bool
backup_status_init_backup_state_file(const char* backup_state_path,
		backup_status_t* status)
{
	if (backup_state_path == NULL) {
		// Only will happen if !backup_config_can_resume(), no need to make a
		// backup state.
		return false;
	}

	backup_state_t* cur_backup_state = as_load_ptr(&status->backup_state);
	if (cur_backup_state != NULL) {
		// a backup state alrady exists, or we've aborted the backup, do nothing
		return false;
	}

	backup_state_t* state = (backup_state_t*) cf_malloc(sizeof(backup_state_t));
	if (state == NULL) {
		err("Unable to allocate %zu bytes for backup state struct",
				sizeof(backup_state_t));
		as_cas_uint64((uint64_t*) &status->backup_state, (uint64_t) NULL,
				(uint64_t) BACKUP_STATE_ABORTED);
		return false;
	}

	if (backup_state_init(state, backup_state_path) != 0) {
		cf_free(state);
		as_cas_uint64((uint64_t*) &status->backup_state, (uint64_t) NULL,
				(uint64_t) BACKUP_STATE_ABORTED);
		return false;
	}

	// compare and swap backup_state from NULL to state, so if backup_state
	// was anything but NULL before, it won't be overwritten
	if (!as_cas_uint64((uint64_t*) &status->backup_state, (uint64_t) NULL, (uint64_t) state)) {
		backup_state_free(state);
		cf_free(state);
		return false;
	}

	inf("Created backup state file %s", backup_state_path);

	return true;
}

backup_state_t*
backup_status_get_backup_state(backup_status_t* status)
{
	return (backup_state_t*) as_load_ptr(&status->backup_state);
}

void
backup_status_save_scan_state(backup_status_t* status,
		const as_partitions_status* parts)
{
	pthread_mutex_lock(&status->stop_lock);

	backup_state_t* state = as_load_ptr(&status->backup_state);

	if (state == BACKUP_STATE_ABORTED) {
		pthread_mutex_unlock(&status->stop_lock);
		return;
	}

	for (uint32_t i = 0; i < parts->part_count; i++) {
		const as_partition_status* status = &parts->parts[i];
		uint16_t part_id = status->part_id;

		if (!parts->done) {
			if (status->digest.init) {
				backup_state_mark_incomplete(state, part_id, status->digest.value);
			}
			else {
				backup_state_mark_not_started(state, part_id);
			}
		}
		else {
			// only possible for this to be false if part_id has 0 records, but
			// in that case we would want to try scanning the whole partition
			// again on resumption
			if (status->digest.init) {
				backup_state_mark_complete(state, part_id, status->digest.value);
			}
			else {
				// this partition has technically already been scanned, but it
				// was empty, so on backup resume we can try scanning it again
				backup_state_mark_complete(state, part_id, NULL);
			}
		}
	}
	pthread_mutex_unlock(&status->stop_lock);
}


//==========================================================
// Local helpers.
//

/*
 * Sort partition ranges and detect overlap.
 */
static bool
sort_partition_filters(as_vector *partition_filters)
{
	// Use insertion sort because ranges will likely already be in sorted order.
	as_partition_filter* list = (as_partition_filter*) partition_filters->list;
	int size = (int) partition_filters->size;
	int i, j;
	as_partition_filter key;

	for (i = 1; i < size; i++) {
		key = list[i];
		j = i - 1;

		while (j >= 0 && list[j].begin > key.begin) {
			list[j + 1] = list[j];
			j = j - 1;
		}
		list[j + 1] = key;
	}

	// Check for overlap.
	for (i = 1; i < size; i++) {
		as_partition_filter* prev = &list[i - 1];

		if (prev->begin + prev->count > list[i].begin) { 
			return false;  // overlap 
		}
	}
	return true; // no overlap
}

/*
 * Parse partition range string in format.
 *
 *  range: <begin partition>[-<partition count>]
 *  begin partition: 0 - 4095
 *  partition count: 1 - 4096  Default: 1
 *
 * Example: 1000-10
 */
static bool
parse_partition_range(char *str, as_partition_filter *range)
{
	char *p = strchr(str, '-');
	uint64_t begin = 0;
	uint64_t count = 1;
	bool rv = false;

	if (p) {
		*p++ = 0;
	}

	if (better_atoi(str, &begin) && begin < MAX_PARTITIONS) {	
		if (p) {
			rv = better_atoi(p, &count) && (begin + count) <= MAX_PARTITIONS;
		}
		else {
			rv = true;
		}
	}

	if (rv) {
		as_partition_filter_set_range(range, (uint32_t) begin, (uint32_t) count);
		return true;	
	}

	// Restore dash.
	if (p) {
		p--;
		*p = '-';
	}
	return false;
}

/*
 * Parse digest string in base64 format.
 *
 * Example: EjRWeJq83vEjRRI0VniavN7xI0U=
 */
static bool
parse_digest(const char *str, as_partition_filter* filter)
{
	uint32_t len = (uint32_t) strlen(str);
	uint8_t* bytes = (uint8_t*) alloca(cf_b64_decoded_buf_size(len));
	uint32_t size;
	uint32_t partition_id;
	
	if (!cf_b64_validate_and_decode(str, len, bytes, &size)) {
		return false;
	}

	if (size != sizeof(as_digest_value)) {
		return false;
	}

	partition_id = as_partition_getid(filter->digest.value, MAX_PARTITIONS);
	// used only when sorting partition ranges to verify no overlap, the c
	// client will not use this value
	as_partition_filter_set_id(filter, partition_id);
	memcpy(filter->digest.value, bytes, size);
	filter->digest.init = true;
	return true;
}

/*
 * Parse partition list string filters.
 *
 *	Format: <filter1>[,<filter2>][,...]
 *  filter: <begin partition>[-<partition count>]|<digest>
 *  begin partition: 0-4095
 *  partition count: 1-4096 Default: 1
 *  digest: base64 encoded string.
 *         This digest only includes records within the digest's partition,
 *         while the --after-digest argument includes both the digest's
 *         partition and every partition after the digest's partition.
 *
 * Example: 0-1000,1000-1000,2222,EjRWeJq83vEjRRI0VniavN7xI0U=
 */
static bool
parse_partition_list(char *partition_list, as_vector *partition_filters)
{
	bool res = false;
	char *clone = safe_strdup(partition_list);

	as_vector filters;
	as_vector_inita(&filters, sizeof(char*), 100);

	if (partition_list[0] == 0) {
		err("Empty partition list");
		goto cleanup;
	}

	split_string(clone, ',', true, &filters);

	as_partition_filter filter;

	for (uint32_t i = 0; i < filters.size; i++) {
		char *str = as_vector_get_ptr(&filters, i);

		if (parse_partition_range(str, &filter) || parse_digest(str, &filter)) {
			as_vector_append(partition_filters, &filter);
		}
		else {
			err("Invalid partition filter '%s'", str);
			err("format: <filter1>[,<filter2>][,...]");
			err("filter: <begin partition>[-<partition count>]|<digest>");
			err("begin partition: 0-4095");
			err("partition count: 1-4096 Default: 1");
			err("digest: base64 encoded string");
			goto cleanup;
		}
	}

	res = sort_partition_filters(partition_filters);

	if (!res) {
		err("Range overlap in partition list '%s'", partition_list);
	}

cleanup:
	as_vector_destroy(&filters);
	cf_free(clone);
	return res;
}

/*
 * Parse digest string filter in base64 format.
 * Append results to digest and partition ranges.
 *
 * Example: EjRWeJq83vEjRRI0VniavN7xI0U=
 */
static bool
parse_after_digest(char *str, as_vector* partition_filters)
{
	as_partition_filter filter;

	if (!parse_digest(str, &filter)) {
		return false;
	}

	// Append digest.
	as_vector_append(partition_filters, &filter);

	// Append all partitions after digest's partition.
	uint32_t id = as_partition_getid(filter.digest.value, MAX_PARTITIONS);

	if (++id < MAX_PARTITIONS) {
		as_partition_filter r;
		as_partition_filter_set_range(&r, id, (MAX_PARTITIONS - id));
		as_vector_append(partition_filters, &r);
	}

	return true;
}


/*
 * Parses a `host:port[,host:port[,...]]` string of (IP address, port) or
 * `host:tls_name:port[,host:tls_name:port[,...]]` string of
 * (IP address, tls_name, port) pairs into an array of node_spec,
 * tls_name being optional.
 *
 *  node_list:    The string to be parsed.
 *  node_specs:   The created array of node_spec.
 *  n_node_specs: The number of elements in the created array.
 *
 * result: true iff successful
 */
static bool
parse_node_list(char *node_list, node_spec **node_specs, uint32_t *n_node_specs)
{
	bool res = false;
	char *clone = safe_strdup(node_list);

	// also allow ";" (remain backwards compatible)
	for (size_t i = 0; node_list[i] != 0; ++i) {
		if (node_list[i] == ';') {
			node_list[i] = ',';
		}
	}

	as_vector node_vec;
	as_vector_inita(&node_vec, sizeof(void*), 25);

	if (node_list[0] == 0) {
		err("Empty node list");
		goto cleanup1;
	}

	split_string(node_list, ',', true, &node_vec);

	*n_node_specs = node_vec.size;
	*node_specs = safe_malloc(sizeof (node_spec) * node_vec.size);
	for (uint32_t i = 0; i < *n_node_specs; i++) {
		(*node_specs)[i].tls_name_str = NULL;
	}

	for (uint32_t i = 0; i < node_vec.size; ++i) {
		char *node_str = as_vector_get_ptr(&node_vec, i);
		sa_family_t family;
		char *colon;

		if (node_str[0] == '[') {
			family = AF_INET6;
			char *closing = strchr(node_str, ']');

			if (closing == NULL) {
				err("Invalid node list %s (missing \"]\"", clone);
				goto cleanup1;
			}

			if (closing[1] != ':') {
				err("Invalid node list %s (missing \":\")", clone);
				goto cleanup1;
			}

			colon = closing + 1;
		} else {
			family = AF_INET;
			colon = strchr(node_str, ':');

			if (colon == NULL) {
				err("Invalid node list %s (missing \":\")", clone);
				goto cleanup1;
			}
		}

		size_t length = (size_t)(colon - node_str);

		if (family == AF_INET6) {
			++node_str;
			length -= 2;
		}

		if (length == 0 || length > IP_ADDR_SIZE - 1) {
			err("Invalid node list %s (invalid IP address)", clone);
			goto cleanup2;
		}

		char ip_addr[IP_ADDR_SIZE];
		memcpy(ip_addr, node_str, length);
		ip_addr[length] = 0;

		union {
			struct in_addr v4;
			struct in6_addr v6;
		} ver;

		if (inet_pton(family, ip_addr, &ver) <= 0) {
			err("Invalid node list %s (invalid IP address %s)", clone, ip_addr);
			goto cleanup2;
		}

		uint64_t tmp;

		if (family == AF_INET6) {
			length = length + 1;
		}

		char *new_colon;
		new_colon = strchr(node_str + length + 1, ':');

		if (new_colon != NULL) {
			node_str = node_str + length + 1;
			length = (size_t)(new_colon - node_str);
			char tls_name[length + 1];
			memcpy(tls_name, node_str, length);
			tls_name[length] = '\0';

			(*node_specs)[i].tls_name_str = safe_malloc(sizeof(char) * (length + 1));
			memcpy((*node_specs)[i].tls_name_str, tls_name, length + 1);

			colon = new_colon;
		}

		if (!better_atoi(colon + 1, &tmp) || tmp < 1 || tmp > 65535) {
			err("Invalid node list %s (invalid port value %s)", clone, colon + 1);
			goto cleanup2;
		}

		memcpy((*node_specs)[i].addr_string, ip_addr, IP_ADDR_SIZE);
		(*node_specs)[i].family = family;
		memcpy(&(*node_specs)[i].ver, &ver, sizeof ver);
		(*node_specs)[i].port = htons((in_port_t)tmp);
	}

	res = true;
	goto cleanup1;

cleanup2:
	for (uint32_t i = 0; i < *n_node_specs; i++) {
		cf_free((*node_specs)[i].tls_name_str);
		(*node_specs)[i].tls_name_str = NULL;
	}
	cf_free(*node_specs);
	*node_specs = NULL;
	*n_node_specs = 0;

cleanup1:
	as_vector_destroy(&node_vec);
	cf_free(clone);
	return res;
}

/*
 * Parses a list of set names to either a single-set scan or a multi-set
 * expression filter.
 *
 * If only one set is given, set_name is populated with that set. Otherwise, if
 * multiple sets are given, set_list_expr is populated with an expression
 * selecting for that list of sets.
 */
static bool
parse_sets(const as_vector* set_list, char* set_name, exp_component_t* set_list_expr)
{
	uint64_t i = 0;
	if (set_list->size == 0) {
		// no sets in the list, keep default args in both scan and policy to
		// scan the entire namespace
		return true;
	}
	else if (set_list->size == 1) {
		// safe to use strcpy here because we have already verified that the
		// length of the set name is < AS_SET_MAX_SIZE
		strcpy(set_name, (const char*) as_vector_get((as_vector*) set_list, 0));
	}
	else {
		// build a filter expression on the set names
		as_vector entries;
		as_vector_init(&entries, sizeof(as_exp_entry), 8);

		as_exp_entry* or_decl = (as_exp_entry*) as_vector_reserve(&entries);
		*or_decl = (as_exp_entry) { .op = _AS_EXP_CODE_OR };

		for (i = 0; i < set_list->size; i++) {
			const char* set_name = (const char*) as_vector_get((as_vector*) set_list,
					(uint32_t) i);
			as_exp_entry eq_entry[] = { as_exp_cmp_eq(as_exp_set_name() ,
					as_exp_str(set_name)) };
			for (uint64_t j = 0; j < (sizeof(eq_entry) / sizeof(as_exp_entry));
					j++) {
				as_vector_append(&entries, &eq_entry[j]);
			}
		}

		as_exp_entry* end_decl = (as_exp_entry*) as_vector_reserve(&entries);
		*end_decl = (as_exp_entry) { .op = _AS_EXP_CODE_END_OF_VA_ARGS };

		exp_component_set(set_list_expr, (as_exp_entry*) entries.list,
				entries.size * sizeof(as_exp_entry));

		as_vector_destroy(&entries);
	}

	return true;
}

/*
 * Calculates the partitions on the list of nodes given (by name), and appends
 * corresponding partition filters to partition_filters
 */
static bool
calc_node_list_partitions(as_cluster *clust, const as_namespace ns,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names,
		as_vector* partition_filters)
{
	as_partition_filter* filter;

	bool last_part_included = false;
	as_partition_tables* tables = &clust->partition_tables;
	as_partition_table* table = as_partition_tables_get(tables, ns);

	for (uint32_t i = 0; i < table->size; i++) {
		as_partition* part = &table->partitions[i];

		for (uint32_t j = 0; j < n_node_names; j++) {
			if (strncmp(part->master->name, (*node_names)[j], AS_NODE_NAME_SIZE) == 0) {
				if (last_part_included) {
					filter->count++;
				}
				else {
					filter = as_vector_reserve(partition_filters);
					as_partition_filter_set_id(filter, i);
					last_part_included = true;
				}
				goto next_partition;
			}
		}

		last_part_included = false;
next_partition:;
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

/*
 * The callback passed to get_info() to parse the namespace LDT flag.
 *
 * @param context_  The boolean result to be populated.
 * @param key       The key of the current key-value pair.
 * @param value     The corresponding value.
 *
 * @result          `true`, if successful.
 */
static bool
check_for_ldt_callback(void *context_, const char *key, const char *value)
{
	bool *context = (bool *)context_;

	if (strcmp(key, "ldt-enabled") == 0 && strcmp(value, "true") == 0) {
		ver("Node supports LDT");

		*context = true;
	}

	return true;
}

/*
 * Determines whether any of the given nodes has LDT enabled for the given namespace.
 *
 * @param as            The Aerospike client instance.
 * @param namespace     The namespace that we are interested in.
 * @param node_names    The array of node IDs of the cluster nodes to be queried.
 * @param n_node_names  The number of elements in the node ID array.
 * @param has_ldt       Returns whether at least one of the nodes uses LDT.
 *
 * @result              `true`, if successful.
 */
static bool
check_for_ldt(aerospike *as, const char *namespace, char (*node_names)[][AS_NODE_NAME_SIZE],
		uint32_t n_node_names, bool *has_ldt)
{
	ver("Checking for LDT");

	bool tmp_has_ldt = false;

	size_t value_size = sizeof "namespace/" - 1 + strlen(namespace) + 1;
	char value[value_size];
	snprintf(value, value_size, "namespace/%s", namespace);

	for (uint32_t i = 0; i < n_node_names; ++i) {
		ver("Checking for LDT on node %s", (*node_names)[i]);

		if (!get_info(as, value, (*node_names)[i], &tmp_has_ldt, check_for_ldt_callback, true)) {
			err("Error while checking for LDT on node %s", (*node_names)[i]);
			return false;
		}

		if (tmp_has_ldt) {
			break;
		}
	}

	*has_ldt = tmp_has_ldt;
	return true;
}

/*
 * The callback passed to get_info() to parse the namespace object count and replication factor.
 *
 * @param context_  The ns_count_context for the parsed result.
 * @param key       The key of the current key-value pair.
 * @param value     The corresponding value.
 *
 * @result          `true`, if successful.
 */
static bool
ns_count_callback(void *context_, const char *key, const char *value)
{
	ns_count_context *context = (ns_count_context *)context_;
	uint64_t tmp;

	if (strcmp(key, "objects") == 0) {
		if (!better_atoi(value, &tmp)) {
			err("Invalid object count %s", value);
			return false;
		}

		context->count = tmp;
		return true;
	}

	if (strcmp(key, "repl-factor") == 0 || strcmp(key, "effective_replication_factor") == 0) {
		if (!better_atoi(value, &tmp) || tmp == 0 || tmp > 100) {
			err("Invalid replication factor %s", value);
			return false;
		}

		context->factor = (uint32_t)tmp;
		return true;
	}

	return true;
}

/*
 * The callback passed to get_info() to parse the set object count.
 *
 * @param context_  The set_count_context for the parsed result.
 * @param key       The key of the current key-value pair. Not used.
 * @param value     A string of the form "<k1>=<v1>[:<k2>=<v2>[:...]]".
 *
 * @result          `true`, if successful.
 */
static bool
set_count_callback(void *context_, const char *key_, const char *value_)
{
	(void)key_;
	set_count_context *context = (set_count_context *)context_;
	bool res = false;

	// The server sends a trailing semicolon, which results in an empty last string. Skip it.
	if (value_[0] == 0) {
		res = true;
		goto cleanup0;
	}

	char *info = safe_strdup(value_);
	as_vector info_vec;
	as_vector_inita(&info_vec, sizeof (void *), 25);
	split_string(info, ':', false, &info_vec);

	bool match = true;
	uint64_t count = 0;

	for (uint32_t i = 0; i < info_vec.size; ++i) {
		char *key = as_vector_get_ptr(&info_vec, i);
		char *equals = strchr(key, '=');

		if (equals == NULL) {
			err("Invalid info string %s (missing \"=\")", value_);
			goto cleanup1;
		}

		*equals = 0;
		char *value = equals + 1;

		if ((strcmp(key, "ns_name") == 0 || strcmp(key, "ns") == 0) &&
				strcmp(value, context->ns) != 0) {
			match = false;
		}

		if ((strcmp(key, "set_name") == 0 || strcmp(key, "set") == 0) &&
				strcmp(value, context->set) != 0) {
			match = false;
		}

		if ((strcmp(key, "n_objects") == 0 || strcmp(key, "objects") == 0) &&
				!better_atoi(value, &count)) {
			err("Invalid object count %s", value);
			goto cleanup1;
		}
	}

	if (match) {
		context->count += count;
	}

	res = true;

cleanup1:
	as_vector_destroy(&info_vec);
	cf_free(info);

cleanup0:
	return res;
}

/*
 * Retrieves the total number of objects stored in the given namespace on the given nodes.
 *
 * Queries each cluster node individually, sums up the reported numbers, and then divides by the
 * replication count.
 *
 * @param as            The Aerospike client instance.
 * @param namespace     The namespace that we are interested in.
 * @param set           The set that we are interested in.
 * @param node_names    The array of node IDs of the cluster nodes to be queried.
 * @param n_node_names  The number of elements in the node ID array.
 * @param obj_count     The number of objects.
 *
 * @result              `true`, if successful.
 */
static bool
get_object_count(aerospike *as, const char *namespace, as_vector* set_list,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, uint64_t *obj_count)
{
	ver("Getting cluster object count");

	*obj_count = 0;

	size_t value_size = sizeof "namespace/" - 1 + strlen(namespace) + 1;
	char value[value_size];
	snprintf(value, value_size, "namespace/%s", namespace);
	inf("%-20s%-15s%-15s", "Node ID", "Objects", "Replication");
	ns_count_context ns_context = { 0, 0 };

	for (uint32_t i = 0; i < n_node_names; ++i) {
		ver("Getting object count for node %s", (*node_names)[i]);

		if (!get_info(as, value, (*node_names)[i], &ns_context, ns_count_callback, true)) {
			err("Error while getting namespace object count for node %s", (*node_names)[i]);
			return false;
		}

		if (ns_context.factor == 0) {
			err("Invalid namespace %s", namespace);
			return false;
		}

		uint64_t count;

		if (set_list->size == 0) {
			count =  ns_context.count;
		} else {
			count = 0;
			for (uint32_t j = 0; j < set_list->size; j++) {
				const char* set = (const char*) as_vector_get(set_list, j);

				set_count_context set_context = { namespace, set, 0 };

				if (!get_info(as, "sets", (*node_names)[i], &set_context, set_count_callback, false)) {
					err("Error while getting set object count for node %s", (*node_names)[i]);
					return false;
				}

				count += set_context.count;
			}
		}

		inf("%-20s%-15" PRIu64 "%-15d", (*node_names)[i], count, ns_context.factor);
		*obj_count += count;
	}

	*obj_count /= ns_context.factor;
	return true;
}

