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

#include <stdatomic.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_exp.h>

#pragma GCC diagnostic pop

#include <backup.h>
#include <backup_state.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

// Pointers to the backup_config_t/backup_status_t structs of the currently
// running backup job.
typedef struct backup_globals {
	_Atomic(backup_config_t*) conf;
	_Atomic(backup_status_t*) status;
} backup_globals_t;

// A list of all global backup states of all jobs. When jobs are run within
// other jobs, their state is pushed to the top of this stack (top meaning end
// of the vector).
static as_vector g_globals;

//==========================================================
// Forward Declarations.
//

static backup_status_t* start_backup(backup_config_t* conf);

typedef struct distr_stats {
	uint64_t total;
	double mean;
	double variance;
} distr_stats_t;

/*
 * The per partition filter information pushed to the job queue and picked up
 * by the backup threads.
 */
typedef struct backup_thread_args {
	// The global backup configuration.
	const backup_config_t *conf;
	// The global backup stats.
	backup_status_t *status;
	// Partition ranges/digest to be backed up. 
	as_partition_filter filter;

	// A queue of all completed backup jobs
	cf_queue* complete_queue;

	union {
		// When backing up to a single file, the file descriptor of that file.
		io_write_proxy_t* shared_fd;

		// When backing up to a directory, the queue of backup files which have
		// not been completely filled yet
		cf_queue* file_queue;
	};
	// This is the first job in the job queue. It'll take care of backing up
	// secondary indexes and UDF files.
	bool first;
	// When estimating the average records size, the array that receives the
	// record size samples.
	uint64_t *samples;
	// The number of record size samples that fit into the samples array.
	_Atomic(uint32_t) *n_samples;
} backup_thread_args_t;

/*
 * The context for information about the currently processed partition. Each backup
 * thread creates one of these for each scan call that it makes.
 */
typedef struct backup_job_context {
	// Task description. 
	char desc[128];
	// The global backup configuration.
	const backup_config_t *conf;
	// The global backup stats. Copied from backup_thread_args.status.
	backup_status_t *status;
	// The scan configuration to be used.
	as_scan scan;
	// Set if the backup job terminated a scan early for any reason.
	bool interrupted;

	union {
		// When backing up to a single file, the file descriptor of that file.
		// Copied from backup_thread_args.shared_fd.
		io_write_proxy_t* shared_fd;

		// When backing up to a directory, the queue of backup files which have
		// not been completely filled yet
		cf_queue* file_queue;
	};

	// The file descriptor of the current backup file for the current job.
	io_write_proxy_t* fd;

	// When backing up to a directory, counts the number of records in the
	// current backup file for the current job.
	uint64_t rec_count_file;
	// When backing up to a directory, tracks the size of the current backup
	// file for the currently processed partition filter.
	uint64_t byte_count_file;
	// Counts the number of records read from the currently processed partition
	// filter.
	uint64_t rec_count_job;
	// Counts the number of bytes written to all backup files for the current
	// job.
	uint64_t byte_count_job;
	// When estimating the average record size, the array that receives the
	// record size samples. Copied from backup_thread_args.samples.
	uint64_t *samples;
	// The number of record size samples that fit into the samples array. Copied
	// from backup_thread_args.n_samples.
	_Atomic(uint32_t)* n_samples;
} backup_job_context_t;

/*
 * To be used by signal handlers, call the corresponding backup_status_* methods
 * with g_backup_status as a first parameter.
 */
static void stop(void);
static bool has_stopped(void);
static void set_sigaction(void (*)(int));

static void push_backup_globals(backup_config_t* conf, backup_status_t* status);
static void pop_backup_globals();
static void set_global_status(backup_status_t* status);

static uint64_t directory_backup_remaining_estimate(const backup_config_t* conf,
		backup_status_t* status);
static int update_file_pos(io_write_proxy_t* fd, uint64_t* byte_count_file,
		uint64_t* byte_count_job, _Atomic(uint64_t)* byte_count_total);
static int update_shared_file_pos(io_write_proxy_t* fd,
		_Atomic(uint64_t)* byte_count_total);
static bool queue_file(backup_job_context_t* bjc);
static bool close_file(io_write_proxy_t *fd);
static bool open_file(const char *file_path, const char *ns,
		uint64_t disk_space, io_write_proxy_t *fd,
		compression_opt c_opt, int32_t compression_level, encryption_opt e_opt,
		encryption_key_t* pkey);
static bool close_dir_file(backup_job_context_t *bjc);
static bool open_dir_file(backup_job_context_t *bjc);
static backup_state_t* load_backup_state(const char* state_file_path);
static void save_job_state(const backup_thread_args_t* args);
static bool complete_job(cf_queue* complete_queue, const backup_thread_args_t*);
static as_scan* prepare_scan(as_scan* scan, const backup_job_context_t* bjc);
static bool scan_callback(const as_val *val, void *cont);
static bool process_secondary_indexes(backup_job_context_t *bjc);
static bool process_udfs(backup_job_context_t *bjc);
static void * backup_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static bool init_scan_bins(char *bin_list, as_scan *scan);
static bool narrow_partition_filters(backup_state_t* state,
		as_vector* partition_filters, const backup_config_t* conf);
static distr_stats_t calc_record_stats(uint64_t* samples, uint32_t n_samples);
static uint64_t estimate_total_backup_size(uint64_t* samples, uint32_t n_samples,
		uint64_t header_size, uint64_t estimate_byte_count,
		uint64_t rec_count_estimate, double confidence_level);
static void show_estimate(FILE* mach_fd, uint64_t* samples, uint32_t n_samples,
		uint64_t header_size, uint64_t estimate_byte_count,
		uint64_t rec_count_estimate, io_write_proxy_t* fd);
static void sig_hand(int32_t sig);
static void no_op(int32_t sig);
static void set_s3_configs(const backup_config_t*);


//==========================================================
// Public API.
//

int32_t
backup_main(int32_t argc, char **argv)
{
	int32_t res = EXIT_FAILURE;

	enable_client_log();

	as_vector_init(&g_globals, sizeof(backup_globals_t), 1);

	backup_config_t conf;

	int backup_config_res = backup_config_set(argc, argv, &conf);
	if (backup_config_res != 0) {
		if (backup_config_res == BACKUP_CONFIG_INIT_EXIT) {
			res = EXIT_SUCCESS;
		}
		goto cleanup;
	}

	int backup_validate_res = backup_config_validate(&conf);
	if (backup_validate_res != 0) {
		goto cleanup;
	}

	backup_status_t* status = start_backup(&conf);
	if (status == RUN_BACKUP_SUCCESS) {
		res = EXIT_SUCCESS;
	}
	else if (status != RUN_BACKUP_FAILURE) {
		backup_status_destroy(status);
		cf_free(status);
		res = EXIT_SUCCESS;
	}

	backup_config_destroy(&conf);

cleanup:
	file_proxy_cloud_shutdown();
	as_vector_destroy(&g_globals);
	ver("Exiting with status code %d", res);
	return res;
}

/*
 * FOR USE WITH ASBACKUP AS A LIBRARY (Use at your own risk)
 *
 * Runs a backup job with the given configuration. This method is not thread
 * safe and should not be called multiple times in parallel, as it uses global
 * variables to handle signal interruption.
 * 
 * The passed in backup config must be destroyed by the caller using backup_config_destroy()
 * To enable C client logging, call enable_client_log() before calling this function
 * 
 * Returns the backup_status struct used during the run which must be freed by the
 * caller using backup_status_destroy(), then free().
 * Only free the return value if it is != RUN_BACKUP_FAILURE || != RUN_BACKUP_SUCCESS
 */
backup_status_t*
backup_run(backup_config_t* conf) {
	as_vector_init(&g_globals, sizeof(backup_globals_t), 1);

	backup_config_set_heap_defaults(conf);
	backup_status_t* status = start_backup(conf);

	file_proxy_cloud_shutdown();
	as_vector_destroy(&g_globals);

	return status;
}

backup_config_t*
get_g_backup_conf(void)
{
	backup_globals_t* cur_globals =
		(backup_globals_t*) as_vector_get(&g_globals, g_globals.size - 1);
	return cur_globals->conf;
}

backup_status_t*
get_g_backup_status(void)
{
	backup_globals_t* cur_globals =
		(backup_globals_t*) as_vector_get(&g_globals, g_globals.size - 1);
	return cur_globals->status;
}


//==========================================================
// Local helpers.
//

/*
 * Runs a backup job with the given configuration. This method is not thread
 * safe and should not be called multiple times in parallel, as it uses global
 * variables to handle signal interruption.
 *
 * Returns the backup_status struct used during the run (must be freed by the
 * caller).
 */
static backup_status_t*
start_backup(backup_config_t* conf)
{
	int32_t res = EXIT_FAILURE;
	bool do_backup_save_state = false;
	backup_state_t* backup_state = NULL;
	backup_status_t* status = RUN_BACKUP_SUCCESS;

	push_backup_globals(conf, NULL);

	set_s3_configs(conf);

	if (conf->remove_artifacts) {

		if (conf->output_file != NULL) {
			inf("Deleting output file %s", conf->output_file);
			if (file_proxy_delete_file(conf->output_file)) {
				res = EXIT_SUCCESS;
			}
		}
		else {
			inf("Deleting backup directory %s", conf->directory);
			if (file_proxy_delete_directory(conf->directory)) {
				res = EXIT_SUCCESS;
			}
		}

		// we're done, go ahead and exit
		goto cleanup1;
	}

	if (!backup_config_log_start(conf)) {
		goto cleanup1;
	}

	status = (backup_status_t*) cf_malloc(sizeof(backup_status_t));
	if (status == NULL) {
		err("Failed to allocate %zu bytes for backup status struct",
				sizeof(backup_status_t));
		goto cleanup1;
	}

	if (!backup_status_init(status, conf)) {
		goto cleanup1;
	}

	FILE *mach_fd = NULL;

	if (conf->machine != NULL && (mach_fd = fopen(conf->machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf->machine);
		goto cleanup2;
	}

	pthread_t backup_threads[MAX_PARALLEL];
	uint32_t n_threads = (uint32_t) (conf->parallel == 0 ? DEFAULT_PARALLEL : conf->parallel);
	backup_thread_args_t backup_args;
	backup_args.conf = conf;
	backup_args.status = status;
	backup_args.shared_fd = NULL;
	backup_args.samples = status->estimate_samples;
	backup_args.n_samples = &status->n_estimate_samples;

	cf_queue *job_queue = cf_queue_create(sizeof(backup_thread_args_t), true);
	cf_queue *complete_queue = cf_queue_create(sizeof(backup_thread_args_t), true);
	backup_args.complete_queue = complete_queue;

	backup_state_t* loaded_backup_state = NULL;

	if (job_queue == NULL || backup_args.complete_queue == NULL) {
		err("Error while allocating job queue");
		goto cleanup3;
	}

	if (status->partition_filters.size <= 1) {
		// since only one partition range is being backed up, evenly divide the range into 'n_threads' segments
		as_partition_filter range;

		if (status->partition_filters.size == 0) {
			as_partition_filter* range_ptr = (as_partition_filter*)
				as_vector_reserve(&status->partition_filters);
			as_partition_filter_set_range(range_ptr, 0, MAX_PARTITIONS);
		}

		range = *(as_partition_filter*) as_vector_get(&status->partition_filters, 0);

		if (n_threads > range.count) {
			inf("Warning: --parallel %u is higher than the number of partitions being "
					"backed up (%u), setting number of threads to %u.",
					n_threads, range.count, range.count);
			n_threads = range.count;
		}

		// don't divide up partition ranges if doing --after-digest of partition 4095
		if (n_threads > 1) {
			as_vector_clear(&status->partition_filters);

			for (uint32_t i = 0; i < n_threads; i++) {
				as_partition_filter* range_ptr = (as_partition_filter*)
					as_vector_reserve(&status->partition_filters);

				uint16_t begin = (uint16_t) ((uint32_t) range.begin +
						((uint32_t) range.count * i) / n_threads);
				uint16_t count = (uint16_t) ((uint32_t) range.begin +
						((uint32_t) range.count * (i + 1)) / n_threads) - begin;
				as_partition_filter_set_range(range_ptr, begin, count);
			}
		}
	}
	else {
		uint32_t n_filters = status->partition_filters.size;
		if (n_threads > n_filters) {
			inf("Warning: --parallel %u is higher than the number of partition "
					"filters given (%u), setting number of threads to %u.",
					n_threads, n_filters, n_filters);
			n_threads = n_filters;
		}
	}

	// Set the global backup status pointer in case it is necessary for file
	// proxy initialization in load_backup_state. Backup interruption is
	// allowable from this point onward, as the fields that haven't been
	// initialized in status aren't used when stopping a backup.
	set_global_status(status);
	#ifndef ASB_SHARED_LIB
	set_sigaction(sig_hand);
	#endif

	if (conf->state_file != NULL) {
		loaded_backup_state = load_backup_state(conf->state_file);

		if (loaded_backup_state == NULL) {
			goto cleanup3;
		}

		if (!narrow_partition_filters(loaded_backup_state, &status->partition_filters, conf)) {
			goto cleanup3;
		}

		backup_state_load_global_status(loaded_backup_state, status);

		// set the byte count limit "conf->bandwidth" bytes above the current
		// byte count so we don't have to wait for byte_count_limit to surpass
		// byte_count_total
		status->byte_count_limit = status->byte_count_total + conf->bandwidth;

		if (conf->max_records > 0) {
			// If we are resuming with --max-records, subtract the number of
			// records that have already been backed up.
			if (conf->max_records < status->rec_count_total) {
				err("Continuing backup with %" PRIu64 " records already backed "
						"up, but --max-records set to %" PRIu64,
						status->rec_count_total, conf->max_records);
				goto cleanup3;
			}
			else {
				conf->max_records -= status->rec_count_total;
			}
		}
	}

	// now that we've finalized the number of threads/tasks, let the backup
	// status struct know
	backup_status_set_n_threads(status, conf, status->partition_filters.size,
			n_threads);

	// backing up to a single backup file: open the file now and store the file descriptor in
	// backup_args.shared_fd; it'll be shared by all backup threads
	if (conf->output_file != NULL) {
		if (conf->state_file != NULL) {
			// if the backup is being resumed, use the reopened io_proxy in the backup
			// state
			if (loaded_backup_state->files.size != 1) {
				err("Expected 1 backup file save state for resuming "
						"backup-to-file, but found %u in the backup state file",
						loaded_backup_state->files.size);
				goto cleanup3;
			}

			backup_state_file_t file =
				*(backup_state_file_t*) as_vector_get(&loaded_backup_state->files, 0);

			if (strcmp(io_proxy_file_path(file.io_proxy), conf->output_file) != 0) {
				err("Expected output file name of \"%s\", but found \"%s\" in "
						"the backup state file", conf->output_file,
						io_proxy_file_path(file.io_proxy));
				goto cleanup3;
			}

			backup_args.shared_fd = file.io_proxy;
			io_proxy_init_compression(backup_args.shared_fd, conf->compress_mode);
			if (conf->compress_mode != IO_PROXY_COMPRESS_NONE &&
					io_proxy_set_compression_level(backup_args.shared_fd,
						conf->compression_level) != 0) {
				goto cleanup3;
			}
			io_proxy_init_encryption(backup_args.shared_fd, conf->pkey,
					conf->encrypt_mode);

			if (io_proxy_initialize(backup_args.shared_fd) != 0) {
				goto cleanup3;
			}

			as_vector_clear(&loaded_backup_state->files);
		}
		else {
			if (!prepare_output_file(conf)) {
				goto cleanup3;
			}

			// run a backup estimate to guess the size of the backup file
			backup_config_t* estimate_conf = backup_config_clone(conf);
			estimate_conf->estimate = true;
			cf_free(estimate_conf->output_file);
			estimate_conf->output_file = NULL;
			// don't do any throttling
			estimate_conf->bandwidth = 0;
			estimate_conf->records_per_second = 0;
			// don't use max-records for the estimate (use estimate-samples)
			estimate_conf->max_records = 0;
			// don't parallelize the estimate
			estimate_conf->parallel = 0;

			bool cur_silent_val = g_silent;
			g_silent = true;
			backup_status_t* estimate_status = start_backup(estimate_conf);
			g_silent = cur_silent_val;

			backup_config_destroy(estimate_conf);
			cf_free(estimate_conf);

			// re-enable signal handling, since it was disabled at the end of
			// the estimate run in start_backup.
			#ifndef ASB_SHARED_LIB
			set_sigaction(sig_hand);
			#endif

			if (estimate_status == RUN_BACKUP_FAILURE) {
				err("Error while running backup estimate");
				// the estimate failed
				goto cleanup3;
			}

			uint64_t est_backup_size = estimate_total_backup_size(
					estimate_status->estimate_samples,
					estimate_status->n_estimate_samples,
					estimate_status->header_size,
					estimate_status->byte_count_total,
					status->rec_count_estimate,
					BACKUP_FILE_ESTIMATE_CONFIDENCE_LEVEL);

			ver("Estimated backup file size: %" PRIu64 " bytes", est_backup_size);

			backup_status_destroy(estimate_status);
			cf_free(estimate_status);

			backup_args.shared_fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
			if (!open_file(conf->output_file, conf->ns, est_backup_size,
						backup_args.shared_fd, conf->compress_mode,
						conf->compression_level, conf->encrypt_mode,
						conf->pkey)) {
				err("Error while opening shared backup file \"%s\"",
						conf->output_file);
				goto cleanup3;
			}
		}
	}
	else if (conf->estimate) {
		backup_args.shared_fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));

		if (!open_file(NULL, conf->ns, 0, backup_args.shared_fd,
					conf->compress_mode, conf->compression_level,
					conf->encrypt_mode, conf->pkey)) {
			err("Error while opening \"/dev/null\"");
			cf_free(backup_args.shared_fd);
			goto cleanup3;
		}
	}
	else {
		backup_args.file_queue = cf_queue_create(sizeof(queued_backup_fd_t), true);

		if (backup_args.file_queue == NULL) {
			err("Failed to create cf_queue");
			goto cleanup3;
		}

		if (!prepare_directory(conf)) {
			goto cleanup4;
		}

		if (!scan_directory(conf, status, loaded_backup_state)) {
			goto cleanup4;
		}

		if (loaded_backup_state != NULL) {
			for (uint32_t i = 0; i < loaded_backup_state->files.size; i++) {
				backup_state_file_t file =
					*(backup_state_file_t*) as_vector_get(&loaded_backup_state->files, i);

				io_proxy_init_compression(file.io_proxy, conf->compress_mode);
				if (conf->compress_mode != IO_PROXY_COMPRESS_NONE &&
						io_proxy_set_compression_level(file.io_proxy,
							conf->compression_level) != 0) {
					goto cleanup4;
				}
				io_proxy_init_encryption(file.io_proxy, conf->pkey, conf->encrypt_mode);

				queued_backup_fd_t q = {
					.fd = file.io_proxy,
					.rec_count_file = file.rec_count_file,
					.byte_count_file =
						(uint64_t) io_write_proxy_bytes_written(file.io_proxy)
				};

				if (cf_queue_push(backup_args.file_queue, &q) != CF_QUEUE_OK) {
					err("Failed to push reopened file %s to the queue",
							io_proxy_file_path(file.io_proxy));
					goto cleanup4;
				}
			}

			as_vector_clear(&loaded_backup_state->files);
		}
	}

	if (loaded_backup_state != NULL) {
		backup_state_free(loaded_backup_state);
		cf_free(loaded_backup_state);
		loaded_backup_state = NULL;
	}

	if (backup_config_can_resume(conf)) {
		char* state_file_loc = gen_backup_state_file_path(conf);

		if (state_file_loc == NULL) {
			goto cleanup4;
		}

		cf_free(conf->state_file_dst);
		conf->state_file_dst = state_file_loc;
	}
	else if (conf->state_file_dst != NULL) {
		inf("Warning: in this state, backup save-state is not possible, "
				"--state-file-dst option is ignored");

		cf_free(conf->state_file_dst);
		conf->state_file_dst = NULL;
	}

	backup_status_start(status);

	bool first;
	// only process indices/udfs if we are not resuming a failed/interrupted backup
	if (conf->state_file != NULL) {
		first = false;
		backup_status_signal_one_shot(status);
	}
	else {
		first = true;
	}

	as_vector* partition_filters = &status->partition_filters;

	// Create backup task for every partition filter.
	for (uint32_t i = 0; i < partition_filters->size; i++) {
		as_partition_filter *filter = as_vector_get(partition_filters, i);
		memcpy(&backup_args.filter, filter, sizeof(as_partition_filter));
		if (filter->parts_all) {
			as_partitions_status_reserve(filter->parts_all);
		}

		backup_args.first = first;
		first = false;

		if (cf_queue_push(job_queue, &backup_args) != CF_QUEUE_OK) {
			err("Error while queueing backup job");
			goto cleanup4;
		}
	}

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = conf;
	counter_args.status = status;
	counter_args.mach_fd = mach_fd;

	ver("Creating counter thread");

	if (pthread_create(&counter_thread, NULL, counter_thread_func, &counter_args) != 0) {
		err_code("Error while creating counter thread");
		goto cleanup5;
	}

	uint32_t n_threads_ok = 0;

	ver("Creating %u backup thread(s)", n_threads);

	for (uint32_t i = 0; i < n_threads; ++i) {
		if (pthread_create(&backup_threads[i], NULL, backup_thread_func, job_queue) != 0) {
			err_code("Error while creating backup thread");
			goto cleanup6;
		}

		++n_threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup6:
	ver("Waiting for %u backup thread(s)", n_threads_ok);

	void *thread_res;

	for (uint32_t i = 0; i < n_threads_ok; i++) {
		if (pthread_join(backup_threads[i], &thread_res) != 0) {
			err_code("Error while joining backup thread");
			stop();
			res = EXIT_FAILURE;
		}
		else if (thread_res != (void *)EXIT_SUCCESS) {
#ifdef __APPLE__
			ver("Backup thread %p failed", backup_threads[i]);
#else
			ver("Backup thread %" PRIu64 " failed", backup_threads[i]);
#endif /* __APPLE__ */

			res = EXIT_FAILURE;
		}
	}

	if (!conf->estimate) {
		// no longer allow SIGINT/SIGSTOP to trigger saving the backup state
		#ifndef ASB_SHARED_LIB
		set_sigaction(no_op);
		#endif
	}

	// Since we won't be acquiring any more locks from here on
	as_fence_seq();

	backup_state = backup_status_get_backup_state(status);
	do_backup_save_state = backup_state != NULL &&
		backup_state != BACKUP_STATE_ABORTED;

	if (conf->estimate) {
		io_proxy_flush(backup_args.shared_fd);
		update_shared_file_pos(backup_args.shared_fd, &status->byte_count_total);
		show_estimate(mach_fd, status->estimate_samples, status->n_estimate_samples,
				status->header_size, status->byte_count_total,
				status->rec_count_estimate, backup_args.shared_fd);
	}
	else if (conf->output_file == NULL) {
		// backing up to a directory, clear out the file queue
		queued_backup_fd_t queued_fd;
		while (cf_queue_pop(backup_args.file_queue, &queued_fd, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			// if we're not saving a backup state and the backup wasn't aborted,
			// close + save the file
			if (backup_state == NULL) {
				if (io_proxy_flush(queued_fd.fd) != 0) {
					err("Failed to flush io proxy %s\n", io_proxy_file_path(queued_fd.fd));
					res = EXIT_FAILURE;
				}
				// Update the global byte count total after flushing the file.
				uint64_t tmp = 0;
				update_file_pos(queued_fd.fd, &queued_fd.byte_count_file, &tmp,
						&status->byte_count_total);

				if (res == EXIT_FAILURE || !close_file(queued_fd.fd)) {
					res = EXIT_FAILURE;
					// try to save the backup state
					if (!backup_status_init_backup_state_file(conf->state_file_dst,
								status)) {
						// if this fails for any reason, we have to abort the backup
						backup_status_abort_backup_unsafe(status);
					}

					backup_state = backup_status_get_backup_state(status);
					do_backup_save_state = backup_state != NULL &&
						backup_state != BACKUP_STATE_ABORTED;
				}
				else {
					// if the file successfully closed, free it and continue
					// closing the rest of the files
					cf_free(queued_fd.fd);
					continue;
				}
			}

			// check this condition again since it may have changed in the above
			// if statement
			if (do_backup_save_state) {
				// Update the global byte count total after flushing the file.
				uint64_t tmp = 0;
				update_file_pos(queued_fd.fd, &queued_fd.byte_count_file, &tmp,
						&status->byte_count_total);

				backup_state_save_file(backup_state, queued_fd.fd,
						queued_fd.rec_count_file);
			}
			else if (backup_state == BACKUP_STATE_ABORTED) {
				// close the backup file without saving
				io_proxy_close2(queued_fd.fd, FILE_PROXY_ABORT);
				cf_free(queued_fd.fd);
			}
		}
	}
	else if (do_backup_save_state) {
		// backing up to a file, save the io proxy to the backup file if necessary
		update_shared_file_pos(backup_args.shared_fd, &status->byte_count_total);

		backup_state_save_file(backup_state, backup_args.shared_fd, 0);
	}

	if (do_backup_save_state) {
		// if we failed for any reason, go through the rest of the backup job
		// queue and mark each of the not-started jobs as not-started in the
		// error file
		backup_thread_args_t args;
		while (cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			save_job_state(&args);

			if (args.filter.parts_all != NULL) {
				as_partitions_status_release(args.filter.parts_all);
			}
		}

		backup_state_set_global_status(backup_state, status);
	}

	backup_thread_args_t complete_args;
	while (cf_queue_pop(complete_queue, &complete_args, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
		if (do_backup_save_state) {
			save_job_state(&complete_args);
		}

		if (complete_args.filter.parts_all != NULL) {
			as_partitions_status_release(complete_args.filter.parts_all);
		}
	}

	backup_status_finish(status);

	ver("Waiting for counter thread");

	if (pthread_join(counter_thread, NULL) != 0) {
		err_code("Error while joining counter thread");
		res = EXIT_FAILURE;
	}

cleanup5:
	// don't catch SIGINT/SIGSTOP while cleaning up
	#ifndef ASB_SHARED_LIB
	set_sigaction(no_op);
	#endif

cleanup4:
	if (conf->output_file != NULL || conf->estimate) {
		// if we are saving the backup state, the shared fd has been passed to the
		// backup state struct, so we are no longer responsible for freeing it
		if (!do_backup_save_state) {
			if (io_proxy_flush(backup_args.shared_fd) != 0) {
				err("Error while flushing shared backup file \"%s\"",
						io_proxy_file_path(backup_args.shared_fd));
				res = EXIT_FAILURE;
			}

			update_shared_file_pos(backup_args.shared_fd, &status->byte_count_total);

			if (!close_file(backup_args.shared_fd)) {
				err("Error while closing shared backup file \"%s\"",
						io_proxy_file_path(backup_args.shared_fd));
				res = EXIT_FAILURE;

				// try to save the backup state
				if (!backup_status_init_backup_state_file(conf->state_file_dst,
							status)) {
					// if this fails for any reason, we have to abort the backup
					backup_status_abort_backup_unsafe(status);
				}

				backup_state = backup_status_get_backup_state(status);
				do_backup_save_state = backup_state != NULL &&
					backup_state != BACKUP_STATE_ABORTED;

				if (do_backup_save_state) {
					backup_state_save_file(backup_state, backup_args.shared_fd, 0);
				}
			}
			else {
				cf_free(backup_args.shared_fd);
			}
		}
	}
	else {
		cf_queue_destroy(backup_args.file_queue);
	}

	if (backup_state == BACKUP_STATE_ABORTED) {
		err("Backup was aborted, meaning the state is unrecoverable");
	}

cleanup3:
	cf_queue_destroy(job_queue);
	cf_queue_destroy(complete_queue);

	if (backup_state != NULL && backup_state != BACKUP_STATE_ABORTED) {
		if (backup_status_one_shot_done(status)) {
			if (backup_state_is_complete(backup_state)) {
				// if the backup state is actually complete, close/flush all
				// of the backup state files and clear the file vector before
				// closing the backup state.
				uint32_t size = backup_state->files.size;
				while (size > 0) {
					backup_state_file_t file_data =
						*(backup_state_file_t*) as_vector_get(&backup_state->files, size - 1);
					io_proxy_t* file = file_data.io_proxy;

					if (io_proxy_flush(file) != 0 ||
							io_proxy_close2(file, FILE_PROXY_EOF) != 0) {
						err("Failed to flush/close backup file %s, saving the backup state",
								io_proxy_file_path(file));
						goto save_backup_state;
					}

					cf_free(file);

					as_vector_remove(&backup_state->files, size - 1);
					size--;
				}

				// if we completed the backup and were able to successfully
				// close all backup files, this was a successful run
				res = EXIT_SUCCESS;
			}
			else {
save_backup_state:
				// only save the backup state if the one shot work finished and at
				// least one partition isn't complete, since one shot work isn't
				// done in backup resumption and it's possible for the backup state
				// to have been created after all scans completed
				if (backup_state_save(backup_state) != 0) {
					err("Failed to save backup state, aborting backup");
					backup_state = BACKUP_STATE_ABORTED;
				}
				else {
					inf("Backup was interrupted, to resume, run backup with "
							"`--continue %s` and all the same arguments "
							"(except --remove-files)", conf->state_file_dst);
				}
			}
		}
	}

	if (backup_state == BACKUP_STATE_ABORTED) {
		err("Backup aborted, backup state is likely unrecoverable");
	}

	if (loaded_backup_state != NULL) {
		backup_state_free(loaded_backup_state);
		cf_free(loaded_backup_state);
		loaded_backup_state = NULL;
	}

	uint64_t records = status->rec_count_total;
	uint64_t bytes = status->byte_count_total;
	inf("Backed up %" PRIu64 " record(s), %u secondary index(es), %u UDF file(s), "
			"%" PRIu64 " byte(s) in total (~%" PRIu64 " B/rec)", records,
			status->index_count, status->udf_count, bytes,
			records == 0 ? 0 : bytes / records);

	if (mach_fd != NULL && (fprintf(mach_fd,
					"SUMMARY:%" PRIu64 ":%u:%u:%" PRIu64 ":%" PRIu64 "\n",
					records, status->index_count, status->udf_count, bytes,
					records == 0 ? 0 : bytes / records) < 0 ||
				fflush(mach_fd) == EOF)) {
		err_code("Error while writing machine-readable summary");
		res = EXIT_FAILURE;
	}

cleanup2:
	if (mach_fd != NULL) {
		fclose(mach_fd);
	}

	if (res == EXIT_FAILURE) {
		backup_status_destroy(status);
		cf_free(status);
		status = RUN_BACKUP_FAILURE;
	}

cleanup1:
	pop_backup_globals();

	return res == EXIT_FAILURE ? RUN_BACKUP_FAILURE : status;
}

/*
 * Stops the program
 */
static void
stop(void)
{
	backup_status_stop(get_g_backup_conf(), get_g_backup_status());
}

/*
 * Checks if the program has been stopped
 */
static bool
has_stopped(void)
{
	return backup_status_has_stopped(get_g_backup_status());
}

static void
set_sigaction(void (*sig_hand)(int))
{
	ver("setting sigaction for SIGINT and SIGTERM");
	sigset_t mask;
	sigemptyset(&mask);
	struct sigaction sa = {
		.sa_handler = sig_hand,
		.sa_mask = mask,
		.sa_flags = 0
	};
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void
push_backup_globals(backup_config_t* conf, backup_status_t* status)
{
	_Atomic(backup_config_t*) atom_conf;
	atomic_init(&atom_conf, conf);

	_Atomic(backup_status_t*) atom_status;
	atomic_init(&atom_status, status);

	backup_globals_t cur_globals = {
		.conf = atom_conf,
		.status = atom_status
	};
	as_vector_append(&g_globals, &cur_globals);
}

static void
pop_backup_globals()
{
	as_vector_remove(&g_globals, g_globals.size - 1);
}

static void
set_global_status(backup_status_t* status)
{
	backup_globals_t* cur_globals =
		(backup_globals_t*) as_vector_get(&g_globals, g_globals.size - 1);
	cur_globals->status = status;
}

/*
 * Estimates the number of remaining bytes left to back up for a directory
 * backup.
 */
static uint64_t
directory_backup_remaining_estimate(const backup_config_t* conf,
		backup_status_t* status)
{
	uint64_t rec_count_estimate = status->rec_count_estimate;
	uint64_t rec_count_total = status->rec_count_total;

	if (rec_count_total == 0) {
		return conf->file_limit;
	}

	pthread_mutex_lock(&status->committed_count_mutex);
	uint64_t rec_count_total_committed = status->rec_count_total_committed;
	uint64_t byte_count_total_committed = status->byte_count_total_committed;
	pthread_mutex_unlock(&status->committed_count_mutex);

	uint64_t rec_remain = rec_count_total > rec_count_estimate ? 0 :
		rec_count_estimate - rec_count_total;
	uint64_t rec_size = rec_count_total_committed == 0 ? 0 :
		byte_count_total_committed / rec_count_total_committed;

	ver("%" PRIu64 " remaining record(s), %" PRIu64 " B/rec average size", rec_remain,
			rec_size);

	return rec_remain * rec_size;
}

/*
 * To be called after data has been written to the io_proxy. Checks if any data
 * was written to the file, and if so, updates the global byte counts.
 *
 * This method should only be called in directory mode.
 */
static int
update_file_pos(io_write_proxy_t* fd, uint64_t* byte_count_file,
		uint64_t* byte_count_job, _Atomic(uint64_t)* byte_count_total)
{
	int64_t pos = io_write_proxy_bytes_written(fd);
	if (pos < 0) {
		err("Failed to get the file position");
		return -1;
	}
	uint64_t diff = (uint64_t) pos - *byte_count_file;

	*byte_count_file = (uint64_t) pos;
	*byte_count_job += diff;
	*byte_count_total += diff;

	return 0;
}

/*
 * To be called after data has been written to the shared io_proxy. Checks if any
 * data was written to the file, and if so, updates the global byte counts.
 *
 * This must be called while holding the file_write_mutex lock or when it is
 * known that this thread is the only one modifying byte_count_total.
 */
static int
update_shared_file_pos(io_write_proxy_t* fd, _Atomic(uint64_t)* byte_count_total)
{
	int64_t pos = io_write_proxy_bytes_written(fd);
	if (pos < 0) {
		err("Failed to get the file position");
		return -1;
	}

	*byte_count_total = (uint64_t) pos;

	return 0;
}

/*
 * add bjc->fd to the file queue, returning true if the file was successfully
 * added, and false if it wasn't (in this case the file is closed in abort mode)
 */
static bool
queue_file(backup_job_context_t *bjc)
{
	// add the fd to the queue
	queued_backup_fd_t q = {
		.fd = bjc->fd,
		.rec_count_file = bjc->rec_count_file,
		.byte_count_file = bjc->byte_count_file
	};

	int push_res = cf_queue_push_unique(bjc->file_queue, &q);

	if (push_res == CF_QUEUE_OK) {
		int64_t file_size = io_write_proxy_bytes_written(bjc->fd);
		ver("File %s size is %" PRId64 ", pushing to the queue",
				io_proxy_file_path(bjc->fd), file_size);
		return true;
	}
	// cf_queue_push_unique returns -2 to indicate that the item already exists
	else if (push_res == -2) {
		ver("File %s already exists in the queue",
				io_proxy_file_path(bjc->fd));
		return true;
	}

	// if pushing to the queue failed, close the file in abort mode and
	// abort the backup
	ver("Could not commit file %s to queue, aborting backup",
			io_proxy_file_path(bjc->fd));
	backup_status_abort_backup(bjc->status);

	io_proxy_close2(bjc->fd, FILE_PROXY_ABORT);
	return false;
}

/*
 * Closes a backup file and frees the associated I/O buffer.
 *
 * @param fd      The file descriptor of the backup file to be closed.
 */
static bool
close_file(io_write_proxy_t *fd)
{
	ver("Closing backup file");

	int res = io_proxy_close2(fd, FILE_PROXY_EOF);
	if (res != 0) {
		err("Error while closing backup io proxy");
		return false;
	}

	return true;
}

/*
 * Initializes a backup file.
 *
 *   - Creates the backup file.
 *   - Allocates an I/O buffer for it.
 *   - Writes the version header and meta data (e.g., the namespace) to the backup file.
 *
 * @param file_path   The path of the backup file to be created.
 * @param ns          The namespace that is being backed up.
 * @param disk_space  An estimate of the required disk space for the backup file.
 * @param fd          The file descriptor of the created backup file.
 * @param c_opt       The compression mode to be used on the file.
 * @param e_opt       The encryption mode to be used on the file.
 *
 * @result            `true`, if successful.
 */
static bool
open_file(const char *file_path, const char *ns, uint64_t disk_space,
		io_write_proxy_t *fd, compression_opt c_opt, int32_t compression_level,
		encryption_opt e_opt, encryption_key_t* pkey)
{
	const char* real_path;

	ver("Opening backup file %s", file_path);

	if (file_path == NULL) {
		ver("Backup up to \"/dev/null\" for estimate");

		real_path = "/dev/null";

		if (io_write_proxy_init(fd, real_path, disk_space) != 0) {
			return false;
		}
	}
	else if (file_proxy_is_std_path(file_path)) {
		ver("Backup up to stdout");

		real_path = "stdout";

		if (io_write_proxy_init(fd, file_path, disk_space) != 0) {
			return false;
		}
	}
	else {
		ver("Creating backup file at %s", file_path);

		real_path = file_path;

		if (io_write_proxy_init(fd, file_path, disk_space) != 0) {
			return false;
		}
	}

	ver("Initializing backup file %s", file_path);

	io_proxy_init_compression(fd, c_opt);
	if (c_opt != IO_PROXY_COMPRESS_NONE &&
			io_proxy_set_compression_level(fd, compression_level) != 0) {
		goto cleanup1;
	}
	io_proxy_init_encryption(fd, pkey, e_opt);

	if (io_proxy_printf(fd, "Version " VERSION_3_1 "\n") < 0) {
		err("Error while writing header to backup file %s", real_path);
		goto cleanup1;
	}

	if (io_proxy_printf(fd, META_PREFIX META_NAMESPACE " %s\n", escape(ns)) < 0) {
		err("Error while writing meta data to backup file %s", real_path);
		goto cleanup1;
	}

	return true;

cleanup1:
	close_file(fd);
	return false;
}

/*
 * Wrapper around close_file(). Used when backing up to a directory.
 *
 * @param bjc  The backup job context of the backup thread that's closing the backup file.
 *
 * @result     `true`, if successful.
 */
static bool
close_dir_file(backup_job_context_t *bjc)
{
	bool ret = true;

	if (bjc->fd == NULL) {
		err("Attempting to close a NULL file descriptor");
		return false;
	}

	// flush the file before calculating the size
	if (io_proxy_flush(bjc->fd) == EOF) {
		err("Error while flushing backup file %s", io_proxy_file_path(bjc->fd));
		ret = false;
	}
	int64_t file_size = io_write_proxy_bytes_written(bjc->fd);

	if (!ret || (uint64_t) file_size < bjc->conf->file_limit) {
		return queue_file(bjc) && ret;
	}

	pthread_mutex_lock(&bjc->status->committed_count_mutex);
	bjc->status->rec_count_total_committed += (int64_t) bjc->rec_count_file;
	bjc->status->byte_count_total_committed += file_size;
	pthread_mutex_unlock(&bjc->status->committed_count_mutex);

	ver("File size is %" PRId64 " for %s", file_size, io_proxy_file_path(bjc->fd));

	if (!close_file(bjc->fd)) {
		stop();
		queue_file(bjc);
		return false;
	}

	cf_free(bjc->fd);
	bjc->fd = NULL;

	return true;
}

/*
 * Wrapper around open_file(). Used when backing up to a directory.
 *
 *   - Generates a backup file name.
 *   - Estimates the disk space required for all remaining backup files based on the average
 *        record size seen so far.
 *   - Invokes open_file().
 *
 * @param bjc  The backup job context of the backup thread that's creating the backup file.
 *
 * @result     `true` if successful, `false` otherwise
 */
static bool
open_dir_file(backup_job_context_t *bjc)
{
	queued_backup_fd_t queued_fd;
	if (cf_queue_pop(bjc->file_queue, &queued_fd, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {

		ver("Found %s in queue", io_proxy_file_path(queued_fd.fd));

		bjc->fd = queued_fd.fd;
		bjc->rec_count_file = queued_fd.rec_count_file;
		bjc->byte_count_file = queued_fd.byte_count_file;
	}
	else {
		uint64_t remaining_bytes =
			directory_backup_remaining_estimate(bjc->conf, bjc->status);

		if (file_proxy_path_type(bjc->conf->directory) == FILE_PROXY_TYPE_LOCAL) {
			uint64_t disk_space = disk_space_remaining(bjc->conf->directory);
			if (disk_space < remaining_bytes) {
				inf("Warning: %" PRIu64 " bytes of disk space remaining, but "
						"the expected total backup size is %" PRIu64,
						disk_space, remaining_bytes);
			}
		}

		bjc->fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));

		if (bjc->fd == NULL) {
			err("Failed to malloc %zu bytes for io_write_proxy_t",
					sizeof(io_write_proxy_t));
			return false;
		}

		uint64_t file_path_size = (size_t) snprintf(NULL, 0, "%s/%s_%05d.asb",
				bjc->conf->directory,
				bjc->conf->prefix == NULL ? bjc->conf->ns : bjc->conf->prefix,
				0);

		char* file_path = (char*) cf_malloc((file_path_size + 1) * sizeof(char));
		if (file_path == NULL) {
			cf_free(bjc->fd);
			bjc->fd = NULL;
			err("Unable to malloc file path name of length %" PRIu64, file_path_size);
			return false;
		}

		pthread_mutex_lock(&bjc->status->dir_file_init_mutex);
		int64_t file_count = bjc->status->file_count;

		snprintf(file_path, file_path_size + 1, "%s/%s_%05" PRId64 ".asb",
				bjc->conf->directory,
				bjc->conf->prefix == NULL ? bjc->conf->ns : bjc->conf->prefix,
				file_count);

		if (!open_file(file_path, bjc->conf->ns,
					MIN(remaining_bytes, bjc->conf->file_limit), bjc->fd,
					bjc->conf->compress_mode, bjc->conf->compression_level,
					bjc->conf->encrypt_mode, bjc->conf->pkey)) {
			pthread_mutex_unlock(&bjc->status->dir_file_init_mutex);
			err("Failed to open directory file %s", file_path);
			cf_free(bjc->fd);
			bjc->fd = NULL;
			cf_free(file_path);
			return false;
		}
		cf_free(file_path);

		bjc->rec_count_file = 0;
		bjc->byte_count_file = 0;
		if (update_file_pos(bjc->fd, &bjc->byte_count_file, &bjc->byte_count_job,
					&bjc->status->byte_count_total) < 0) {
			pthread_mutex_unlock(&bjc->status->dir_file_init_mutex);
			cf_free(bjc->fd);
			bjc->fd = NULL;
			err("New directory file %s, failed to get file position", file_path);
			return false;
		}

		bjc->status->file_count = file_count + 1;
		pthread_mutex_unlock(&bjc->status->dir_file_init_mutex);
	}

	return true;
}

/*
 * Loads the backup state from the file path given and returns a pointer to it.
 */
static backup_state_t*
load_backup_state(const char* state_file_path)
{
	backup_state_t* state = (backup_state_t*) cf_malloc(sizeof(backup_state_t));

	if (state == NULL) {
		err("Failed to allocate %zu bytes for backup state struct",
				sizeof(backup_state_t));
		return NULL;
	}

	if (backup_state_load(state, state_file_path) != 0) {
		err("Failed to load backup state file %s", state_file_path);
		cf_free(state);
		return NULL;
	}

	return state;
}

static void
save_job_state(const backup_thread_args_t* args)
{
	const as_partition_filter* filter = &args->filter;

	if (filter->parts_all == NULL) {
		pthread_mutex_lock(&args->status->stop_lock);
		backup_state_t* state = backup_status_get_backup_state(args->status);

		if (state == BACKUP_STATE_ABORTED) {
			pthread_mutex_unlock(&args->status->stop_lock);
			return;
		}

		for (uint32_t part_id = filter->begin; part_id < filter->begin + filter->count;
				part_id++) {
			backup_state_mark_not_started(state, (uint16_t) part_id);
		}

		pthread_mutex_unlock(&args->status->stop_lock);
	}
	else {
		// if we are saving a resumed backup job, parts_all will have been
		// initialized even for the backup jobs still on the queue, and we want
		// to preserve the status of those states
		backup_status_save_scan_state(args->status, filter->parts_all);
	}
}

static bool
complete_job(cf_queue* complete_queue, const backup_thread_args_t* args)
{
	if (cf_queue_push(complete_queue, args) != CF_QUEUE_OK) {
		err("Failed to push completed scan job args to complete queue");
		return false;
	}
	else if (args->filter.parts_all != NULL) {
		as_partitions_status_reserve(args->filter.parts_all);
	}

	return true;
}

/*
 * Initializes the as_scan object according to the backup job context.
 */
static as_scan*
prepare_scan(as_scan* scan, const backup_job_context_t* bjc)
{
	if (as_scan_init(scan, bjc->conf->ns, bjc->status->set) == NULL) {
		return NULL;
	}
	const backup_config_t* conf = bjc->conf;

	scan->deserialize_list_map = false;
	scan->paginate = true;
	scan->no_bins = bjc->conf->no_bins;

	if (conf->bin_list != NULL && !init_scan_bins(conf->bin_list, scan)) {
		err("Error while setting scan bin list");
		as_scan_destroy(scan);
		return NULL;
	}

	return scan;
}

/*
 * Callback function for the cluster node scan. Passed to `aerospike_scan_partitions()`.
 *
 * @param val   The record to be processed. `NULL` indicates scan completion.
 * @param cont  The user-specified context passed to `aerospike_scan_partitions()`.
 *
 * @result      `false` to abort the scan, `true` to keep going.
 */
static bool
scan_callback(const as_val *val, void *cont)
{
	backup_job_context_t *bjc = cont;

	if (val == NULL) {
		ver("Received scan end marker");

		return true;
	}

	if (backup_status_has_stopped(bjc->status)) {
		ver("Callback detected failure");

		bjc->interrupted = true;
		return false;
	}

	as_record *rec = as_record_fromval(val);

	if (rec == NULL) {
		err("Received value of unexpected type %d", (int32_t)as_val_type(val));
		bjc->interrupted = true;
		return false;
	}

	if (rec->key.ns[0] == 0) {
		err("Received record without namespace, generation %d, %d bin(s)", rec->gen,
				rec->bins.size);
		bjc->interrupted = true;
		return false;
	}

	// backing up to a directory: switch backup files when reaching the file size limit
	if (bjc->conf->directory != NULL && bjc->byte_count_file >= bjc->conf->file_limit) {
		ver("Crossed %" PRIu64 " bytes, switching backup file", bjc->conf->file_limit);

		if (!close_dir_file(bjc)) {
			err("Error while closing old backup file");
			// set fd to NULL so that worker threads
			// will not attempt to close this file again
			// if they do, this can cause problems like...
			// if this close fails, the file will be added to bjc->file_queue
			// which is saved to the state file. If the next close in
			// worker thread succeeds, then the file will
			// be cleaned up in the successful close call
			// and when the state file logic at cleanup 6
			// tries to close the file from the queue it will access
			// freed memory/uninitialized fields.
			bjc->fd = NULL;
			bjc->interrupted = true;
			return false;
		}

		if (!open_dir_file(bjc)) {
			err("Error while opening new backup file");
			bjc->interrupted = true;
			return false;
		}
	}

	// backing up to a single backup file: allow one thread at a time to write
	if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
		safe_lock(&bjc->status->file_write_mutex);
	}

	bool ok;
	if (bjc->conf->estimate) {
		uint32_t sample_idx = (*bjc->n_samples)++;
		// should never happen, but just to ensure we don't write past the end
		// of the sample buffer, check that we don't exceed estimate_samples
		if (sample_idx >= bjc->conf->n_estimate_samples) {
			*bjc->n_samples = bjc->conf->n_estimate_samples;
			safe_unlock(&bjc->status->file_write_mutex);
			// don't abort the scan, as this will cause a broken pipe error on
			// the server. Let the scan gracefully terminate.
			return true;
		}

		int64_t prev_pos = io_write_proxy_absolute_pos(bjc->fd);
		ok = bjc->status->encoder.put_record(bjc->fd, bjc->conf->compact, rec);
		int64_t post_pos = io_write_proxy_absolute_pos(bjc->fd);

		if (prev_pos < 0 || post_pos < 0) {
			err("Error reading the file position from the io_proxy while running estimate");
			ok = false;
		}

		bjc->samples[sample_idx] = (uint64_t) (post_pos - prev_pos);
	}
	else {
		ok = bjc->status->encoder.put_record(bjc->fd, bjc->conf->compact, rec);
	}

	++bjc->rec_count_file;
	++bjc->rec_count_job;
	++bjc->status->rec_count_total;

	if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
		if (update_shared_file_pos(bjc->fd, &bjc->status->byte_count_total) < 0) {
			ok = false;
		}
	}
	else {
		if (update_file_pos(bjc->fd, &bjc->byte_count_file, &bjc->byte_count_job,
					&bjc->status->byte_count_total) < 0) {
			ok = false;
		}
	}

	if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
		safe_unlock(&bjc->status->file_write_mutex);
	}

	if (!ok) {
		err("Error while storing record in backup file, aborting scan. The "
				"backup state is currently unrecoverable in this state, so "
				"backup resumption is not possible.");
		backup_status_abort_backup(bjc->status);
		bjc->interrupted = true;
		return false;
	}

	if (bjc->conf->bandwidth > 0) {
		safe_lock(&bjc->status->bandwidth_mutex);

		while (bjc->status->byte_count_total >=
				bjc->status->byte_count_limit &&
				!backup_status_has_stopped(bjc->status)) {
			safe_wait(&bjc->status->bandwidth_cond,
					&bjc->status->bandwidth_mutex);
		}

		safe_unlock(&bjc->status->bandwidth_mutex);
	}

	return true;
}

/*
 * Stores secondary index information.
 *
 *   - Retrieves the information from the cluster.
 *   - Parses the information.
 *   - Invokes backup_encoder.put_secondary_index() to store it.
 *
 * @param bjc  The backup job context of the backup thread that's backing up the indexes.
 *
 * @result     `true`, if successful.
 */
static bool
process_secondary_indexes(backup_job_context_t *bjc)
{
	ver("Processing secondary indexes");

	bool res = false;
	char* b64_enable = ";b64=true";
	size_t value_size = sizeof "sindex-list:ns=" - 1 + strlen(bjc->conf->ns) + strlen(b64_enable) + 1;
	char value[value_size];
	snprintf(value, value_size, "sindex-list:ns=%s%s", bjc->conf->ns, b64_enable);
	
	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = TIMEOUT;

	char *resp =  NULL;
	as_error ae;

	if (aerospike_info_any(bjc->status->as, &ae, &policy, value, &resp) != AEROSPIKE_OK) {
		err("Error while retrieving secondary index info - code %d: %s at %s:%d", ae.code,
				ae.message, ae.file, ae.line);
		goto cleanup0;
	}

	char *info_str;

	if (as_info_parse_single_response(resp, &info_str) != AEROSPIKE_OK) {
		err("Error while parsing single info_str response");
		goto cleanup1;
	}

	size_t info_len = strlen(info_str);

	if (info_str[info_len - 1] == ';') {
		info_str[info_len - 1] = 0;
	}

	if (info_str[0] == 0) {
		inf("No secondary indexes");
		res = true;
		goto cleanup1;
	}

	as_vector info_vec;
	as_vector_inita(&info_vec, sizeof (void *), 25);
	split_string(info_str, ';', false, &info_vec);

	inf("Backing up %u secondary index(es)", info_vec.size);
	int32_t skipped = 0;

	char *clone = safe_strdup(info_str);
	index_param index;

	for (uint32_t i = 0; i < info_vec.size; ++i) {
		char *index_str = as_vector_get_ptr(&info_vec, i);

		if (!parse_index_info((char*) bjc->conf->ns, index_str, &index)) {
			err("Error while parsing secondary index info string %s", clone);
			goto cleanup2;
		}
		
		ver("Storing index %s", index.name);

		uint32_t n_sets = bjc->conf->set_list.size;
		if (n_sets == 0 || (index.set != NULL &&
					str_vector_contains(&bjc->conf->set_list, index.set))) {
			// backing up to a single backup file: allow one thread at a time to write
			if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
				safe_lock(&bjc->status->file_write_mutex);
			}

			bool ok = bjc->status->encoder.put_secondary_index(bjc->fd, &index);

			if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
				safe_unlock(&bjc->status->file_write_mutex);
			}

			if (!ok) {
				err("Error while storing secondary index in backup file");
				goto cleanup3;
			}

			if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
				if (update_shared_file_pos(bjc->fd, &bjc->status->byte_count_total) < 0) {
					err("Error while storing secondary index in backup file");
					goto cleanup3;
				}
			}
			else {
				if (update_file_pos(bjc->fd, &bjc->byte_count_file, &bjc->byte_count_job,
							&bjc->status->byte_count_total) < 0) {
					err("Error while storing secondary index in backup file");
					goto cleanup3;
				}
			}
		}
		else {
			++skipped;
		}

		as_vector_destroy(&index.path_vec);
	}

	bjc->status->index_count = info_vec.size;
	res = true;

	if (skipped > 0) {
		inf("Skipped %d index(es) with unwanted set(s)", skipped);
	}
	
	goto cleanup2;

cleanup3:
	as_vector_destroy(&index.path_vec);

cleanup2:
	as_vector_destroy(&info_vec);
	cf_free(clone);

cleanup1:
	cf_free(resp);

cleanup0:
	return res;
}

/*
 * Stores UDF files.
 *
 *   - Retrieves the UDF files from the cluster.
 *   - Invokes backup_encoder.put_udf_file() to store each of them.
 *
 * @param bjc  The backup job context of the backup thread that's backing up the UDF files.
 *
 * @result     `true`, if successful.
 */
static bool
process_udfs(backup_job_context_t *bjc)
{
	ver("Processing UDFs");

	bool res = false;

	as_udf_files files;
	as_udf_files_init(&files, MAX_UDF_FILES);

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = TIMEOUT;
	as_error ae;

	if (aerospike_udf_list(bjc->status->as, &ae, &policy, &files) != AEROSPIKE_OK) {
		err("Error while listing UDFs - code %d: %s at %s:%d", ae.code, ae.message, ae.file,
				ae.line);
		goto cleanup1;
	}

	if (files.size == MAX_UDF_FILES) {
		err("Too many UDF files (%u or more)", MAX_UDF_FILES);
		goto cleanup2;
	}

	inf("Backing up %u UDF file(s)", files.size);
	as_udf_file file;
	as_udf_file_init(&file);

	for (uint32_t i = 0; i < files.size; ++i) {
		ver("Fetching UDF file %u: %s", i + 1, files.entries[i].name);

		if (aerospike_udf_get(bjc->status->as, &ae, &policy, files.entries[i].name,
				files.entries[i].type, &file) != AEROSPIKE_OK) {
			err("Error while fetching UDF file %s - code %d: %s at %s:%d", files.entries[i].name,
					ae.code, ae.message, ae.file, ae.line);
			goto cleanup2;
		}

		// backing up to a single backup file: allow one thread at a time to write
		if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
			safe_lock(&bjc->status->file_write_mutex);
		}

		bool ok = bjc->status->encoder.put_udf_file(bjc->fd, &file);

		if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
			safe_unlock(&bjc->status->file_write_mutex);
		}

		if (!ok) {
			err("Error while storing UDF file in backup file");
			goto cleanup2;
		}

		if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
			if (update_shared_file_pos(bjc->fd, &bjc->status->byte_count_total) < 0) {
				err("Error while storing UDF file in backup file");
				goto cleanup2;
			}
		}
		else {
			if (update_file_pos(bjc->fd, &bjc->byte_count_file, &bjc->byte_count_job,
						&bjc->status->byte_count_total) < 0) {
				err("Error while storing UDF file in backup file");
				goto cleanup2;
			}
		}

		as_udf_file_destroy(&file);
		as_udf_file_init(&file);
	}

	bjc->status->udf_count = files.size;
	res = true;

cleanup2:
	as_udf_file_destroy(&file);

cleanup1:
	as_udf_files_destroy(&files);
	return res;
}

/*
 * Main backup worker thread function.
 *
 *   - Pops the backup_thread_args for a cluster node off the job queue.
 *   - Initializes a backup_job_context_t for that cluster node.
 *   - If backing up to a single file: uses the provided shared file descriptor,
 *       backup_thread_args.shared_fd.
 *   - If backing up to a directory: creates a new backup file by invoking
 *       open_dir_file().
 *   - If handling the first job from the queue: stores secondary index
 *       information and UDF file by invoking process_secondary_indexes() and
 *       process_udfs().
 *   - Initiates a node or partition scan with scan_callback() as the callback
 *       and the initialized backup_job_context_t as user-specified context.
 *
 * @param cont  The job queue.
 *
 * @result      `EXIT_SUCCESS` on success, `EXIT_FAILURE` otherwise.
 */
static void *
backup_thread_func(void *cont)
{
	ver("Entering backup thread 0x%" PRIx64, (uint64_t)pthread_self());

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;
	uint64_t backup_file_size;

	while (true) {
		if (has_stopped()) {
			ver("Backup thread detected failure");

			break;
		}

		backup_thread_args_t args;
		int32_t q_res = cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT);

		if (q_res == CF_QUEUE_EMPTY) {
			ver("Job queue is empty");

			res = (void *)EXIT_SUCCESS;
			break;
		}

		if (q_res != CF_QUEUE_OK) {
			err("Error while picking up backup job");
			stop();
			break;
		}

		backup_job_context_t bjc;
		as_scan* scan_ptr;
		bjc.conf = args.conf;
		bjc.status = args.status;
		bjc.interrupted = false;
		if (args.conf->output_file != NULL) {
			bjc.shared_fd = args.shared_fd;
		}
		else {
			bjc.file_queue = args.file_queue;
		}
		bjc.fd = NULL;
		bjc.rec_count_job = 0;
		bjc.byte_count_job = 0;
		bjc.samples = args.samples;
		bjc.n_samples = args.n_samples;

		if (args.filter.digest.init) {
			uint32_t id = as_partition_getid(args.filter.digest.value,
					bjc.status->as->cluster->n_partitions);
			uint32_t len = cf_b64_encoded_len(sizeof(args.filter.digest.value));
			char* str = cf_malloc(len + 1);
	
			cf_b64_encode(args.filter.digest.value, sizeof(args.filter.digest.value), str);
			str[len] = 0;
			sprintf(bjc.desc, "partition %u after %s", id, str);
			cf_free(str);
		}
		else if (args.filter.count > 0) {
			if (args.filter.count == 1) {
				sprintf(bjc.desc, "partition %u", args.filter.begin);
			}
			else {
				sprintf(bjc.desc, "%u partitions from %u to %u", args.filter.count,
						args.filter.begin, args.filter.begin + args.filter.count - 1);
			}
		}
		else {
			sprintf(bjc.desc, "whole namespace");
		}

		// backing up to a single backup file: use the provided shared file descriptor for
		// the current job
		if (bjc.conf->output_file != NULL || bjc.conf->estimate) {
			ver("Using shared file descriptor");

			bjc.fd = bjc.shared_fd;
		}
		// backing up to a directory: create the first backup file for the current job
		else if (bjc.conf->directory != NULL) {
			if (!open_dir_file(&bjc)) {
				err("Error while opening first backup file");
				stop();
				save_job_state(&args);
				break;
			}
		}

		if ((scan_ptr = prepare_scan(&bjc.scan, &bjc)) == NULL) {
			err("Failed to prepare scan object");
			stop();
			goto close_file;
		}

		// if we got the first job in the queue, take care of secondary indexes and UDF files
		if (args.first) {
			ver("Picked up first job, doing one shot work");

			if (io_proxy_printf(bjc.fd, META_PREFIX META_FIRST_FILE "\n") < 0) {
				err("Error while writing meta data to backup file");
				stop();
				goto close_file;
			}

			if (bjc.conf->output_file != NULL || bjc.conf->estimate) {
				if (update_shared_file_pos(bjc.fd, &bjc.status->byte_count_total) < 0) {
					err("Error while writing meta prefix header");
					stop();
					goto close_file;
				}
			}
			else {
				if (update_file_pos(bjc.fd, &bjc.byte_count_file, &bjc.byte_count_job,
							&bjc.status->byte_count_total) < 0) {
					err("Error while writing meta prefix header");
					stop();
					goto close_file;
				}
			}

			if (bjc.conf->no_indexes) {
				ver("Skipping index backup");
			} else if (!process_secondary_indexes(&bjc)) {
				err("Error while processing secondary indexes");
				stop();
				goto close_file;
			}

			if (bjc.conf->no_udfs) {
				ver("Skipping UDF backup");
			} else if (!process_udfs(&bjc)) {
				err("Error while processing UDFs");
				stop();
				goto close_file;
			}

			if (bjc.conf->estimate) {
				bjc.status->header_size = (uint64_t) io_write_proxy_absolute_pos(bjc.fd);
			}

			ver("Signaling one shot work completion");

			// all other jobs wait until the first job is done with the secondary indexes and UDF files
			backup_status_signal_one_shot(bjc.status);
		} else {
			ver("Ensuring one shot work completion");

			backup_status_wait_one_shot(bjc.status);

			if (backup_status_has_stopped(bjc.status)) {
				goto close_file;
			}
		}

		inf("Starting backup for %s", bjc.desc);

		as_error ae;
		as_status status;

		if (bjc.conf->no_records) {
			ver("Skipping record backup");
			status = AEROSPIKE_OK;
		} else {
			status = aerospike_scan_partitions(bjc.status->as, &ae,
					bjc.status->policy, &bjc.scan, &args.filter, scan_callback,
					&bjc);

			// update args.filter with the newly created parts_all object in
			// scan_partitions if it wasn't initialized in args.filter already
			if (args.filter.parts_all == NULL) {
				as_partitions_status_reserve(bjc.scan.parts_all);
				as_partition_filter_set_partitions(&args.filter, bjc.scan.parts_all);
			}

			// if we're running an estimate, this is the only thread, so update
			// the file position before giving the update
			if (bjc.conf->estimate) {
				if (io_proxy_flush(bjc.fd) == EOF) {
					err("Error while flushing backup file %s", io_proxy_file_path(bjc.fd));
					stop();
					goto close_file;
				}

				if (update_shared_file_pos(bjc.fd, &bjc.status->byte_count_total) < 0) {
					err("Error updating shared file pos of backup file %s", io_proxy_file_path(bjc.fd));
					stop();
					goto close_file;
				}
			}
		}

		if (status != AEROSPIKE_OK) {
			if (ae.code == AEROSPIKE_OK) {
				inf("Abort scan for %s", bjc.desc);
			}
			else if (ae.code == AEROSPIKE_ERR_FAIL_FORBIDDEN) {
				err("Failed to start scan job for %s, potentially not enough "
						"available scan/query threads on the server - "
						"code %d: %s at %s:%d",
						bjc.desc, ae.code, ae.message, ae.file, ae.line);
			}
			else {
				err("Error while running scan for %s - code %d: %s at %s:%d", bjc.desc,
						ae.code, ae.message, ae.file, ae.line);
			}

			stop();
			goto close_file;
		}

		if (bjc.conf->output_file != NULL || bjc.conf->estimate) {
			backup_file_size = bjc.status->byte_count_total;
		}
		else {
			backup_file_size = bjc.byte_count_job;
		}

		if (!bjc.interrupted) {
			inf("Completed backup for %s, records: %" PRIu64 ", size: %" PRIu64 " "
					"(~%" PRIu64 " B/rec)", bjc.desc, bjc.rec_count_job,
					backup_file_size,
					bjc.rec_count_job == 0 ? 0 : backup_file_size / bjc.rec_count_job);
		}
		else {
			inf("Backup of %s interrupted, records: %" PRIu64 ", size: %" PRIu64 " "
					"(~%" PRIu64 " B/rec)", bjc.desc, bjc.rec_count_job,
					backup_file_size,
					bjc.rec_count_job == 0 ? 0 : backup_file_size / bjc.rec_count_job);

			stop();
		}

close_file:
		// backing up to a single backup file: do nothing
		if (bjc.conf->output_file != NULL) {
			ver("Not closing shared file descriptor");

			bjc.fd = NULL;
		}
		// backing up to a directory: close the last backup file for the current job
		else if (bjc.conf->directory != NULL) {
			if (!close_dir_file(&bjc)) {
				err("Error while closing backup file");
				stop();
			}
		}

		if (scan_ptr == NULL || scan_ptr->parts_all == NULL) {
			// it's possible scan_ptr->parts_all == NULL and we haven't failed
			// if no_records is set
			if (backup_config_can_resume(args.conf) &&
					backup_status_has_stopped(args.status)) {
				save_job_state(&args);
			}
		}
		else if (backup_config_can_resume(args.conf) &&
				backup_status_has_stopped(args.status)) {
			backup_status_save_scan_state(args.status, scan_ptr->parts_all);
		}
		else if (!complete_job(args.complete_queue, &args)) {
			stop();
			if (backup_config_can_resume(args.conf)) {
				backup_status_save_scan_state(args.status, scan_ptr->parts_all);
			}
		}

		if (args.filter.parts_all != NULL) {
			as_partitions_status_release(args.filter.parts_all);
		}

		as_scan_destroy(scan_ptr);
	}

	if (res != (void *)EXIT_SUCCESS) {
		ver("Indicating failure to other threads");

		stop();
	}

	ver("Leaving backup thread");

	return res;
}

/*
 * Main counter thread function.
 *
 *   - Outputs human-readable and machine-readable progress information.
 *   - If throttling is active: increases the I/O quota every second.
 *
 * @param cont  The arguments for the thread, passed as a counter_thread_args.
 *
 * @result      Always `EXIT_SUCCESS`.
 */
static void *
counter_thread_func(void *cont)
{
	ver("Entering counter thread 0x%" PRIx64, (uint64_t)pthread_self());

	counter_thread_args *args = (counter_thread_args *)cont;
	const backup_config_t *conf = args->conf;
	backup_status_t *status = args->status;

	cf_clock prev_ms = cf_getms();

	uint32_t iter = 0;
	cf_clock print_prev_ms = prev_ms;
	uint64_t print_prev_bytes = status->byte_count_total;
	uint64_t print_prev_recs = status->rec_count_total;

	uint64_t mach_prev_recs = print_prev_recs;

	while (true) {
		backup_status_sleep_for(status, 1);

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		prev_ms = now_ms;

		uint64_t n_recs = conf->estimate ? conf->n_estimate_samples :
			status->rec_count_estimate;

		if (n_recs > 0) {
			uint64_t now_bytes = status->byte_count_total;
			uint64_t now_recs = status->rec_count_total;

			int32_t percent = (int32_t)(now_recs * 100 / n_recs);

			// rec_count_estimate may be a little off, make sure that we only print up to 99%
			if (percent < 100) {
				if (iter++ % 10 == 0) {
					uint32_t ms = (uint32_t)(now_ms - print_prev_ms);
					print_prev_ms = now_ms;

					uint64_t bytes = now_bytes - print_prev_bytes;
					uint64_t recs = now_recs - print_prev_recs;

					int32_t eta = recs == 0 ? -1 :
						(int32_t)(((uint64_t) n_recs - now_recs) *
								ms / recs / 1000);
					char eta_buff[ETA_BUF_SIZE];
					format_eta(eta, eta_buff, sizeof eta_buff);

					print_prev_recs = now_recs;
					print_prev_bytes = now_bytes;

					inf("%d%% complete (~%" PRIu64 " KiB/s, ~%" PRIu64 " rec/s, "
							"~%" PRIu64 " B/rec)",
							percent, ms == 0 ? 0 : bytes * 1000 / 1024 / ms,
							ms == 0 ? 0 : recs * 1000 / ms, recs == 0 ? 0 : bytes / recs);

					if (eta >= 0) {
						inf("~%s remaining", eta_buff);
					}
				}

				if (args->mach_fd != NULL) {
					uint64_t recs = now_recs - mach_prev_recs;

					int32_t eta = recs == 0 ? -1 :
						(int32_t)(((uint64_t) n_recs - now_recs) *
								ms / recs / 1000);
					char eta_buff[ETA_BUF_SIZE];
					format_eta(eta, eta_buff, sizeof eta_buff);

					mach_prev_recs = now_recs;

					if ((fprintf(args->mach_fd, "PROGRESS:%d\n", percent) < 0 ||
							fflush(args->mach_fd) == EOF)) {
						err_code("Error while writing machine-readable progress");
					}

					if (eta >= 0 && (fprintf(args->mach_fd, "REMAINING:%s\n", eta_buff) < 0 ||
							fflush(args->mach_fd) == EOF)) {
						err_code("Error while writing machine-readable remaining time");
					}
				}
			}
		}

		safe_lock(&status->bandwidth_mutex);

		if (conf->bandwidth > 0) {
			if (ms > 0) {
				status->byte_count_limit = 
					status->byte_count_limit + conf->bandwidth * 1000 / ms;
			}

			safe_signal(&status->bandwidth_cond);
		}

		bool tmp_stop = backup_status_has_finished(status) ||
			backup_status_has_stopped(status);
		safe_unlock(&status->bandwidth_mutex);

		if (tmp_stop) {
			break;
		}
	}

	ver("Leaving counter thread");

	return (void *)EXIT_SUCCESS;
}

/*
 * Parses a `bin-name[,bin-name[,...]]` string of bin names and initializes a scan from it.
 *
 * @param bin_list  The string to be parsed.
 * @param scan      The scan to be initialized.
 *
 * @result          `true`, if successful.
 */
static bool
init_scan_bins(char *bin_list, as_scan *scan)
{
	bool res = false;
	char *clone = safe_strdup(bin_list);
	as_vector bin_vec;
	as_vector_inita(&bin_vec, sizeof (void *), 25);

	if (clone[0] == 0) {
		err("Empty bin list");
		goto cleanup1;
	}

	split_string(clone, ',', true, &bin_vec);

	as_scan_select_init(scan, (uint16_t)bin_vec.size);

	for (uint32_t i = 0; i < bin_vec.size; ++i) {
		if (!as_scan_select(scan, as_vector_get_ptr(&bin_vec, i))) {
			err("Error while selecting bin %s", (char *)as_vector_get_ptr(&bin_vec, i));
			goto cleanup1;
		}
	}

	res = true;

cleanup1:
	as_vector_destroy(&bin_vec);
	cf_free(clone);
	return res;
}

/*
 * Reads the backup progress statuses from the state file and narrows the
 * partition ranges/digests in the partition_filters vector.
 *
 * This method also validates the partition ranges/digests, i.e. ensures that
 * they cover all partitions in the backup file, failing if that is not the
 * case.
 */
static bool
narrow_partition_filters(backup_state_t* state, as_vector* partition_filters,
		const backup_config_t* conf)
{
	for (uint32_t i = 0; i < partition_filters->size; i++) {
		as_partition_filter* filter = (as_partition_filter*)
			as_vector_get(partition_filters, i);
		as_partitions_status* parts_all;
		as_digest_value digest_val;

		parts_all = cf_malloc(sizeof(as_partitions_status) +
				filter->count * sizeof(as_partition_status));
		if (parts_all == NULL) {
			err("Unable to malloc %zu bytes for as_partitions_status\n",
					sizeof(as_partitions_status) +
					filter->count * sizeof(as_partition_status));
			return false;
		}

		parts_all->ref_count = 1;
		parts_all->part_begin = filter->begin;
		parts_all->part_count = filter->count;
		parts_all->done = false;
		parts_all->retry = false;

		for (uint16_t part_id = filter->begin; part_id < filter->begin + filter->count;
				part_id++) {
			uint8_t status = backup_state_get_status(state, part_id, digest_val);
			as_partition_status* pstat = &parts_all->parts[part_id - filter->begin];
			pstat->part_id = part_id;
			pstat->retry = false;
			pstat->bval = 0;

			switch (status) {
				case BACKUP_STATE_STATUS_NONE:
					if (!backup_config_allow_uncovered_partitions(conf)) {
						err("Partition %u was not saved in the backup state file", part_id);
						cf_free(parts_all);
						return false;
					}
					else {
						memset(pstat->digest.value, 0, sizeof(as_digest_value));
						*((uint16_t*) pstat->digest.value) = part_id;
						pstat->digest.init = true;
					}

					break;

				case BACKUP_STATE_STATUS_NOT_STARTED:
				case BACKUP_STATE_STATUS_COMPLETE_EMPTY:
					if (filter->digest.init) {
						memcpy(pstat->digest.value, digest_val, sizeof(as_digest_value));
						pstat->digest.init = true;
					}
					else {
						pstat->digest.init = false;
					}

					break;

				case BACKUP_STATE_STATUS_INCOMPLETE:
				case BACKUP_STATE_STATUS_COMPLETE:
					// if the partition filter has an after-digest, verify that
					// it is no greater than the digest we're resuming from
					if (filter->digest.init) {
						// digests are iterated over in reverse order, hence the < 0
						if (memcmp(filter->digest.value, digest_val,
									sizeof(as_digest_value)) < 0) {
							uint32_t len = cf_b64_encoded_len(sizeof(as_digest_value));
							char* digest_str = alloca(len + 1);
							char* digest_val_str = alloca(len + 1);
							cf_b64_encode(filter->digest.value, sizeof(as_digest_value),
									digest_str);
							digest_str[len] = '\0';
							cf_b64_encode(digest_val, sizeof(as_digest_value),
									digest_val_str);
							digest_val_str[len] = '\0';

							err("Digest value %s is below the after-digest %s of "
									"partition %u", digest_str, digest_val_str, part_id);

							cf_free(parts_all);
							return false;
						}
					}

					memcpy(pstat->digest.value, digest_val, sizeof(as_digest_value));
					pstat->digest.init = true;
					break;
			}

			backup_state_clear_partition(state, part_id);
		}

		as_partition_filter_set_partitions(filter, parts_all);
	}

	// check to see that every partition in the backup file was covered by some
	// partition filter
	for (uint16_t part_id = 0; part_id < MAX_PARTITIONS; part_id++) {
		as_digest_value digest_val;
		uint8_t status = backup_state_get_status(state, part_id, digest_val);
		if (status != BACKUP_STATE_STATUS_NONE) {
			err("Error while narrowing partition filters from backup state file: "
					"partition %u was not covered by any partition range",
					part_id);
			return false;
		}
	}

	return true;
}

static distr_stats_t
calc_record_stats(uint64_t* samples, uint32_t n_samples)
{
	if (n_samples > 1) {
		uint64_t total = 0.0;
		for (uint32_t i = 0; i < n_samples; i++) {
			total += samples[i];
		}

		double exp_value = (double) total / n_samples;

		double variance = 0;
		for (uint32_t i = 0; i < n_samples; i++) {
			double diff = (double) samples[i] - exp_value;
			variance += diff * diff;
		}
		variance /= n_samples - 1;

		return (distr_stats_t) {
			.total = total,
			.mean = exp_value,
			.variance = variance
		};
	}
	else {
		return (distr_stats_t) { 0, 0, 0 };
	}
}

/*
 * Estimates the total backup file size given:
 *
 * @param samples             The list of record sizes calculated in the estimate run.
 * @param n_samples           The number of samples recorded in the samples list.
 * @param header_size         The size of the backup file metadata section.
 * @param estimate_byte_count The total size in bytes of the estimate backup file.
 * @param rec_count_estimate  The estimated total number of records in the namespace.
 * @param confidence_level    The upper-bound confidence interval level to calculate (out of 1).
 */
static uint64_t
estimate_total_backup_size(uint64_t* samples, uint32_t n_samples,
		uint64_t header_size, uint64_t estimate_byte_count,
		uint64_t rec_count_estimate, double confidence_level)
{
	distr_stats_t rec_stats = calc_record_stats(samples, n_samples);

	double z = confidence_z(confidence_level, rec_count_estimate);
	double compression_ratio = (double) estimate_byte_count /
		(double) (rec_stats.total + header_size);
	uint64_t est_backup_size = header_size +
		(uint64_t) ceil((double) rec_count_estimate * (
					compression_ratio * rec_stats.mean +
					(n_samples == 0 ? 0 :
					 (z * sqrt(rec_stats.variance / (double) n_samples)))));

	return est_backup_size;
}

/*
 * Estimates and outputs the average record size based on the given record size samples.
 *
 * The estimate is the upper bound for a 99.9999% confidence interval. The 99.9999% is where the
 * 4.7 constant comes from.
 *
 * @param mach_fd             The file descriptor for the machine-readable output.
 * @param samples             The array of record size samples.
 * @param n_samples           The number of elements in the sample array.
 * @param header_size         The size of the backup file metadata section.
 * @param estimate_byte_count The total size in bytes of the estimate backup file.
 * @param rec_count_estimate  The total number of records.
 * @param fd                  The io_proxy that was written to
 */
static void
show_estimate(FILE *mach_fd, uint64_t *samples, uint32_t n_samples,
		uint64_t header_size, uint64_t estimate_byte_count,
		uint64_t rec_count_estimate, io_write_proxy_t* fd)
{
	distr_stats_t stats = calc_record_stats(samples, n_samples);
	double z = confidence_z(0.999999, 1);
	uint64_t upper = n_samples <= 1 ? 0 : (uint64_t) ceil(stats.mean +
			z * sqrt(stats.variance / n_samples));

	if (io_proxy_do_compress(fd)) {
		int64_t n_bytes = io_write_proxy_absolute_pos(fd);
		int64_t compressed_bytes = io_write_proxy_bytes_written(fd);

		double compression_ratio = (double) compressed_bytes / (double) n_bytes;
		inf("Estimated overall record size before compression is %" PRIu64 " byte(s)", upper);
		inf("Approximate compression ratio is %g%%", 100 * compression_ratio);
	}
	else {
		inf("Estimated overall record size is %" PRIu64 " byte(s)", upper);
	}

	if (mach_fd != NULL && (fprintf(mach_fd, "ESTIMATE:%" PRIu64 ":%" PRIu64 "\n",
			rec_count_estimate, upper) < 0 || fflush(mach_fd) == EOF)) {
		err_code("Error while writing machine-readable estimate");
	}

	uint64_t est_backup_size = estimate_total_backup_size(samples, n_samples,
			header_size, estimate_byte_count, rec_count_estimate,
			BACKUP_FILE_ESTIMATE_CONFIDENCE_LEVEL);

	inf("Estimated total backup file size (for backup-to-file, %g%% "
			"confidence): %" PRIu64 " byte(s)",
			100 * BACKUP_FILE_ESTIMATE_CONFIDENCE_LEVEL, est_backup_size);
}

/*
 * Signal handler for `SIGINT` and `SIGTERM`.
 *
 * @param sig  The signal number.
 */
static void
sig_hand(int32_t sig)
{
	(void)sig;
	err("### Backup interrupted ###");
	backup_status_stop(get_g_backup_conf(), get_g_backup_status());
}

static void
no_op(int32_t sig)
{
	(void) sig;
}

static void
set_s3_configs(const backup_config_t* conf)
{
	if (s3_initialized()) {
		return;
	}

	if (conf->s3_region != NULL) {
		s3_set_region(conf->s3_region);
	}

	if (conf->s3_profile != NULL) {
		s3_set_profile(conf->s3_profile);
	}

	if (conf->s3_endpoint_override != NULL) {
		s3_set_endpoint(conf->s3_endpoint_override);
	}

	s3_set_max_async_downloads(conf->s3_max_async_downloads);
	s3_set_max_async_uploads(conf->s3_max_async_uploads);
	s3_set_connect_timeout_ms(conf->s3_connect_timeout);
	s3_set_log_level(conf->s3_log_level);
}
