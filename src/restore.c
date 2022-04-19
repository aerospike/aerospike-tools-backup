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

#include <restore.h>

#include <conf.h>
#include <dec_text.h>
#include <io_proxy.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#define OPTIONS_SHORT "-h:Sp:A:U:P::n:d:i:t:vm:B:s:urgN:RILFwVZT:y:z:"

static restore_config_t* g_conf;
static restore_status_t* g_status;


//==========================================================
// Forward Declarations.
//

static bool has_stopped(void);
static void stop(void);
static int update_file_pos(per_thread_context_t* ptc);
static bool close_file(io_read_proxy_t *fd);
static bool open_file(const char *file_path, as_vector *ns_vec, io_read_proxy_t *fd,
		bool *legacy, uint32_t *line_no, bool *first_file, off_t *size,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey);
static bool check_set(char *set, as_vector *set_vec);
static void * restore_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static const char * print_set(const char *set);
static bool compare_sets(const char *set1, const char *set2);
static index_status check_index(aerospike *as, index_param *index, uint32_t timeout);
static bool restore_index(aerospike *as, index_param *index,
		as_vector *set_vec, restore_thread_args_t*, uint32_t timeout);
static bool wait_index(index_param *index);
static bool restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec,
		restore_thread_args_t*, bool wait, uint32_t timeout);
static bool restore_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static bool wait_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static void sig_hand(int32_t sig);
static void print_stat(per_thread_context_t *ptc, cf_clock *prev_log,
		uint64_t *prev_records,	cf_clock *now, cf_clock *store_time, cf_clock *read_time);


//==========================================================
// Public API.
//

int32_t
restore_main(int32_t argc, char **argv)
{
	int32_t res = EXIT_FAILURE;

	restore_config_t conf;
	g_conf = &conf;

	int restore_config_res = restore_config_init(argc, argv, &conf);
	if (restore_config_res != 0) {
		if (restore_config_res == RESTORE_CONFIG_INIT_EXIT) {
			res = EXIT_SUCCESS;
		}
		goto cleanup1;
	}

	restore_status_t status;
	g_status = &status;
	if (!restore_status_init(&status, &conf)) {
		err("Failed to initialize restore status");
		goto cleanup1;
	}

	signal(SIGINT, sig_hand);
	signal(SIGTERM, sig_hand);

	inf("Starting restore to %s (bins: %s, sets: %s) from %s", conf.host,
			conf.bin_list == NULL ? "[all]" : conf.bin_list,
			conf.set_list == NULL ? "[all]" : conf.set_list,
			conf.input_file != NULL ?
					file_proxy_is_std_path(conf.input_file) ? "[stdin]" : conf.input_file :
					conf.directory);

	FILE *mach_fd = NULL;

	if (conf.machine != NULL && (mach_fd = fopen(conf.machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf.machine);
		goto cleanup2;
	}

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names;
	get_node_names(status.as->cluster, NULL, 0, &node_names, &n_node_names);

	inf("Processing %u node(s)", n_node_names);

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = &conf;
	counter_args.status = &status;
	counter_args.node_names = node_names;
	counter_args.n_node_names = n_node_names;
	counter_args.mach_fd = mach_fd;

	ver("Creating counter thread");

	if (pthread_create(&counter_thread, NULL, counter_thread_func, &counter_args) != 0) {
		err_code("Error while creating counter thread");
		goto cleanup3;
	}

	pthread_t restore_threads[MAX_THREADS];
	restore_thread_args_t restore_args;
	restore_args.conf = &conf;
	restore_args.status = &status;
	restore_args.path = NULL;
	restore_args.shared_fd = NULL;
	restore_args.line_no = NULL;
	restore_args.legacy = false;

	cf_queue *job_queue = cf_queue_create(sizeof (restore_thread_args_t), true);

	if (job_queue == NULL) {
		err_code("Error while allocating job queue");
		goto cleanup4;
	}

	uint32_t line_no;

	// restoring from a directory
	if (conf.directory != NULL) {
		if (!get_backup_files(conf.directory, &status.file_vec)) {
			err("Error while getting backup files");
			goto cleanup5;
		}

		if (status.file_vec.size == 0) {
			err("No backup files found");
			goto cleanup5;
		}

		if (!conf.no_records) {
			ver("Triaging %u backup file(s)", status.file_vec.size);

			for (uint32_t i = 0; i < status.file_vec.size; ++i) {
				char *path = as_vector_get_ptr(&status.file_vec, i);
				off_t size = get_file_size(path);
				if (size == -1) {
					err("Failed to get the size of file %s", path);
					goto cleanup5;
				}

				status.estimated_bytes += size;
			}
		}

		ver("Pushing %u exclusive job(s) to job queue", status.file_vec.size);

		// push a job for each backup file
		for (uint32_t i = 0; i < status.file_vec.size; ++i) {
			restore_args.path = as_vector_get_ptr(&status.file_vec, i);

			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup6;
			}
		}

		if (status.file_vec.size < conf.parallel) {
			conf.parallel = status.file_vec.size;
		}
	}
	// restoring from a single backup file
	else {
		inf("Restoring %s", conf.input_file);

		restore_args.shared_fd =
			(io_read_proxy_t*) cf_malloc(sizeof(io_read_proxy_t));
		// open the file, file descriptor goes to restore_args.shared_fd
		if (!open_file(conf.input_file, &status.ns_vec, restore_args.shared_fd,
				&restore_args.legacy, &line_no, NULL,
				conf.no_records ? NULL : &status.estimated_bytes,
				conf.compress_mode, conf.encrypt_mode, conf.pkey)) {
			err("Error while opening shared backup file");
			cf_free(restore_args.shared_fd);
			goto cleanup5;
		}

		ver("Pushing %u shared job(s) to job queue", conf.parallel);

		restore_args.line_no = &line_no;
		restore_args.path = conf.input_file;

		// push an identical job for each thread; all threads use restore_args.shared_fd for reading
		for (uint32_t i = 0; i < conf.parallel; ++i) {
			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup6;
			}
		}
	}

	if (!conf.no_records) {
		inf("Restoring records");
	}
	uint32_t threads_ok = 0;

	ver("Creating %u restore thread(s)", conf.parallel);

	for (uint32_t i = 0; i < conf.parallel; ++i) {
		if (pthread_create(&restore_threads[i], NULL, restore_thread_func, job_queue) != 0) {
			err_code("Error while creating restore thread");
			goto cleanup7;
		}

		++threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup7:
	ver("Waiting for %u restore thread(s)", threads_ok);

	void *thread_res;

	for (uint32_t i = 0; i < threads_ok; i++) {
		if (pthread_join(restore_threads[i], &thread_res) != 0) {
			err_code("Error while joining restore thread");
			stop();
			res = EXIT_FAILURE;
		}

		if (thread_res != (void *)EXIT_SUCCESS) {
			ver("Restore thread failed");

			res = EXIT_FAILURE;
		}
	}

	if (res == EXIT_SUCCESS && !conf.no_indexes &&
			!restore_indexes(status.as, &status.index_vec, &status.set_vec,
				&restore_args, conf.wait, conf.timeout)) {
		err("Error while restoring secondary indexes to cluster");
		res = EXIT_FAILURE;
	}

	if (res == EXIT_SUCCESS && conf.wait) {
		for (uint32_t i = 0; i < status.udf_vec.size; i++) {
			udf_param* udf = as_vector_get(&status.udf_vec, i);
			if (!wait_udf(status.as, udf, conf.timeout)) {
				err("Error while waiting for UDF upload");
				res = EXIT_FAILURE;
			}
		}
	}

cleanup6:
	if (conf.directory == NULL) {
		if (!close_file(restore_args.shared_fd)) {
			err("Error while closing shared backup file");
			res = EXIT_FAILURE;
		}
		cf_free(restore_args.shared_fd);
	}

cleanup5:
	cf_queue_destroy(job_queue);

cleanup4:
	stop();

	ver("Waiting for counter thread");

	if (pthread_join(counter_thread, NULL) != 0) {
		err_code("Error while joining counter thread");
		res = EXIT_FAILURE;
	}

cleanup3:
	if (node_names != NULL) {
		cf_free(node_names);
	}

cleanup2:
	if (mach_fd != NULL) {
		fclose(mach_fd);
	}

	restore_status_destroy(&status);

cleanup1:
	restore_config_destroy(&conf);

	file_proxy_cloud_shutdown();

	ver("Exiting with status code %d", res);

	return res;
}

void
restore_config_destroy(restore_config_t *conf)
{
	if (conf->host != NULL) {
		cf_free(conf->host);
	}

	if (conf->user != NULL) {
		cf_free(conf->user);
	}

	if (conf->password != NULL) {
		cf_free(conf->password);
	}

	if (conf->auth_mode != NULL) {
		cf_free(conf->auth_mode);
	}

	if (conf->s3_region != NULL) {
		cf_free(conf->s3_region);
	}

	if (conf->s3_profile != NULL) {
		cf_free(conf->s3_profile);
	}

	if (conf->s3_endpoint_override != NULL) {
		cf_free(conf->s3_endpoint_override);
	}

	if (conf->nice_list != NULL) {
		cf_free(conf->nice_list);
	}

	if (conf->ns_list != NULL) {
		cf_free(conf->ns_list);
	}

	if (conf->directory != NULL) {
		cf_free(conf->directory);
	}

	if (conf->input_file != NULL) {
		cf_free(conf->input_file);
	}

	if (conf->machine != NULL) {
		cf_free(conf->machine);
	}

	if (conf->bin_list != NULL) {
		cf_free(conf->bin_list);
	}

	if (conf->set_list != NULL) {
		cf_free(conf->set_list);
	}

	if (conf->pkey != NULL) {
		encryption_key_free(conf->pkey);
		cf_free(conf->pkey);
	}

	if (conf->tls_name != NULL) {
		cf_free(conf->tls_name);
	}

	tls_config_destroy(&conf->tls);
}


//==========================================================
// Local helpers.
//

/*
 * Checks if the program has been stopped.
 */
static bool
has_stopped(void)
{
	return restore_status_has_stopped(g_status);
}

/*
 * stops the program
 */
static void
stop(void)
{
	restore_status_stop(g_status);
}

/*
 * To be called after data has been read from the io_proxy. Updates the total
 * number of bytes read from all files globally
 */
static int
update_file_pos(per_thread_context_t* ptc)
{
	int64_t pos = io_read_proxy_estimate_pos(ptc->fd);
	if (pos < 0) {
		err("Failed to get the file position (%" PRId64 ")", pos);
		return -1;
	}
	uint64_t diff = (uint64_t) pos - ptc->byte_count_file;

	ptc->byte_count_file = (uint64_t) pos;
	as_add_uint64(&ptc->status->total_bytes, diff);

	return 0;
}


/*
 * Closes a backup file and frees the associated I/O buffer.
 *
 * @param fd      The file descriptor of the backup file to be closed.
 *
 * @result        `true`, if successful.
 */
static bool
close_file(io_read_proxy_t *fd)
{
	int ret = true;

	ver("Closing backup file");

	ver("Closing file descriptor");

	if (io_proxy_close(fd) == EOF) {
		err("Error while closing backup file");
		ret = false;
	}

	return ret;
}

/*
 * Opens and validates a backup file.
 *
 *   - Opens the backup file.
 *   - Allocates an I/O buffer for it.
 *   - Validates the version header and meta data (e.g., the namespace).
 *
 * @param file_path   The path of the backup file to be opened.
 * @param ns_vec      The (optional) source and (also optional) target namespace to be restored.
 * @param fd          The file descriptor of the opened backup file.
 * @param legacy      Indicates a version 3.0 backup file.
 * @param line_no     The current line number.
 * @param first_file  Indicates that the backup file may contain secondary index information and
 *                    UDF files, i.e., it was the first backup file written during backup.
 * @param total       Increased by the number of bytes read from the opened backup file (version
 *                    header, meta data).
 * @param size        The size of the opened backup file.
 *
 * @result            `true`, if successful.
 */
static bool
open_file(const char *file_path, as_vector *ns_vec, io_read_proxy_t *fd,
		bool *legacy, uint32_t *line_no, bool *first_file,
		off_t *size, compression_opt c_opt, encryption_opt e_opt,
		encryption_key_t* pkey)
{
	ver("Opening backup file %s", file_path);

	if (file_proxy_is_std_path(file_path) || strncmp(file_path, "-:", 2) == 0) {
		ver("Backup file is stdin");

		if (size != NULL) {
			if (strcmp(file_path, "-") == 0) {
				*size = 0;
			} else {
				uint64_t tmp;

				if (!better_atoi(file_path + 2, &tmp) ||
						tmp > (uint64_t)1024 * 1024 * 1024 * 1024 * 1024) {
					err("Invalid stdin input size %s", file_path + 2);
					return false;
				}

				*size = (off_t)tmp;
			}
		}

		if (io_read_proxy_init(fd, "-") != 0) {
			return false;
		}
	}
	else {

		if (io_read_proxy_init(fd, file_path) != 0) {
			return false;
		}

		if (size != NULL) {
			*size = file_proxy_get_size(&fd->file);
		}

		inf("Opened backup file %s", file_path);
	}

	io_proxy_init_compression(fd, c_opt);
	io_proxy_init_encryption(fd, pkey, e_opt);

	ver("Validating backup file version");

	bool res = false;
	char version[13];
	memset(version, 0, sizeof version);

	if (io_proxy_gets(fd, version, sizeof(version)) == NULL) {
		err("Error while reading version from backup file %s", file_path);
		goto cleanup1;
	}

	if (strncmp("Version ", version, 8) != 0 || version[11] != '\n' || version[12] != 0) {
		err("Invalid version line in backup file %s", file_path);
		hex_dump_err(version, sizeof(version));
		goto cleanup1;
	}

	*legacy = strncmp(version + 8, VERSION_3_0, 3) == 0;

	if (!(*legacy) && strncmp(version + 8, VERSION_3_1, 3) != 0) {
		err("Invalid backup file version %.3s in backup file %s", version + 8, file_path);
		hex_dump_err(version, sizeof version);
		goto cleanup1;
	}

	int32_t ch;
	char meta[MAX_META_LINE - 1 + 1 + 1];
	*line_no = 2;

	if (first_file != NULL) {
		*first_file = false;
	}

	while ((ch = io_proxy_peekc_unlocked(fd)) == META_PREFIX[0]) {
		io_proxy_getc_unlocked(fd);

		if (io_proxy_gets(fd, meta, sizeof(meta)) == NULL) {
			err("Error while reading meta data from backup file %s:%u [1]",
					file_path, *line_no);
			goto cleanup1;
		}

		for (uint32_t i = 0; i < sizeof meta; ++i) {
			if (meta[i] == '\n') {
				meta[i] = 0;
				break;
			}

			if (meta[i] == 0) {
				err("Meta data line %s too long in backup file %s:%u", meta, file_path, *line_no);
				goto cleanup1;
			}
		}

		if (meta[0] != META_PREFIX[1]) {
			err("Invalid meta data line \"#%s\" in backup file %s:%u [1]", meta, file_path,
					*line_no);
			goto cleanup1;
		}

		if (strcmp(meta + 1, META_FIRST_FILE) == 0) {
			if (first_file != NULL) {
				*first_file = true;
			}
		} else if (strncmp(meta + 1, META_NAMESPACE, sizeof META_NAMESPACE - 1) == 0) {
			if (ns_vec->size > 1) {
				const char *ns = as_vector_get_ptr(ns_vec, 0);

				if (meta[1 + sizeof META_NAMESPACE - 1] != ' ') {
					err("Invalid namespace meta data line in backup file %s:%u", file_path,
							*line_no);
					goto cleanup1;
				}

				if (strcmp(meta + 1 + sizeof META_NAMESPACE - 1 + 1, ns) != 0) {
					err("Invalid namespace %s in backup file %s (expected: %s)",
							meta + 1 + sizeof META_NAMESPACE - 1 + 1, file_path, ns);
					goto cleanup1;
				}
			}
		} else {
			err("Invalid meta data line \"#%s\" in backup file %s:%u [2]", meta, file_path,
					*line_no);
			goto cleanup1;
		}

		++(*line_no);
	}

	if (ch == EOF) {
		if (io_proxy_error(fd) != 0) {
			err("Error while reading meta data from backup file %s [2]", file_path);
			goto cleanup1;
		}
	}

	res = true;
	goto cleanup0;

cleanup1:
	close_file(fd);

	if (size != NULL) {
		*size = 0;
	}

cleanup0:
	return res;
}

/*
 * Checks whether the given vector of set names contains the given set name.
 *
 * @param set      The set name to be looked for.
 * @param set_vec  The vector of set names to be searched.
 *
 * @result         `true`, if the vector contains the set name or if the vector is empty.
 */
static bool
check_set(char *set, as_vector *set_vec)
{
	if (set_vec->size == 0) {
		return true;
	}

	for (uint32_t i = 0; i < set_vec->size; ++i) {
		char *item = as_vector_get_ptr(set_vec, i);

		if (strcmp(item, set) == 0) {
			return true;
		}
	}

	return false;
}

/*
 * Main restore worker thread function.
 *
 *   - Pops the restore_thread_args_t for a backup file off the job queue.
 *     - When restoring from a single file, all restore_thread_args_t elements in the queue are
 *       identical and there are initially as many elements in the queue as there are threads.
 *     - When restoring from a directory, the queue initially contains one element for each backup
 *       file in the directory.
 *   - Initializes a per_thread_context for that backup file.
 *   - If restoring from a single file: uses the shared file descriptor given by
 *     restore_thread_args_t.shared_fd.
 *   - If restoring from a directory: opens the backup file given by restore_thread_args_t.path.
 *   - Reads the records from the backup file and stores them in the database.
 *   - Secondary indexes and UDF files are not handled here. They are handled on the main thread.
 *
 * @param cont  The job queue.
 *
 * @result      `EXIT_SUCCESS` on success, `EXIT_FAILURE` otherwise.
 */
static void *
restore_thread_func(void *cont)
{
	record_uploader_t record_uploader;
	bool uploader_init = false;

	ver("Entering restore thread");

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;

	while (true) {
		if (has_stopped()) {
			ver("Restore thread detected failure");

			break;
		}

		restore_thread_args_t args;
		int32_t q_res = cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT);

		if (q_res == CF_QUEUE_EMPTY) {
			ver("Job queue is empty");

			res = (void *)EXIT_SUCCESS;
			break;
		}

		if (q_res != CF_QUEUE_OK) {
			err("Error while picking up restore job");
			break;
		}

		if (!uploader_init) {
			if (record_uploader_init(&record_uploader,
						&args.status->batch_uploader, args.conf->batch_size) != 0) {
				err("Failed to initialize record uploader");
				break;
			}
			uploader_init = true;
		}

		uint32_t line_no;
		per_thread_context_t ptc;
		ptc.conf = args.conf;
		ptc.status = args.status;
		ptc.record_uploader = &record_uploader;
		ptc.path = args.path;
		ptc.shared_fd = args.shared_fd;
		ptc.line_no = args.line_no != NULL ? args.line_no : &line_no;
		ptc.ns_vec = &args.status->ns_vec;
		ptc.bin_vec = &args.status->bin_vec;
		ptc.set_vec = &args.status->set_vec;
		ptc.legacy = args.legacy;
		ptc.stat_records = 0;
		ptc.read_time = 0;
		ptc.store_time = 0;
		ptc.read_ema = 0;
		ptc.store_ema = 0;

		// restoring from a single backup file: use the provided shared file descriptor
		if (ptc.conf->input_file != NULL) {
			ver("Using shared file descriptor");

			ptc.fd = ptc.shared_fd;
		}
		// restoring from a directory: open the backup file with the given path
		else {
			inf("Restoring %s", ptc.path);

			ptc.byte_count_file = 0;
			ptc.fd = (io_read_proxy_t*) cf_malloc(sizeof(io_read_proxy_t));
			if (!open_file(ptc.path, ptc.ns_vec, ptc.fd,
						&ptc.legacy, ptc.line_no, NULL, NULL,
						ptc.conf->compress_mode, ptc.conf->encrypt_mode,
						ptc.conf->pkey)) {
				err("Error while opening backup file");
				break;
			}
		}

		as_policy_write policy;
		as_policy_write_init(&policy);
		policy.base.socket_timeout = ptc.conf->socket_timeout;
		policy.base.total_timeout = ptc.conf->total_timeout > 0 ?
			ptc.conf->total_timeout : ptc.conf->timeout;
		policy.base.max_retries = ptc.conf->max_retries;
		policy.base.sleep_between_retries = ptc.conf->retry_delay;

		bool flag_ignore_rec_error = false;

		if (ptc.conf->replace) {
			policy.exists = AS_POLICY_EXISTS_CREATE_OR_REPLACE;

			ver("Existence policy is create or replace");
		} else if (ptc.conf->unique) {
			policy.exists = AS_POLICY_EXISTS_CREATE;

			ver("Existence policy is create");
		} else {
			ver("Existence policy is default");
		}

		if (ptc.conf->ignore_rec_error) {
			flag_ignore_rec_error = true;
		}

		if (!ptc.conf->no_generation) {
			policy.gen = AS_POLICY_GEN_GT;

			ver("Generation policy is greater-than");
		} else {
			ver("Generation policy is default");
		}

		cf_clock prev_log = 0;
		uint64_t prev_records = 0;

		while (true) {
			as_record rec;
			bool expired;
			index_param index;
			udf_param udf;

			// restoring from a single backup file: allow one thread at a time to read
			if (ptc.conf->input_file != NULL) {
				safe_lock(&ptc.status->file_read_mutex);
			}

			// check the stop flag inside the critical section; makes sure that we do not try to
			// read from the shared file descriptor after another thread encountered an error and
			// set the stop flag
			if (restore_status_has_stopped(ptc.status)) {
				if (ptc.conf->input_file != NULL) {
					safe_unlock(&ptc.status->file_read_mutex);
				}

				break;
			}

			cf_clock read_start = as_load_bool(&g_verbose) ? cf_getus() : 0;
			decoder_status res = ptc.status->decoder.parse(ptc.fd, ptc.legacy,
					ptc.ns_vec, ptc.bin_vec, ptc.line_no, &rec,
					ptc.conf->extra_ttl, &expired, &index, &udf);
			cf_clock read_time = as_load_bool(&g_verbose) ? cf_getus() - read_start : 0;

			// set the stop flag inside the critical section; see check above
			if (res == DECODER_ERROR) {
				stop();
			}

			if (ptc.conf->input_file != NULL) {
				safe_unlock(&ptc.status->file_read_mutex);
			}
			// only update the file pos in dir mode
			else if (update_file_pos(&ptc) < 0) {
				err("Error while restoring backup file %s (line %u)", ptc.path, *ptc.line_no);
				stop();
			}

			if (res == DECODER_EOF) {
				ver("End of backup file reached");

				break;
			}

			if (res == DECODER_ERROR) {
				err("Error while restoring backup file %s (line %u)", ptc.path, *ptc.line_no);
				break;
			}

			if (res == DECODER_INDEX) {
				if (args.conf->no_indexes) {
					ver("Ignoring index block");
					free_index(&index);
					continue;
				}
				else if (!args.conf->indexes_last &&
						!restore_index(args.status->as, &index, ptc.set_vec,
							&args, args.conf->timeout)) {
					err("Error while restoring secondary index");
					break;
				}

				pthread_mutex_lock(&args.status->idx_udf_lock);
				as_vector_append(&args.status->index_vec, &index);
				pthread_mutex_unlock(&args.status->idx_udf_lock);

				as_incr_uint32(&args.status->index_count);
				continue;
			}

			if (res == DECODER_UDF) {
				if (args.conf->no_udfs) {
					ver("Ignoring UDF file block");
					free_udf(&udf);
					continue;
				}
				else if (!restore_udf(args.status->as, &udf, args.conf->timeout)) {
					err("Error while restoring UDF");
					break;
				}

				pthread_mutex_lock(&args.status->idx_udf_lock);
				as_vector_append(&args.status->udf_vec, &udf);
				pthread_mutex_unlock(&args.status->idx_udf_lock);

				as_incr_uint32(&args.status->udf_count);
				continue;
			}

			if (res == DECODER_RECORD) {
				if (args.conf->no_records) {
					break;
				}

				if (expired) {
					as_incr_uint64(&ptc.status->expired_records);
				} else if (rec.bins.size == 0 || !check_set(rec.key.set, ptc.set_vec)) {
					as_incr_uint64(&ptc.status->skipped_records);
				} else {
					if (!record_uploader_put(&record_uploader, &rec)) {
						stop();
						break;
					}

					/*
					useconds_t backoff = INITIAL_BACKOFF * 1000;
					int32_t tries;

					for (tries = 0; tries < MAX_TRIES && !restore_status_has_stopped(ptc.status); ++tries) {
						as_error ae;
						policy.key = rec.key.valuep != NULL ? AS_POLICY_KEY_SEND :
								AS_POLICY_KEY_DIGEST;
						cf_clock store_start = as_load_bool(&g_verbose) ? cf_getus() : 0;
						as_status put = aerospike_key_put(ptc.status->as, &ae, &policy, &rec.key,
								&rec);
						cf_clock now = as_load_bool(&g_verbose) ? cf_getus() : 0;
						cf_clock store_time = now - store_start;

						bool do_retry = false;

						switch (put) {
							// System level permanent errors. No point in 
							// continuing. Fail immediately. The list
							// is by no means complete, all missed cases would
							// fall into default and go through n_retries cycle
							// and eventually fail.
							case AEROSPIKE_ERR_SERVER_FULL:
							case AEROSPIKE_ROLE_VIOLATION:
								err("Error while storing record - code %d: %s at %s:%d",
										ae.code, ae.message, ae.file, ae.line);
								stop();
								break;

							// Record specific error either ignored or restore
							// is aborted. retry is meaningless
							case AEROSPIKE_ERR_RECORD_TOO_BIG:
							case AEROSPIKE_ERR_RECORD_KEY_MISMATCH:
							case AEROSPIKE_ERR_BIN_NAME:
							case AEROSPIKE_ERR_ALWAYS_FORBIDDEN:
								ver("Error while storing record - code %d: %s at %s:%d",
										ae.code, ae.message, ae.file, ae.line);
								as_incr_uint64(&ptc.status->ignored_records);

								if (! flag_ignore_rec_error) {
									stop();
									err("Error while storing record - code %d: %s at %s:%d", ae.code, ae.message, ae.file, ae.line);
									err("Encountered error while restoring. Skipping retries and aborting!!");
								}
								break;

							// Conditional error based on input config. No
							// retries.
							case AEROSPIKE_ERR_RECORD_GENERATION:
								as_incr_uint64(&ptc.status->fresher_records);
								break;

							case AEROSPIKE_ERR_RECORD_EXISTS:
								as_incr_uint64(&ptc.status->existed_records);
								break;

							case AEROSPIKE_OK:
								print_stat(&ptc, &prev_log, &prev_records,
										&now, &store_time, &read_time);
								as_incr_uint64(&ptc.status->inserted_records);
								break;

							// All other cases attempt retry.
							default: 

								if (tries == MAX_TRIES - 1) {
									err("Error while storing record - code %d: %s at %s:%d",
											ae.code, ae.message, ae.file, ae.line);
									err("Encountered too many errors while restoring. Aborting!!");
									stop();
									break;
								}

								do_retry = true;

								ver("Error while storing record - code %d: %s at %s:%d",
										ae.code, ae.message, ae.file,
										ae.line);

								
								// DEVICE_OVERLOAD error always retry with
								// backoff and sleep.
								if (put == AEROSPIKE_ERR_DEVICE_OVERLOAD) {
									usleep(backoff);
									backoff *= 2;
									as_incr_uint64(&ptc.status->backoff_count);
								} else {
									backoff = INITIAL_BACKOFF * 1000;
									restore_status_sleep_for(ptc.status, 1);
								}
								break;

						}

						if (!do_retry) {
							break;
						}
					}
					*/
				}

				as_incr_uint64(&ptc.status->total_records);
				as_record_destroy(&rec);

				if (ptc.conf->bandwidth > 0 && ptc.conf->tps > 0) {
					safe_lock(&ptc.status->limit_mutex);

					while ((as_load_uint64(&ptc.status->total_bytes) >= ptc.status->bytes_limit ||
								as_load_uint64(&ptc.status->total_records) >= ptc.status->records_limit) &&
							!restore_status_has_stopped(ptc.status)) {
						safe_wait(&ptc.status->limit_cond, &ptc.status->limit_mutex);
					}

					safe_unlock(&ptc.status->limit_mutex);
				}

				continue;
			}
		}

		// restoring from a single backup file: do nothing
		if (ptc.conf->input_file != NULL) {
			ver("Not closing shared file descriptor");

			ptc.fd = NULL;
		}
		// restoring from a directory: close the backup file
		else {
			if (!close_file(ptc.fd)) {
				err("Error while closing backup file");
				cf_free(ptc.fd);
				break;
			}
			cf_free(ptc.fd);
		}
	}

	if (res != (void *)EXIT_SUCCESS) {
		ver("Indicating failure to other threads");

		stop();
	}

	ver("Leaving restore thread");

	return res;
}

/*
 * Main counter thread function.
 *
 * Outputs human-readable and machine-readable progress information.
 *
 * @param cont  The arguments for the thread, passed as a counter_thread_args.
 *
 * @result      Always `EXIT_SUCCESS`.
 */
static void *
counter_thread_func(void *cont)
{
	ver("Entering counter thread");

	counter_thread_args *args = (counter_thread_args *)cont;
	restore_config_t *conf = args->conf;
	restore_status_t *status = args->status;

	cf_clock prev_ms = cf_getms();

	uint32_t iter = 0;
	cf_clock print_prev_ms = prev_ms;
	uint64_t prev_bytes = as_load_uint64(&status->total_bytes);
	uint64_t mach_prev_bytes = prev_bytes;
	uint64_t prev_records = as_load_uint64(&status->total_records);

	while (true) {
		restore_status_sleep_for(status, 1);
		bool last_iter = restore_status_has_stopped(status);

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		prev_ms = now_ms;

		uint64_t now_bytes = as_load_uint64(&status->total_bytes);
		uint64_t now_records = as_load_uint64(&status->total_records);

		uint64_t expired_records = as_load_uint64(&status->expired_records);
		uint64_t skipped_records = as_load_uint64(&status->skipped_records);
		uint64_t ignored_records = as_load_uint64(&status->ignored_records);
		uint64_t inserted_records = as_load_uint64(&status->inserted_records);
		uint64_t existed_records = as_load_uint64(&status->existed_records);
		uint64_t fresher_records = as_load_uint64(&status->fresher_records);
		uint64_t backoff_count = as_load_uint64(&status->backoff_count);
		uint32_t index_count = as_load_uint32(&status->index_count);
		uint32_t udf_count = as_load_uint32(&status->udf_count);

		int32_t percent = status->estimated_bytes == 0 ? -1 :
			(int32_t) (now_bytes * 100 / (uint64_t) status->estimated_bytes);

		if (last_iter || iter++ % 10 == 0) {
			uint64_t bytes = now_bytes - prev_bytes;
			uint64_t records = now_records - prev_records;

			uint32_t ms = (uint32_t)(now_ms - print_prev_ms);
			print_prev_ms = now_ms;

			inf("%u UDF file(s), %u secondary index(es), %" PRIu64 " record(s) "
					"(%" PRIu64 " KiB/s, %" PRIu64 " rec/s, %" PRIu64 " B/rec, backed off: "
					"%" PRIu64 ")",
					udf_count, index_count, now_records,
					ms == 0 ? 0 : bytes * 1000 / 1024 / ms, ms == 0 ? 0 : records * 1000 / ms,
					records == 0 ? 0 : bytes / records, backoff_count);

			inf("Expired %" PRIu64 " : skipped %" PRIu64 " : err_ignored %" PRIu64 " "
					": inserted %" PRIu64 ": failed %" PRIu64 " (existed %" PRIu64 " "
					", fresher %" PRIu64 ")", expired_records, skipped_records,
					ignored_records, inserted_records,
					existed_records + fresher_records, existed_records,
					fresher_records);

			int32_t eta = (bytes == 0 || status->estimated_bytes == 0) ? -1 :
				(int32_t) (((uint64_t) status->estimated_bytes - now_bytes) * ms / bytes / 1000);
			char eta_buff[ETA_BUF_SIZE];
			format_eta(eta, eta_buff, sizeof eta_buff);

			if (percent >= 0 && eta >= 0) {
				inf("%d%% complete, ~%s remaining", percent, eta_buff);
			}

			prev_bytes = now_bytes;
			prev_records = now_records;
		}

		if (args->mach_fd != NULL) {
			if (percent >= 0 && (fprintf(args->mach_fd, "PROGRESS:%d\n", percent) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable progress");
			}

			uint64_t bytes = now_bytes - mach_prev_bytes;

			int32_t eta = (bytes == 0 || status->estimated_bytes == 0) ? -1 :
				(int32_t) (((uint64_t) status->estimated_bytes - now_bytes) * ms / bytes / 1000);
			char eta_buff[ETA_BUF_SIZE];
			format_eta(eta, eta_buff, sizeof eta_buff);

			if (eta >= 0 && (fprintf(args->mach_fd, "REMAINING:%s\n", eta_buff) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable remaining time");
			}

			mach_prev_bytes = now_bytes;
		}

		safe_lock(&status->limit_mutex);

		if (conf->bandwidth > 0 && conf->tps > 0) {
			if (ms > 0) {
				status->bytes_limit += conf->bandwidth * 1000 / ms;
				status->records_limit += conf->tps * 1000 / ms;
			}

			safe_signal(&status->limit_cond);
		}

		safe_unlock(&status->limit_mutex);

		if (last_iter) {
			if (args->mach_fd != NULL && (fprintf(args->mach_fd,
					"SUMMARY:%u:%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%" PRIu64 " "
					":%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n", udf_count,
					index_count, now_records, expired_records, skipped_records,
					ignored_records, inserted_records, existed_records,
					fresher_records) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable summary");
			}

			break;
		}
	}

	ver("Leaving counter thread");

	return (void *)EXIT_SUCCESS;
}

/*
 * Creates a printable secondary index set specification.
 *
 * @param set  The set specification to be printed.
 *
 * @result     The printable set specification.
 */
static const char *
print_set(const char *set)
{
	return set != NULL && set[0] != 0 ? set : "[none]";
}

/*
 * Compares two secondary index set specifications for equality.
 *
 * @param set1  The first set specification.
 * @param set2  The second set specification.
 *
 * @result      `true`, if the set specifications are equal.
 */
static bool
compare_sets(const char *set1, const char *set2)
{
	bool none1 = set1 == NULL || set1[0] == 0;
	bool none2 = set2 == NULL || set2[0] == 0;

	if (none1 && none2) {
		return true;
	}

	if (!none1 && !none2) {
		return strcmp(set1, set2) == 0;
	}

	return false;
}

/*
 * Checks whether a secondary index exists in the cluster and matches the given spec.
 *
 * @param as      The Aerospike client.
 * @param index   The secondary index to look for.
 * @param timeout The timeout for Aerospike command.
 *
 * @result       `INDEX_STATUS_ABSENT`, if the index does not exist.
 *               `INDEX_STATUS_SAME`, if the index exists and matches the given spec.
 *               `INDEX_STATUS_DIFFERENT`, if the index exists, but does not match the given spec.
 *               `INDEX_STATUS_INVALID` in case of an error.
 */
static index_status
check_index(aerospike *as, index_param *index, uint32_t timeout)
{
	ver("Checking index %s:%s:%s", index->ns, index->set, index->name);

	index_status res = INDEX_STATUS_INVALID;

	size_t value_size = sizeof "sindex-list:ns=" - 1 + strlen(index->ns) + 1;
	char value[value_size];
	snprintf(value, value_size, "sindex-list:ns=%s", index->ns);

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = timeout;

	char *resp = NULL;
	as_error ae;

	if (aerospike_info_any(as, &ae, &policy, value, &resp) != AEROSPIKE_OK) {
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
		ver("No secondary indexes");

		res = INDEX_STATUS_ABSENT;
		goto cleanup1;
	}

	as_vector info_vec;
	as_vector_inita(&info_vec, sizeof (void *), 25);
	split_string(info_str, ';', false, &info_vec);

	char *clone = safe_strdup(info_str);
	index_param index2;
	uint32_t i;

	for (i = 0; i < info_vec.size; ++i) {
		char *index_str = as_vector_get_ptr(&info_vec, i);

		if (!parse_index_info(index->ns, index_str, &index2)) {
			err("Error while parsing secondary index info string %s", clone);
			goto cleanup2;
		}

		if (strcmp(index->name, index2.name) == 0) {
			break;
		}

		as_vector_destroy(&index2.path_vec);
	}

	if (i == info_vec.size) {
		ver("Index not found");

		res = INDEX_STATUS_ABSENT;
		goto cleanup2;
	}

	if (!compare_sets(index->set, index2.set)) {
		ver("Set mismatch, %s vs. %s", print_set(index->set), print_set(index2.set));

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	if (index->type != index2.type) {
		ver("Type mismatch, %d vs. %d", (int32_t)index->type, (int32_t)index2.type);

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	if (index->path_vec.size != index2.path_vec.size) {
		ver("Path count mismatch, %u vs. %u", index->path_vec.size, index2.path_vec.size);

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	for (i = 0; i < index->path_vec.size; ++i) {
		path_param *path1 = as_vector_get((as_vector *)&index->path_vec, i);
		path_param *path2 = as_vector_get((as_vector *)&index2.path_vec, i);

		if (path1->type != path2->type) {
			ver("Path type mismatch, %d vs. %d", (int32_t)path1->type, (int32_t)path2->type);

			res = INDEX_STATUS_DIFFERENT;
			goto cleanup3;
		}

		if (strcmp(path1->path, path2->path) != 0) {
			ver("Path mismatch, %s vs. %s", path1->path, path2->path);

			res = INDEX_STATUS_DIFFERENT;
			goto cleanup3;
		}
	}

	res = INDEX_STATUS_SAME;

cleanup3:
	as_vector_destroy(&index2.path_vec);

cleanup2:
	as_vector_destroy(&info_vec);
	cf_free(clone);

cleanup1:
	cf_free(resp);

cleanup0:
	return res;
}

static bool
restore_index(aerospike *as, index_param *index, as_vector *set_vec,
		restore_thread_args_t* args, uint32_t timeout)
{
	path_param *path = as_vector_get(&index->path_vec, 0);

	if (!check_set(index->set, set_vec)) {
		ver("Skipping index with unwanted set %s:%s:%s (%s)", index->ns, index->set,
				index->name, path->path);
		as_incr_uint32(&args->status->skipped_indexes);

		index->task.as = as;
		memcpy(index->task.ns, index->ns, sizeof(as_namespace));
		memcpy(index->task.name, index->name, sizeof(index->task.name));
		index->task.done = true;
		return true;
	}

	ver("Restoring index %s:%s:%s (%s)", index->ns, index->set, index->name, path->path);

	as_index_type itype;
	as_index_datatype dtype;

	switch (index->type) {
		default:
		case INDEX_TYPE_INVALID:
			err("Invalid index type");
			return false;

		case INDEX_TYPE_NONE:
			itype = AS_INDEX_TYPE_DEFAULT;
			break;

		case INDEX_TYPE_LIST:
			itype = AS_INDEX_TYPE_LIST;
			break;

		case INDEX_TYPE_MAPKEYS:
			itype = AS_INDEX_TYPE_MAPKEYS;
			break;

		case INDEX_TYPE_MAPVALUES:
			itype = AS_INDEX_TYPE_MAPVALUES;
			break;
	}

	switch (path->type) {
		default:
		case PATH_TYPE_INVALID:
			err("Invalid path type");
			return false;

		case PATH_TYPE_STRING:
			dtype = AS_INDEX_STRING;
			break;

		case PATH_TYPE_NUMERIC:
			dtype = AS_INDEX_NUMERIC;
			break;

		case PATH_TYPE_GEOJSON:
			dtype = AS_INDEX_GEO2DSPHERE;
			break;
	}

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = timeout;
	as_error ae;

	index_status orig_stat = check_index(as, index, timeout);
	index_status stat = orig_stat;

	if (stat == INDEX_STATUS_DIFFERENT) {
		ver("Removing mismatched index %s:%s", index->ns, index->name);

		if (aerospike_index_remove(as, &ae, &policy, index->ns, index->name) != AEROSPIKE_OK) {
			err("Error while removing index %s:%s - code %d: %s at %s:%d", index->ns,
					index->name, ae.code, ae.message, ae.file, ae.line);
			return false;
		}

		// aerospike_index_remove() is asynchronous. Check the index again, because AEROSPIKE_OK
		// doesn't necessarily mean that the index is gone.
		for (int32_t tries = 0; tries < MAX_TRIES; ++tries) {
			restore_status_sleep_for(args->status, 1);
			stat = check_index(as, index, timeout);

			if (stat != INDEX_STATUS_DIFFERENT) {
				break;
			}
		}
	}

	switch (stat) {
		default:
			err("Unknown index status");
			return false;

		case INDEX_STATUS_INVALID:
			err("Error while checking index %s:%s:%s (%s)", index->ns, index->set, index->name,
					path->path);
			return false;

		case INDEX_STATUS_ABSENT:
			break;

		case INDEX_STATUS_SAME:
			ver("Skipping matched index %s:%s:%s (%s)", index->ns, index->set, index->name,
					path->path);

			if (orig_stat == INDEX_STATUS_DIFFERENT) {
				as_incr_uint32(&args->status->mismatched_indexes);
			}
			else {
				as_incr_uint32(&args->status->matched_indexes);
			}

			index->task.as = as;
			memcpy(index->task.ns, index->ns, sizeof(as_namespace));
			memcpy(index->task.name, index->name, sizeof(index->task.name));
			index->task.done = true;
			return true;

		case INDEX_STATUS_DIFFERENT:
			err("Error while removing mismatched index %s:%s", index->ns, index->name);
			return false;
	}

	ver("Creating index %s:%s:%s (%s)", index->ns, index->set, index->name, path->path);

	if (aerospike_index_create_complex(as, &ae, &index->task, &policy, index->ns,
				index->set[0] == 0 ? NULL : index->set, path->path, index->name, itype,
				dtype) != AEROSPIKE_OK) {
		err("Error while creating index %s:%s:%s (%s) - code %d: %s at %s:%d", index->ns,
				index->set, index->name, path->path, ae.code, ae.message, ae.file, ae.line);
		return false;
	}

	return true;
}

static bool
wait_index(index_param *index)
{
	as_error ae;
	path_param *path = as_vector_get(&index->path_vec, 0);

	ver("Waiting for index %s:%s:%s (%s)", index->ns, index->set, index->name,
			path->path);

	if (aerospike_index_create_wait(&ae, &index->task, 500) != AEROSPIKE_OK) {
		err("Error while waiting for index %s:%s:%s (%s) - code %d: %s at %s:%d", index->ns,
				index->set, index->name, path->path, ae.code, ae.message, ae.file, ae.line);
		return false;
	}

	return true;
}

/*
 * Creates the given secondary indexes in the cluster.
 *
 * @param as         The Aerospike client.
 * @param index_vec  The secondary index information, as a vector of index_param.
 * @param set_vec    The sets to be restored.
 * @param args       The restore thread args struct.
 * @param wait       Makes the function wait until each secondary index is fully built.
 * @param timeout    The timeout for Aerospike command.
 *
 * @result           `true`, if successful.
 */
static bool
restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec, restore_thread_args_t* args,
		bool wait, uint32_t timeout)
{
	bool res = true;

	if (args->conf->indexes_last) {
		for (uint32_t i = 0; i < index_vec->size; ++i) {
			index_param *index = as_vector_get(index_vec, i);

			if (!restore_index(as, index, set_vec, args, timeout)) {
				res = false;
			}
		}
	}

	uint32_t skipped = as_load_uint32(&args->status->skipped_indexes);
	uint32_t matched = as_load_uint32(&args->status->matched_indexes);
	uint32_t mismatched = as_load_uint32(&args->status->mismatched_indexes);

	if (skipped > 0) {
		inf("Skipped %d index(es) with unwanted set(s)", skipped);
	}

	if (matched > 0) {
		inf("Skipped %d matched index(es)", matched);
	}

	if (mismatched > 0) {
		err("Skipped %d mismatched index(es)", mismatched);
	}

	if (wait) {
		for (uint32_t i = 0; i < index_vec->size; ++i) {
			index_param *index = as_vector_get(index_vec, i);
			if (!wait_index(index)) {
				res = false;
			}
		}
	}

	return res;
}

static bool
restore_udf(aerospike *as, udf_param *udf, uint32_t timeout)
{
	inf("Restoring UDF file %s (size %u)", udf->name, udf->size);

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = timeout;
	as_bytes content;
	as_bytes_init_wrap(&content, udf->data, udf->size, false);
	as_error ae;

	if (aerospike_udf_put(as, &ae, &policy, udf->name, udf->type,
				&content) != AEROSPIKE_OK) {
		err("Error while putting UDF file %s - code %d: %s at %s:%d", udf->name, ae.code,
				ae.message, ae.file, ae.line);
		as_bytes_destroy(&content);
		return false;
	}

	as_bytes_destroy(&content);

	return true;
}

static bool
wait_udf(aerospike *as, udf_param *udf, uint32_t timeout)
{
	as_error ae;
	as_policy_info policy;
	ver("Waiting for UDF file %s", udf->name);

	as_policy_info_init(&policy);
	policy.timeout = timeout;

	if (aerospike_udf_put_wait(as, &ae, &policy, udf->name, 500) != AEROSPIKE_OK) {
		err("Error while waiting for UDF file %s - code %d: %s at %s:%d", udf->name,
				ae.code, ae.message, ae.file, ae.line);
		return false;
	}

	return true;
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
	err("### Restore interrupted ###");
	stop();
}

static void
print_stat(per_thread_context_t *ptc, cf_clock *prev_log, uint64_t *prev_records,	
		cf_clock *now, cf_clock *store_time, cf_clock *read_time)
{
	ptc->read_time += *read_time;
	ptc->store_time += *store_time;
	ptc->read_ema = (99 * ptc->read_ema + 1 * (uint32_t)*read_time) / 100;
	ptc->store_ema = (99 * ptc->store_ema + 1 * (uint32_t)*store_time) / 100;

	++ptc->stat_records;

	uint32_t time_diff = (uint32_t)((*now - *prev_log) / 1000);

	if (time_diff < STAT_INTERVAL * 1000) {
		return;
	}

	uint32_t rec_diff = (uint32_t)(ptc->stat_records - *prev_records);

	ver("%" PRIu64 " per-thread record(s) (%u rec/s), "
			"read latency: %u (%u) us, store latency: %u (%u) us",
			ptc->stat_records,
			*prev_records > 0 ? rec_diff * 1000 / time_diff : 1,
			(uint32_t)(ptc->read_time / ptc->stat_records), ptc->read_ema,
			(uint32_t)(ptc->store_time / ptc->stat_records), ptc->store_ema);

	*prev_log = *now;
	*prev_records = ptc->stat_records;
}

