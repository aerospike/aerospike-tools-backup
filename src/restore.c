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

static restore_status_t* start_restore(restore_config_t *conf);
static bool has_stopped(void);
static void stop(void);
static int update_file_pos(per_thread_context_t* ptc);
static int update_shared_file_pos(per_thread_context_t* ptc);
static bool close_file(io_read_proxy_t *fd);
static bool open_file(const char *file_path, as_vector *ns_vec, io_read_proxy_t *fd,
		bool *legacy, uint32_t *line_no, bool *first_file, off_t *size,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey);
static bool check_set(char *set, as_vector *set_vec);
static void * restore_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static const char * print_optional_str(const char *str);
static bool compare_strs(const char *str1, const char *str2);
static index_status check_index(aerospike *as, index_param *index, uint32_t timeout);
static bool restore_index(aerospike *as, index_param *index,
		as_vector *set_vec, restore_thread_args_t*, uint32_t timeout);
static bool wait_index(index_param *index);
static bool restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec,
		restore_thread_args_t*, bool wait, uint32_t timeout);
static bool restore_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static bool wait_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static void sig_hand(int32_t sig);
//static void print_stat(per_thread_context_t *ptc, cf_clock *prev_log,
//		uint64_t *prev_records,	cf_clock *now, cf_clock *store_time, cf_clock *read_time);
static void set_s3_configs(const restore_config_t* conf);


//==========================================================
// Public API.
//

int32_t
restore_main(int32_t argc, char **argv)
{
	int32_t res = EXIT_FAILURE;

	enable_client_log();

	restore_config_t conf;

	int restore_config_res = restore_config_set(argc, argv, &conf);
	if (restore_config_res != 0) {
		if (restore_config_res == RESTORE_CONFIG_INIT_EXIT) {
			res = EXIT_SUCCESS;
		}
		goto cleanup;
	}

	int restore_validate_res = restore_config_validate(&conf);
	if (restore_validate_res != 0) {
		goto cleanup;
	}

	signal(SIGINT, sig_hand);
	signal(SIGTERM, sig_hand);

	restore_status_t *status = start_restore(&conf);
	if (status != RUN_RESTORE_FAILURE) {
		restore_status_destroy(status);
		cf_free(status);
		res = EXIT_SUCCESS;
	}

	restore_config_destroy(&conf);

cleanup:
	file_proxy_cloud_shutdown();
	ver("Exiting with status code %d", res);
	return res;
}

/*
 * FOR USE WITH ASRESTORE AS A LIBRARY (Use at your own risk)
 *
 * Runs a restore job with the given configuration. This method is not thread
 * safe and should not be called multiple times in parallel, as it uses global
 * variables to handle signal interruption.
 *
 * The passed in restore_config must be freed by the caller using restore_config_destroy().
 * To enable C client logging, call enable_client_log() before calling this function
 * 
 * Returns the restore_status struct used during the run which must be freed by the
 * caller. Only free the return value if it is != RUN_RESTORE_FAILURE
 */
restore_status_t*
restore_run(restore_config_t *conf) {
	restore_config_set_heap_defaults(conf);
	restore_status_t *status = start_restore(conf);
	file_proxy_cloud_shutdown();

	return status;
}

//==========================================================
// Local helpers.
//

/*
 * Runs a restore job with the given configuration. This method is not thread
 * safe and should not be called multiple times in parallel, as it uses global
 * variables to handle signal interruption.
 *
 * Returns the restore_status struct used during the run which must be freed by the
 * caller.
 * Only free the return value if it is != RUN_RESTORE_FAILURE
 */
static restore_status_t*
start_restore(restore_config_t *conf)
{
	int32_t res = EXIT_FAILURE;
	g_conf = conf;

	restore_status_t *status = (restore_status_t*) malloc(sizeof(restore_status_t));
	if (status == NULL) {
		err("Failed to allocate %zu bytes for restore status struct",
				sizeof(restore_status_t));
		goto cleanup1;
	}

	set_s3_configs(conf);

	if (!restore_status_init(status, conf)) {
		err("Failed to initialize restore status");
		goto cleanup1;
	}
	g_status = status;

	if (conf->validate) {
		inf("Starting validation of %s",
				conf->input_file != NULL ?
						file_proxy_is_std_path(conf->input_file) ? "[stdin]" : conf->input_file :
						conf->directory);
	}
	else {
		inf("Starting restore to %s (bins: %s, sets: %s) from %s", conf->host,
				conf->bin_list == NULL ? "[all]" : conf->bin_list,
				conf->set_list == NULL ? "[all]" : conf->set_list,
				conf->input_file != NULL ?
						file_proxy_is_std_path(conf->input_file) ? "[stdin]" : conf->input_file :
						conf->directory);
	}

	FILE *mach_fd = NULL;

	if (conf->machine != NULL && (mach_fd = fopen(conf->machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf->machine);
		goto cleanup2;
	}

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names = 0;

	if (!conf->validate) {
		get_node_names(status->as->cluster, NULL, 0, &node_names, &n_node_names);

		inf("Processing %u node(s)", n_node_names);
	}

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = conf;
	counter_args.status = status;
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
	restore_args.conf = conf;
	restore_args.status = status;
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
	as_vector directories;
	as_vector_init(&directories, sizeof(char*), 1);
	off_t total_file_size = 0;

	// restoring from multiple directories
	if (conf->directory_list != NULL) {

		char *dir_clone = safe_strdup(conf->directory_list);
		split_string(dir_clone, ',', false, &directories);

		for (uint32_t i = 0; i < directories.size; i++) {
			char *dir = as_vector_get_ptr(&directories, i);

			if (conf->parent_directory) {

				size_t parent_dir_size = strlen(conf->parent_directory);
				size_t path_size = parent_dir_size + strlen(dir) + 1;
				char *fmt = "%s%s";


				if (conf->parent_directory[parent_dir_size - 1] != '/') {
					++path_size;
					fmt = "%s/%s";
				}

				char *tmp_dir = dir;
				dir = cf_malloc(path_size);
				snprintf(dir, path_size, fmt, conf->parent_directory, tmp_dir);
			}

			total_file_size = get_backup_files(dir, &status->file_vec);
			if (total_file_size < 0) {
				err("Error while getting backup files from directory_list entry: %s", dir);
				cf_free(dir_clone);

				if (conf->parent_directory) {
					cf_free(dir);
				}

				goto cleanup5;
			}

			if (conf->parent_directory) {
				cf_free(dir);
			}
		}

		cf_free(dir_clone);
	}

	// restoring from a directory
	if (conf->directory != NULL) {

		total_file_size = get_backup_files(conf->directory, &status->file_vec);
		if (total_file_size < 0) {
			err("Error while getting backup files from directory");
			goto cleanup5;
		}
	}

	// directory and directory_list are mutually exclusive but share this logic
	if (conf->directory != NULL || conf->directory_list != NULL) {

		if (status->file_vec.size == 0) {
			err("No backup files found");
			goto cleanup5;
		}

		if (!conf->no_records) {
			ver("Triaging %u backup file(s)", status->file_vec.size);
			status->estimated_bytes = total_file_size;
			ver("Estimated total backup file size: %lli bytes", status->estimated_bytes);
		}

		if (conf->validate) {
			inf("Validating backup files");
		}

		ver("Pushing %u exclusive job(s) to job queue", status->file_vec.size);

		// push a job for each backup file
		for (uint32_t i = 0; i < status->file_vec.size; ++i) {
			restore_args.path = as_vector_get_ptr(&status->file_vec, i);

			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup6;
			}
		}

		if (status->file_vec.size < conf->parallel) {
			conf->parallel = status->file_vec.size;
		}
	}
	// restoring from a single backup file
	else {
		inf(
			"%s %s", 
			conf->validate ? "Validating" : "Restoring",
			conf->input_file
		);

		restore_args.shared_fd =
			(io_read_proxy_t*) cf_malloc(sizeof(io_read_proxy_t));
		// open the file, file descriptor goes to restore_args.shared_fd
		if (!open_file(conf->input_file, &status->ns_vec, restore_args.shared_fd,
				&restore_args.legacy, &line_no, NULL,
				conf->no_records ? NULL : &status->estimated_bytes,
				conf->compress_mode, conf->encrypt_mode, conf->pkey)) {
			err("Error while opening shared backup file");
			cf_free(restore_args.shared_fd);
			goto cleanup5;
		}

		ver("Pushing %u shared job(s) to job queue", conf->parallel);

		restore_args.line_no = &line_no;
		restore_args.path = conf->input_file;

		// push an identical job for each thread; all threads use restore_args.shared_fd for reading
		for (uint32_t i = 0; i < conf->parallel; ++i) {
			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup6;
			}
		}
	}

	if (!conf->no_records && !conf->validate) {
		inf("Restoring records");
	}

	uint32_t threads_ok = 0;

	ver("Creating %u restore thread(s)", conf->parallel);

	for (uint32_t i = 0; i < conf->parallel; ++i) {
		if (pthread_create(&restore_threads[i], NULL, restore_thread_func, job_queue) != 0) {
			err_code("Error while creating restore thread");
			goto cleanup7;
		}

		++threads_ok;
	}

	res = EXIT_SUCCESS;

	inf(
		"Finished %s backup file(s)",
		conf->validate ? "validating" : "restoring"
	);

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
			res = EXIT_FAILURE;
		}
	}

	if (!conf->validate && !batch_uploader_await(&status->batch_uploader)) {
		res = EXIT_FAILURE;
	}

	// NOTE this is here to support the --indexes-last option
	if (res == EXIT_SUCCESS && !conf->no_indexes && !conf->validate &&
			!restore_indexes(status->as, &status->index_vec, &status->set_vec,
				&restore_args, conf->wait, conf->timeout)) {
		err("Error while restoring secondary indexes to cluster");
		res = EXIT_FAILURE;
	}

	if (res == EXIT_SUCCESS && conf->wait) {
		for (uint32_t i = 0; i < status->udf_vec.size; i++) {
			udf_param* udf = as_vector_get(&status->udf_vec, i);
			if (!wait_udf(status->as, udf, conf->timeout)) {
				err("Error while waiting for UDF upload");
				res = EXIT_FAILURE;
			}
		}
	}

cleanup6:
	if (conf->directory == NULL && conf->directory_list == NULL) {
		if (!close_file(restore_args.shared_fd)) {
			err("Error while closing shared backup file");
			res = EXIT_FAILURE;
		}
		cf_free(restore_args.shared_fd);
	}

cleanup5:
	cf_queue_destroy(job_queue);
	as_vector_destroy(&directories);

cleanup4:
	ver("Waiting for counter thread");

	restore_status_finish(status);

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

	if (res == EXIT_FAILURE) {
		restore_status_destroy(status);
		cf_free(status);
		status = RUN_RESTORE_FAILURE;
	}

cleanup1:

	return res == EXIT_FAILURE ? RUN_RESTORE_FAILURE : status;
}

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
	ptc->status->total_bytes += diff;

	return 0;
}

/*
 * To be called after reading from the shared file proxy while holding the file
 * read lock.
 */
static int
update_shared_file_pos(per_thread_context_t* ptc)
{
	int64_t pos = io_write_proxy_bytes_written(ptc->fd);
	if (pos < 0) {
		err("Failed to get the file position");
		return -1;
	}

	ptc->status->total_bytes = (uint64_t) pos;

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
				int64_t tmp;

				if (!better_atoi(file_path + 2, &tmp) || tmp < 0 ||
						(uint64_t) tmp > (uint64_t) 1024 * 1024 * 1024 * 1024 * 1024) {
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

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;

	while (true) {
		if (has_stopped()) {
			break;
		}

		restore_thread_args_t args;
		int32_t q_res = cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT);

		if (q_res == CF_QUEUE_EMPTY) {
			res = (void *)EXIT_SUCCESS;
			break;
		}

		if (q_res != CF_QUEUE_OK) {
			err("Error while picking up restore job");
			break;
		}

		if (!uploader_init && !args.conf->validate) {
			if (record_uploader_init(&record_uploader,
						&args.status->batch_uploader, args.status->batch_size) != 0) {
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

		// restoring from a single backup file: use the provided shared file descriptor
		if (ptc.conf->input_file != NULL) {
			ptc.fd = ptc.shared_fd;
		}
		// restoring from a directory: open the backup file with the given path
		else {
			inf(
				"%s %s",
				ptc.conf->validate ? "validating" : "restoring",
				ptc.path
			);

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

			decoder_status res = ptc.status->decoder.parse(ptc.fd, ptc.legacy,
					ptc.ns_vec, ptc.bin_vec, ptc.line_no, &rec,
					ptc.conf->extra_ttl, &expired, &index, &udf);

			// set the stop flag inside the critical section; see check above
			if (res == DECODER_ERROR) {
				stop();
			}

			if (ptc.conf->input_file != NULL) {
				if (update_shared_file_pos(&ptc) < 0) {
					err("Error while parsing backup file %s (line %u)",
							ptc.path, *ptc.line_no);
					stop();
				}

				safe_unlock(&ptc.status->file_read_mutex);
			}
			// only update the file pos in dir mode
			else if (update_file_pos(&ptc) < 0) {
				err("Error while parsing backup file %s (line %u)", ptc.path,
						*ptc.line_no);
				stop();
			}

			if (res == DECODER_EOF) {
				if (ptc.conf->input_file == NULL) {
					ver("End of backup file reached");
				}

				break;
			}

			if (res == DECODER_ERROR) {
				err("Error while parsing backup file %s (line %u)", ptc.path, *ptc.line_no);
				break;
			}

			if (res == DECODER_INDEX) {
				if (args.conf->validate) {
					ver("Validated Secondary Index");
					args.status->index_count++;
					free_index(&index);
					continue;
				}
				else if (args.conf->no_indexes) {
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

				args.status->index_count++;
				continue;
			}

			if (res == DECODER_UDF) {
				if (args.conf->validate) {
					ver("Validated UDF");
					args.status->udf_count++;
					free_udf(&udf);
					continue;
				}
				else if (args.conf->no_udfs) {
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

				args.status->udf_count++;
				continue;
			}

			if (res == DECODER_RECORD) {
				if (args.conf->validate) {
					ptc.status->total_records++;
					as_record_destroy(&rec);
					continue;
				}
				else if (args.conf->no_records) {
					// NOTE: not a continue because records come
					// last in the backup file, if that ever changes this should too.
					break;
				}

				if (expired) {
					ptc.status->expired_records++;
					as_record_destroy(&rec);
				} else if (rec.bins.size == 0 || !check_set(rec.key.set, ptc.set_vec)) {
					ptc.status->skipped_records++;
					as_record_destroy(&rec);
				} else {
					if (!record_uploader_put(&record_uploader, &rec)) {
						stop();
						break;
					}
				}

				ptc.status->total_records++;

				if (ptc.conf->bandwidth > 0 && ptc.conf->tps > 0) {
					safe_lock(&ptc.status->limit_mutex);

					while (ptc.status->total_bytes >= ptc.status->bytes_limit ||
								ptc.status->total_records >= ptc.status->records_limit &&
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

	if (uploader_init) {
		if (res != (void *)EXIT_FAILURE &&
				!record_uploader_flush(&record_uploader)) {
			res = (void *)EXIT_FAILURE;
		}
		record_uploader_free(&record_uploader);
	}

	if (res != (void *)EXIT_SUCCESS) {
		stop();
	}

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
	counter_thread_args *args = (counter_thread_args *)cont;
	restore_config_t *conf = args->conf;
	restore_status_t *status = args->status;

	cf_clock prev_ms = cf_getms();

	uint32_t iter = 0;
	cf_clock print_prev_ms = prev_ms;
	uint64_t prev_bytes = status->total_bytes;
	uint64_t mach_prev_bytes = prev_bytes;
	uint64_t prev_records = status->total_records;

	while (true) {
		restore_status_sleep_for(status, 1, true);
		bool last_iter = restore_status_has_finished(status);

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t) (now_ms - prev_ms);
		prev_ms = now_ms;

		uint64_t now_bytes = status->total_bytes;
		uint64_t now_records = status->total_records;

		uint64_t expired_records = status->expired_records;
		uint64_t skipped_records = status->skipped_records;
		uint64_t ignored_records = status->ignored_records;
		uint64_t inserted_records = status->inserted_records;
		uint64_t existed_records = status->existed_records;
		uint64_t fresher_records = status->fresher_records;
		// no retires will ever occur if we are validating backup files because there are no writes
		uint64_t retry_count = conf->validate ? 0 : batch_uploader_retry_count(&status->batch_uploader);
		uint32_t index_count = status->index_count;
		uint32_t udf_count = status->udf_count;

		int32_t percent = status->estimated_bytes == 0 ? -1 :
			(int32_t) (now_bytes * 100 / (uint64_t) status->estimated_bytes);

		if (last_iter || iter++ % 10 == 0) {
			uint64_t bytes = now_bytes - prev_bytes;
			uint64_t records = now_records - prev_records;

			uint32_t ms = (uint32_t)(now_ms - print_prev_ms);
			print_prev_ms = now_ms;

			inf("%u UDF file(s), %u secondary index(es), %" PRIu64 " record(s) "
					"(%" PRIu64 " rec/s, %" PRIu64 " KiB/s, %" PRIu64 " B/rec, retries: "
					"%" PRIu64 ")",
					udf_count, index_count, now_records,
					ms == 0 ? 0 : records * 1000 / ms,
					ms == 0 ? 0 : bytes * 1000 / 1024 / ms,
					records == 0 ? 0 : bytes / records, retry_count);

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
 * Creates a printable secondary index set/ctx specification.
 *
 * @param set  The set/ctx specification to be printed.
 *
 * @result     The printable set specification.
 */
static const char *
print_optional_str(const char *str)
{
	return str != NULL && str[0] != 0 ? str : "[none]";
}

/*
 * Compares two secondary index optional string (set, ctx) specifications for equality.
 *
 * @param str1  The first set/ctx specification.
 * @param str2  The second set/ctx specification.
 *
 * @result      `true`, if the given specifications are equal.
 */
static bool
compare_strs(const char *str1, const char *str2)
{
	bool none1 = str1 == NULL || str1[0] == 0;
	bool none2 = str2 == NULL || str2[0] == 0;

	if (none1 && none2) {
		return true;
	}

	if (!none1 && !none2) {
		return strcmp(str1, str2) == 0;
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

	char* b64_enable = ";b64=true";
	size_t value_size = sizeof "sindex-list:ns=" - 1 + strlen(index->ns)+ strlen(b64_enable) + 1;
	char value[value_size];
	snprintf(value, value_size, "sindex-list:ns=%s%s", index->ns, b64_enable);

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

	if (!compare_strs(index->set, index2.set)) {
		ver("Set mismatch, %s vs. %s", print_optional_str(index->set), print_optional_str(index2.set));

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

	if (!compare_strs(index->ctx, index2.ctx)) {
		ver("Context mismatch, %s vs. %s", print_optional_str(index->ctx), print_optional_str(index2.ctx));

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup2;
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
		args->status->skipped_indexes++;

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

		case PATH_TYPE_GEO2DSPHERE:
			dtype = AS_INDEX_GEO2DSPHERE;
			break;

		case PATH_TYPE_BLOB:
			dtype = AS_INDEX_BLOB;
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
			restore_status_sleep_for(args->status, 1, false);
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
				args->status->mismatched_indexes++;
			}
			else {
				args->status->matched_indexes++;
			}

			index->task.as = as;
			strncpy(index->task.ns, index->ns, sizeof(as_namespace));
			strncpy(index->task.name, index->name, sizeof(index->task.name));
			index->task.done = true;
			return true;

		case INDEX_STATUS_DIFFERENT:
			err("Error while removing mismatched index %s:%s", index->ns, index->name);
			return false;
	}

	ver("Creating index %s:%s:%s (%s):[%s]", index->ns, index->set, index->name, path->path, index->ctx);
	
	as_cdt_ctx ctx;
	as_cdt_ctx_init(&ctx, 1);
	if (index->ctx != NULL && index->ctx[0] != 0) {
		// convert b64 encoded ctx to as_cdt_ctx
		bool res = as_cdt_ctx_from_base64(&ctx, index->ctx);
		if (!res) {
			err("Error while converting b64 encoded ctx %s into as_cdt_ctx; index info %s:%s:%s (%s)", index->ctx,
				index->ns, index->set, index->name, path->path);
			// c-client destroy the &ctx in case of any error during conversion (from b64 to cdt_ctx)
			return false;
		}
	}
	if (aerospike_index_create_ctx(as, &ae, &index->task, &policy, index->ns,
				index->set[0] == 0 ? NULL : index->set, path->path, index->name, itype,
				dtype, index->ctx[0] == 0 ? NULL : &ctx) != AEROSPIKE_OK) {
		err("Error while creating index %s:%s:%s (%s) - code %d: %s at %s:%d", index->ns,
				index->set, index->name, path->path, ae.code, ae.message, ae.file, ae.line);
		
		as_cdt_ctx_destroy(&ctx);
		return false;
	}
	as_cdt_ctx_destroy(&ctx);
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

	uint32_t skipped = args->status->skipped_indexes;
	uint32_t matched = args->status->matched_indexes;
	uint32_t mismatched = args->status->mismatched_indexes;

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
set_s3_configs(const restore_config_t* conf)
{
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
	s3_set_connect_timeout_ms(conf->s3_connect_timeout);
	s3_set_log_level(conf->s3_log_level);
}
