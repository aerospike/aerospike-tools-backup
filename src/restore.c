/*
 * Copyright 2015-2017 Aerospike, Inc.
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

#include <restore.h>
#include <dec_text.h>
#include <utils.h>
#include <conf.h>

extern char *aerospike_client_version;  ///< The C client's version string.

static volatile bool stop = false;  ///< Makes background threads exit.

static pthread_cond_t limit_cond = PTHREAD_COND_INITIALIZER;    ///< Used by the counter thread
                                                                ///  to signal newly available
                                                                ///  bandwidth or transactions to
                                                                ///  the restore threads.

static void print_stat(per_thread_context *, cf_clock *, uint64_t *, cf_clock *, cf_clock *, cf_clock *);

static void config_default(restore_config *conf);
///
/// Closes a backup file and frees the associated I/O buffer.
///
/// @param fd      The file descriptor of the backup file to be closed.
/// @param fd_buf  The I/O buffer that was allocated for the file descriptor.
///
/// @result        `true`, if successful.
///
static bool
close_file(FILE **fd, void **fd_buf)
{
	if (*fd == NULL) {
		return true;
	}

	if (verbose) {
		ver("Closing backup file");
	}

	if (*fd == stdin) {
		if (verbose) {
			ver("Not closing stdin");
		}

		// not closing, but we still have to detach our I/O buffer, as we're going to free it
		setlinebuf(stdin);
	} else {
		if (verbose) {
			ver("Closing file descriptor");
		}

		if (fclose(*fd) == EOF) {
			err_code("Error while closing backup file");
			return false;
		}
	}

	cf_free(*fd_buf);
	*fd = NULL;
	*fd_buf = NULL;
	return true;
}

///
/// Opens and validates a backup file.
///
///   - Opens the backup file.
///   - Allocates an I/O buffer for it.
///   - Validates the version header and meta data (e.g., the namespace).
///
/// @param file_path   The path of the backup file to be opened.
/// @param ns_vec      The (optional) source and (also optional) target namespace to be restored.
/// @param fd          The file descriptor of the opened backup file.
/// @param fd_buf      The I/O buffer allocated for the file descriptor.
/// @param legacy      Indicates a version 3.0 backup file.
/// @param line_no     The current line number.
/// @param first_file  Indicates that the backup file may contain secondary index information and
///                    UDF files, i.e., it was the first backup file written during backup.
/// @param total       Increased by the number of bytes read from the opened backup file (version
///                    header, meta data).
/// @param size        The size of the opened backup file.
///
/// @result            `true`, if successful.
///
static bool
open_file(const char *file_path, as_vector *ns_vec, FILE **fd, void **fd_buf, bool *legacy,
		uint32_t *line_no, bool *first_file, cf_atomic64 *total, off_t *size)
{
	if (verbose) {
		ver("Opening backup file %s", file_path);
	}

	if (strcmp(file_path, "-") == 0 || strncmp(file_path, "-:", 2) == 0) {
		if (verbose) {
			ver("Backup file is stdin");
		}

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

		*fd = stdin;
	} else {
		if (verbose) {
			ver("Getting file descriptor");
		}

		if (size != NULL) {
			struct stat stat_buf;

			if (stat(file_path, &stat_buf) < 0) {
				err_code("Error while determining backup file size for %s", file_path);
				return false;
			}

			*size = stat_buf.st_size;
		}

		if ((*fd = fopen(file_path, "r")) == NULL) {
			err_code("Error while opening backup file %s", file_path);
			return false;
		}

		inf("Opened backup file %s", file_path);
	}

	*fd_buf = safe_malloc(IO_BUF_SIZE);
	setbuffer(*fd, *fd_buf, IO_BUF_SIZE);

	if (verbose) {
		ver("Validating backup file version");
	}

	bool res = false;
	char version[13];
	memset(version, 0, sizeof version);

	if (fgets(version, sizeof version, *fd) == NULL) {
		err("Error while reading version from backup file %s", file_path);
		goto cleanup1;
	}

	if (strncmp("Version ", version, 8) != 0 || version[11] != '\n' || version[12] != 0) {
		err("Invalid version line in backup file %s", file_path);
		hex_dump_err(version, sizeof version);
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

	if (total != NULL) {
		cf_atomic64_add(total, 12);
	}

	if (first_file != NULL) {
		*first_file = false;
	}

	while ((ch = getc_unlocked(*fd)) == META_PREFIX[0]) {
		if (total != NULL) {
			cf_atomic64_incr(total);
		}

		if (fgets(meta, sizeof meta, *fd) == NULL) {
			err("Error while reading meta data from backup file %s:%u [1]", file_path, *line_no);
			goto cleanup1;
		}

		for (uint32_t i = 0; i < sizeof meta; ++i) {
			if (total != NULL) {
				cf_atomic64_incr(total);
			}

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
		if (ferror(*fd) != 0) {
			err("Error while reading meta data from backup file %s [2]", file_path);
			goto cleanup1;
		}
	} else {
		if (total != NULL) {
			cf_atomic64_incr(total);
		}

		if (ungetc(ch, *fd) == EOF) {
			err("Error while reading meta data from backup file %s [3]", file_path);
			goto cleanup1;
		}

		if (total != NULL) {
			cf_atomic64_decr(total);
		}
	}

	res = true;
	goto cleanup0;

cleanup1:
	close_file(fd, fd_buf);

	if (size != NULL) {
		*size = 0;
	}

cleanup0:
	return res;
}

///
/// Deallocates the fields of a udf_param UDF file record.
///
/// @param param  The udf_param to be deallocated.
///
static void
free_udf(udf_param *param)
{
	cf_free(param->name);
	cf_free(param->data);
}

///
/// Deallocates a vector of udf_param UDF file records.
///
/// @param udf_vec  The vector of udf_param records to be deallocated.
///
static void
free_udfs(as_vector *udf_vec)
{
	if (verbose) {
		ver("Freeing %u UDF file(s)", udf_vec->size);
	}

	for (uint32_t i = 0; i < udf_vec->size; ++i) {
		udf_param *param = as_vector_get(udf_vec, i);
		free_udf(param);
	}
}

///
/// Deallocates the fields of an index_param secondary index information record.
///
/// @param param  The index_param to be deallocated.
///
static void
free_index(index_param *param)
{
	cf_free(param->ns);
	cf_free(param->set);
	cf_free(param->name);

	for (uint32_t i = 0; i < param->path_vec.size; ++i) {
		path_param *param2 = as_vector_get(&param->path_vec, i);
		cf_free(param2->path);
	}

	as_vector_destroy(&param->path_vec);
}

///
/// Deallocates a vector of index_param secondary index information records.
///
/// @param index_vec  The vector of index_param records to be deallocated.
///
static void
free_indexes(as_vector *index_vec)
{
	if (verbose) {
		ver("Freeing %u index(es)", index_vec->size);
	}

	for (uint32_t i = 0; i < index_vec->size; ++i) {
		index_param *param = as_vector_get(index_vec, i);
		free_index(param);
	}
}

///
/// Checks whether the given vector of set names contains the given set name.
///
/// @param set      The set name to be looked for.
/// @param set_vec  The vector of set names to be searched.
///
/// @result         `true`, if the vector contains the set name or if the vector is empty.
///
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

///
/// Main restore worker thread function.
///
///   - Pops the restore_thread_args for a backup file off the job queue.
///     - When restoring from a single file, all restore_thread_args elements in the queue are
///       identical and there are initially as many elements in the queue as there are threads.
///     - When restoring from a directory, the queue initially contains one element for each backup
///       file in the directory.
///   - Initializes a per_thread_context for that backup file.
///   - If restoring from a single file: uses the shared file descriptor given by
///     restore_thread_args.shared_fd.
///   - If restoring from a directory: opens the backup file given by restore_thread_args.path.
///   - Reads the records from the backup file and stores them in the database.
///   - Secondary indexes and UDF files are not handled here. They are handled on the main thread.
///
/// @param cont  The job queue.
///
/// @result      `EXIT_SUCCESS` on success, `EXIT_FAILURE` otherwise.
///
static void *
restore_thread_func(void *cont)
{
	if (verbose) {
		ver("Entering restore thread");
	}

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;

	while (true) {
		if (stop) {
			if (verbose) {
				ver("Restore thread detected failure");
			}

			break;
		}

		restore_thread_args args;
		int32_t q_res = cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT);

		if (q_res == CF_QUEUE_EMPTY) {
			if (verbose) {
				ver("Job queue is empty");
			}

			res = (void *)EXIT_SUCCESS;
			break;
		}

		if (q_res != CF_QUEUE_OK) {
			err("Error while picking up restore job");
			break;
		}

		uint32_t line_no;
		per_thread_context ptc;
		ptc.conf = args.conf;
		ptc.path = args.path;
		ptc.shared_fd = args.shared_fd;
		ptc.line_no = args.line_no != NULL ? args.line_no : &line_no;
		ptc.fd = NULL;
		ptc.fd_buf = NULL;
		ptc.ns_vec = args.ns_vec;
		ptc.bin_vec = args.bin_vec;
		ptc.set_vec = args.set_vec;
		ptc.legacy = args.legacy;
		ptc.stat_records = 0;
		ptc.read_time = 0;
		ptc.store_time = 0;
		ptc.read_ema = 0;
		ptc.store_ema = 0;

		// restoring from a single backup file: use the provided shared file descriptor
		if (ptc.conf->input_file != NULL) {
			if (verbose) {
				ver("Using shared file descriptor");
			}

			ptc.fd = ptc.shared_fd;
		// restoring from a directory: open the backup file with the given path
		} else {
			inf("Restoring %s", ptc.path);

			if (!open_file(ptc.path, ptc.ns_vec, &ptc.fd, &ptc.fd_buf, &ptc.legacy, ptc.line_no,
					NULL, &ptc.conf->total_bytes, NULL)) {
				err("Error while opening backup file");
				break;
			}
		}

		as_policy_write policy;
		as_policy_write_init(&policy);
		policy.base.total_timeout = ptc.conf->timeout;
		policy.base.max_retries = 0;

		bool flag_ignore_rec_error = false;

		if (ptc.conf->replace) {
			policy.exists = AS_POLICY_EXISTS_CREATE_OR_REPLACE;

			if (verbose) {
				ver("Existence policy is create or replace");
			}
		} else if (ptc.conf->unique) {
			policy.exists = AS_POLICY_EXISTS_CREATE;

			if (verbose) {
				ver("Existence policy is create");
			}
		} else if (verbose) {
			ver("Existence policy is default");
		}

		if (ptc.conf->ignore_rec_error) {
			flag_ignore_rec_error = true;
		}

		if (!ptc.conf->no_generation) {
			policy.gen = AS_POLICY_GEN_GT;

			if (verbose) {
				ver("Generation policy is greater-than");
			}
		} else if (verbose) {
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
				safe_lock();
			}

			// check the stop flag inside the critical section; makes sure that we do not try to
			// read from the shared file descriptor after another thread encountered an error and
			// set the stop flag
			if (stop) {
				if (ptc.conf->input_file != NULL) {
					safe_unlock();
				}

				break;
			}

			cf_clock read_start = verbose ? cf_getus() : 0;
			decoder_status res = ptc.conf->decoder->parse(ptc.fd, ptc.legacy, ptc.ns_vec,
					ptc.bin_vec, ptc.line_no, &ptc.conf->total_bytes, &rec, &expired,
					&index, &udf);
			cf_clock read_time = verbose ? cf_getus() - read_start : 0;

			// set the stop flag inside the critical section; see check above
			if (res == DECODER_ERROR) {
				stop = true;
			}

			if (ptc.conf->input_file != NULL) {
				safe_unlock();
			}

			if (res == DECODER_EOF) {
				if (verbose) {
					ver("End of backup file reached");
				}

				break;
			}

			if (res == DECODER_ERROR) {
				err("Error while restoring backup file %s (line %u)", ptc.path, *ptc.line_no);
				break;
			}

			if (res == DECODER_INDEX) {
				if (verbose) {
					ver("Ignoring index block");
				}

				free_index(&index);
				continue;
			}

			if (res == DECODER_UDF) {
				if (verbose) {
					ver("Ignoring UDF file block");
				}

				free_udf(&udf);
				continue;
			}

			if (res == DECODER_RECORD) {
				if (expired) {
					cf_atomic64_incr(&ptc.conf->expired_records);
				} else if (rec.bins.size == 0 || !check_set(rec.key.set, ptc.set_vec)) {
					cf_atomic64_incr(&ptc.conf->skipped_records);
				} else {
					useconds_t backoff = INITIAL_BACKOFF * 1000;
					int32_t tries;

					for (tries = 0; tries < MAX_TRIES && !stop; ++tries) {
						as_error ae;
						policy.key = rec.key.valuep != NULL ? AS_POLICY_KEY_SEND :
								AS_POLICY_KEY_DIGEST;
						cf_clock store_start = verbose ? cf_getus() : 0;
						as_status put = aerospike_key_put(ptc.conf->as, &ae, &policy, &rec.key,
								&rec);
						cf_clock now = verbose ? cf_getus() : 0;
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
								stop = true;
								break;

							// Record specific error either ignored or restore
							// is aborted. retry is meaningless
							case AEROSPIKE_ERR_RECORD_TOO_BIG:
							case AEROSPIKE_ERR_RECORD_KEY_MISMATCH:
							case AEROSPIKE_ERR_BIN_NAME:
							case AEROSPIKE_ERR_ALWAYS_FORBIDDEN:
								if (verbose) {
									ver("Error while storing record - code %d: %s at %s:%d",
											ae.code, ae.message, ae.file, ae.line);
								}

								if (! flag_ignore_rec_error) {
									stop = true;
									err("Error while storing record - code %d: %s at %s:%d", ae.code, ae.message, ae.file, ae.line);
									err("Encountered error while restoring. Skipping retries and aborting!!");
								}
								cf_atomic64_incr(&ptc.conf->ignored_records);
								break;

							// Conditional error based on input config. No
							// retries.
							case AEROSPIKE_ERR_RECORD_GENERATION:
								cf_atomic64_incr(&ptc.conf->fresher_records);
								break;

							case AEROSPIKE_ERR_RECORD_EXISTS:
								cf_atomic64_incr(&ptc.conf->existed_records);
								break;

							case AEROSPIKE_OK:
								if (verbose) {
									print_stat(&ptc, &prev_log, &prev_records,
											&now, &store_time, &read_time);
								}
								cf_atomic64_incr(&ptc.conf->inserted_records);
								break;

							// All other cases attempt retry.
							default: 

								if (tries == MAX_TRIES - 1) {
									err("Error while storing record - code %d: %s at %s:%d",
											ae.code, ae.message, ae.file, ae.line);
									err("Encountered too many errors while restoring. Aborting!!");
									stop = true;
									break;
								}

								do_retry = true;

								if (verbose) {
									ver("Error while storing record - code %d: %s at %s:%d",
											ae.code, ae.message, ae.file,
											ae.line);
								}

								
								// DEVICE_OVERLOAD error always retry with
								// backoff and sleep.
								if (put == AEROSPIKE_ERR_DEVICE_OVERLOAD) {
									usleep(backoff);
									backoff *= 2;
									cf_atomic64_incr(&ptc.conf->backoff_count);
								} else {
									backoff = INITIAL_BACKOFF * 1000;
									sleep(1);
								} 
								break;

						}

						if (! do_retry) {
							break;
						}
					}
				}

				cf_atomic64_incr(&ptc.conf->total_records);
				as_record_destroy(&rec);

				if (ptc.conf->bandwidth > 0 && ptc.conf->tps > 0) {
					safe_lock();

					while ((cf_atomic64_get(ptc.conf->total_bytes) >= ptc.conf->bytes_limit ||
							cf_atomic64_get(ptc.conf->total_records) >= ptc.conf->records_limit) &&
							!stop) {
						safe_wait(&limit_cond);
					}

					safe_unlock();
				}

				continue;
			}
		}

		// restoring from a single backup file: do nothing
		if (ptc.conf->input_file != NULL) {
			if (verbose) {
				ver("Not closing shared file descriptor");
			}

			ptc.fd = NULL;
		// restoring from a directory: close the backup file
		} else if (!close_file(&ptc.fd, &ptc.fd_buf)) {
			err("Error while closing backup file");
			break;
		}
	}

	if (res != (void *)EXIT_SUCCESS) {
		if (verbose) {
			ver("Indicating failure to other threads");
		}

		stop = true;
	}

	if (verbose) {
		ver("Leaving restore thread");
	}

	return res;
}

///
/// Main counter thread function.
///
/// Outputs human-readable and machine-readable progress information.
///
/// @param cont  The arguments for the thread, passed as a counter_thread_args.
///
/// @result      Always `EXIT_SUCCESS`.
///
static void *
counter_thread_func(void *cont)
{
	if (verbose) {
		ver("Entering counter thread");
	}

	counter_thread_args *args = (counter_thread_args *)cont;
	restore_config *conf = args->conf;
	uint32_t iter = 0;
	cf_clock prev_ms = cf_getms();
	uint64_t prev_bytes = cf_atomic64_get(conf->total_bytes);
	uint64_t prev_records = cf_atomic64_get(conf->total_records);

	while (true) {
		sleep(1);
		bool last_iter = stop;

		cf_clock now_ms = cf_getms();
		uint64_t now_bytes = cf_atomic64_get(conf->total_bytes);
		uint64_t now_records = cf_atomic64_get(conf->total_records);

		int32_t percent = conf->estimated_bytes == 0 ? -1 :
				(int32_t)(now_bytes * 100 / (uint64_t)conf->estimated_bytes);
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		uint64_t bytes = now_bytes - prev_bytes;
		uint64_t records = now_records - prev_records;

		int32_t eta = (bytes == 0 || conf->estimated_bytes == 0) ? -1 :
				(int32_t)(((uint64_t)conf->estimated_bytes - now_bytes) * ms / bytes / 1000);
		char eta_buff[ETA_BUF_SIZE];
		format_eta(eta, eta_buff, sizeof eta_buff);

		prev_ms = now_ms;
		prev_bytes = now_bytes;
		prev_records = now_records;

		uint64_t expired_records = cf_atomic64_get(conf->expired_records);
		uint64_t skipped_records = cf_atomic64_get(conf->skipped_records);
		uint64_t ignored_records = cf_atomic64_get(conf->ignored_records);
		uint64_t inserted_records = cf_atomic64_get(conf->inserted_records);
		uint64_t existed_records = cf_atomic64_get(conf->existed_records);
		uint64_t fresher_records = cf_atomic64_get(conf->fresher_records);
		uint64_t backoff_count = cf_atomic64_get(conf->backoff_count);
		uint32_t index_count = conf->index_count;
		uint32_t udf_count = conf->udf_count;

		if (last_iter || iter++ % 10 == 0) {
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

			if (percent >= 0 && eta >= 0) {
				inf("%d%% complete, ~%s remaining", percent, eta_buff);
			}
		}

		if (args->mach_fd != NULL) {
			if (percent >= 0 && (fprintf(args->mach_fd, "PROGRESS:%d\n", percent) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable progress");
			}

			if (eta >= 0 && (fprintf(args->mach_fd, "REMAINING:%s\n", eta_buff) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable remaining time");
			}
		}

		safe_lock();

		if (conf->bandwidth > 0 && conf->tps > 0) {
			if (ms > 0) {
				conf->bytes_limit += conf->bandwidth * 1000 / ms;
				conf->records_limit += conf->tps * 1000 / ms;
			}

			safe_signal(&limit_cond);
		}

		safe_unlock();

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

	if (verbose) {
		ver("Leaving counter thread");
	}

	return (void *)EXIT_SUCCESS;
}

///
/// Reads, parses, and returns the secondary index information and UDF files from the given
/// backup file descriptor.
///
/// Assumes that the file pointer points to the beginning of the global section of the backup file.
///
/// @param fd         The file descriptor to read from.
/// @param ns_vec     The (optional) source and (also optional) target namespace to be restored.
/// @param legacy     Indicates a version 3.0 backup file.
/// @param conf       The restore configuration.
/// @param line_no    The current line number.
/// @param total      Increased by the number of bytes read from the file descriptor.
/// @param index_vec  The secondary index information, as a vector of index_param.
/// @param udf_vec    The UDF files, as a vector of udf_param.
///
/// @result           `true`, if successful.
///
static bool
get_indexes_and_udfs(FILE *fd, as_vector *ns_vec, bool legacy, restore_config *conf,
		uint32_t *line_no, cf_atomic64 *total, as_vector *index_vec, as_vector *udf_vec)
{
	bool res = false;

	if (verbose) {
		ver("Parsing global index and UDF data (line %u)", *line_no);
	}

	while (true) {
		int32_t ch = getc_unlocked(fd);

		if (ch == EOF) {
			if (ferror(fd) != 0) {
				err("Error while reading global data from backup file (line %u) [1]", *line_no);
				goto cleanup1;
			}

			res = true;
			goto cleanup0;
		}

		if (total != NULL) {
			cf_atomic64_incr(total);
		}

		if (ungetc(ch, fd) == EOF) {
			err("Error while reading global data from backup file (line %u) [2]", *line_no);
			goto cleanup1;
		}

		if (total != NULL) {
			cf_atomic64_decr(total);
		}

		if (ch != GLOBAL_PREFIX[0]) {
			res = true;
			goto cleanup0;
		}

		index_param index;
		udf_param udf;
		decoder_status res = conf->decoder->parse(fd, legacy, ns_vec, NULL, line_no, total, NULL,
				NULL, &index, &udf);

		if (res == DECODER_ERROR || res == DECODER_EOF) {
			err("Error while reading global data from backup file (line %u) [3]", *line_no);
			goto cleanup1;
		}

		if (res == DECODER_INDEX) {
			if (index_vec != NULL) {
				as_vector_append(index_vec, &index);
			} else {
				free_index(&index);
			}
		} else if (res == DECODER_UDF) {
			if (udf_vec != NULL) {
				as_vector_append(udf_vec, &udf);
			} else {
				free_udf(&udf);
			}
		}
	}

	res = true;
	goto cleanup0;

cleanup1:
	if (index_vec != NULL) {
		free_indexes(index_vec);
	}

	if (udf_vec != NULL) {
		free_udfs(udf_vec);
	}

cleanup0:
	return res;
}

///
/// Creates a printable secondary index set specification.
///
/// @param set  The set specification to be printed.
///
/// @result     The printable set specification.
///
static const char *
print_set(const char *set)
{
	return set != NULL && set[0] != 0 ? set : "[none]";
}

///
/// Compares two secondary index set specifications for equality.
///
/// @param set1  The first set specification.
/// @param set2  The second set specification.
///
/// @result      `true`, if the set specifications are equal.
///
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

///
/// Checks whether a secondary index exists in the cluster and matches the given spec.
///
/// @param as      The Aerospike client.
/// @param index   The secondary index to look for.
/// @param timeout The timeout for Aerospike command.
///
/// @result       `INDEX_STATUS_ABSENT`, if the index does not exist.
///               `INDEX_STATUS_SAME`, if the index exists and matches the given spec.
///               `INDEX_STATUS_DIFFERENT`, if the index exists, but does not match the given spec.
///               `INDEX_STATUS_INVALID` in case of an error.
///
static index_status
check_index(aerospike *as, index_param *index, uint32_t timeout)
{
	if (verbose) {
		ver("Checking index %s:%s:%s", index->ns, index->set, index->name);
	}

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
		if (verbose) {
			ver("No secondary indexes");
		}

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
		if (verbose) {
			ver("Index not found");
		}

		res = INDEX_STATUS_ABSENT;
		goto cleanup2;
	}

	if (!compare_sets(index->set, index2.set)) {
		if (verbose) {
			ver("Set mismatch, %s vs. %s", print_set(index->set), print_set(index2.set));
		}

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	if (index->type != index2.type) {
		if (verbose) {
			ver("Type mismatch, %d vs. %d", (int32_t)index->type, (int32_t)index2.type);
		}

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	if (index->path_vec.size != index2.path_vec.size) {
		if (verbose) {
			ver("Path count mismatch, %u vs. %u", index->path_vec.size, index2.path_vec.size);
		}

		res = INDEX_STATUS_DIFFERENT;
		goto cleanup3;
	}

	for (i = 0; i < index->path_vec.size; ++i) {
		path_param *path1 = as_vector_get((as_vector *)&index->path_vec, i);
		path_param *path2 = as_vector_get((as_vector *)&index2.path_vec, i);

		if (path1->type != path2->type) {
			if (verbose) {
				ver("Path type mismatch, %d vs. %d", (int32_t)path1->type, (int32_t)path2->type);
			}

			res = INDEX_STATUS_DIFFERENT;
			goto cleanup3;
		}

		if (strcmp(path1->path, path2->path) != 0) {
			if (verbose) {
				ver("Path mismatch, %s vs. %s", path1->path, path2->path);
			}

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

///
/// Creates the given secondary indexes in the cluster.
///
/// @param as         The Aerospike client.
/// @param index_vec  The secondary index information, as a vector of index_param.
/// @param set_vec    The sets to be restored.
/// @param count      The number of created secondary indexes.
/// @param wait       Makes the function wait until each secondary index is fully built.
/// @param timeout    The timeout for Aerospike command.
///
/// @result           `true`, if successful.
///
static bool
restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec, volatile uint32_t *count,
		bool wait, uint32_t timeout)
{
	inf("Restoring %d secondary index(es)", index_vec->size);
	int32_t skipped = 0;
	int32_t matched = 0;
	int32_t mismatched = 0;

	for (uint32_t i = 0; i < index_vec->size; ++i) {
		index_param *index = as_vector_get(index_vec, i);
		path_param *path = as_vector_get(&index->path_vec, 0);

		if (!check_set(index->set, set_vec)) {
			if (verbose) {
				ver("Skipping index with unwanted set %s:%s:%s (%s)", index->ns, index->set,
						index->name, path->path);
			}

			++skipped;
			continue;
		}

		if (verbose) {
			ver("Restoring index %s:%s:%s (%s)", index->ns, index->set, index->name, path->path);
		}

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

		index_status stat = check_index(as, index, timeout);

		if (stat == INDEX_STATUS_DIFFERENT) {
			if (verbose) {
				ver("Removing mismatched index %s:%s", index->ns, index->name);
			}

			if (aerospike_index_remove(as, &ae, &policy, index->ns, index->name) != AEROSPIKE_OK) {
				err("Error while removing index %s:%s - code %d: %s at %s:%d", index->ns,
						index->name, ae.code, ae.message, ae.file, ae.line);
				return false;
			}

			// aerospike_index_remove() is asynchronous. Check the index again, because AEROSPIKE_OK
			// doesn't necessarily mean that the index is gone.
			for (int32_t tries = 0; tries < MAX_TRIES; ++tries) {
				sleep(1);
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
			if (verbose) {
				ver("Skipping matched index %s:%s:%s (%s)", index->ns, index->set, index->name,
						path->path);
			}

			++matched;
			continue;

		case INDEX_STATUS_DIFFERENT:
			err("Error while removing mismatched index %s:%s", index->ns, index->name);
			++mismatched;
			continue;
		}

		if (verbose) {
			ver("Creating index %s:%s:%s (%s)", index->ns, index->set, index->name, path->path);
		}

		as_index_task task;

		if (aerospike_index_create_complex(as, &ae, &task, &policy, index->ns,
				index->set[0] == 0 ? NULL : index->set, path->path, index->name, itype,
				dtype) != AEROSPIKE_OK) {
			err("Error while creating index %s:%s:%s (%s) - code %d: %s at %s:%d", index->ns,
					index->set, index->name, path->path, ae.code, ae.message, ae.file, ae.line);
			return false;
		}

		if (wait) {
			if (verbose) {
				ver("Waiting for index %s:%s:%s (%s)", index->ns, index->set, index->name,
						path->path);
			}

			if (aerospike_index_create_wait(&ae, &task, 500) != AEROSPIKE_OK) {
				err("Error while waiting for index %s:%s:%s (%s) - code %d: %s at %s:%d", index->ns,
						index->set, index->name, path->path, ae.code, ae.message, ae.file, ae.line);
				return false;
			}
		}

		++(*count);
	}

	if (skipped > 0) {
		inf("Skipped %d index(es) with unwanted set(s)", skipped);
	}

	if (matched > 0) {
		inf("Skipped %d matched index(es)", matched);
	}

	if (mismatched > 0) {
		err("Skipped %d mismatched index(es)", mismatched);
	}

	return true;
}

///
/// Creates the given UDF files in the cluster.
///
/// @param as       The Aerospike client.
/// @param udf_vec  The UDF files, as a vector of udf_param.
/// @param count    The number of created UDF files.
/// @param wait     Makes the function wait until each UDF file is acknowledged by all cluster
///                 nodes.
/// @param timeout  The timeout for Aerospike command.
///
/// @result         `true`, if successful.
///
static bool
restore_udfs(aerospike *as, as_vector *udf_vec, volatile uint32_t *count, bool wait, uint32_t timeout)
{
	inf("Restoring %d UDF file(s)", udf_vec->size);

	uint32_t not_done = udf_vec->size;
	bool done[udf_vec->size];

	for (uint32_t i = 0; i < udf_vec->size; ++i) {
		done[i] = false;
	}

	bool final = false;

	while (not_done > 0) {
		if (verbose) {
			ver("%s try, %u UDF file(s) left", final ? "Final" : "Non-final", not_done);
		}

		uint32_t per_try = 0;

		for (uint32_t i = 0; i < udf_vec->size; ++i) {
			udf_param *udf = as_vector_get(udf_vec, i);

			if (verbose) {
				ver("%s UDF file %s (size %u)", done[i] ? "Skipping" : "Restoring", udf->name,
						udf->size);
			}

			if (done[i]) {
				continue;
			}

			as_policy_info policy;
			as_policy_info_init(&policy);
			policy.timeout = timeout;
			as_bytes content;
			as_bytes_init_wrap(&content, udf->data, udf->size, false);
			as_error ae;

			if (aerospike_udf_put(as, &ae, &policy, udf->name, udf->type,
					&content) != AEROSPIKE_OK) {
				if (!final) {
					if (verbose) {
						ver("Error, retrying later");
					}

					continue;
				}

				err("Error while putting UDF file %s - code %d: %s at %s:%d", udf->name, ae.code,
						ae.message, ae.file, ae.line);
				*count = udf_vec->size - not_done;
				return false;
			}

			as_bytes_destroy(&content);

			if (wait) {
				if (verbose) {
					ver("Waiting for UDF file %s", udf->name);
				}

				if (aerospike_udf_put_wait(as, &ae, &policy, udf->name, 500) != AEROSPIKE_OK) {
					if (!final) {
						if (verbose) {
							ver("Error, retrying later");
						}

						continue;
					}

					err("Error while waiting for UDF file %s - code %d: %s at %s:%d", udf->name,
							ae.code, ae.message, ae.file, ae.line);
					*count = udf_vec->size - not_done;
					return false;
				}
			}

			++per_try;
			--not_done;
			done[i] = true;
		}

		if (verbose) {
			ver("Restored %u UDF file(s) in this try", per_try);
		}

		final = per_try == 0;
	}

	*count = udf_vec->size - not_done;
	return true;
}

///
/// Scans the given directory for backup files.
///
/// @param dir_path  The path of the directory to be scanned.
/// @param file_vec  The paths of the found backup files, as a vector of strings.
///
/// @result          `true`, if successful.
///
static bool
get_backup_files(const char *dir_path, as_vector *file_vec)
{
	bool res = false;

	if (verbose) {
		ver("Listing backup files in %s", dir_path);
	}

	DIR *dir = opendir(dir_path);

	if (dir == NULL) {
		if (errno == ENOENT) {
			err("Directory %s does not exist", dir_path);
			goto cleanup0;
		}

		err_code("Error while opening directory %s", dir_path);
		goto cleanup0;
	}

	struct dirent *entry;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name + strlen(entry->d_name) - 4, ".asb") == 0) {
			char file_path[PATH_MAX];
			size_t length;

			if ((length = (size_t)snprintf(file_path, sizeof file_path, "%s/%s", dir_path,
					entry->d_name)) >= sizeof file_path) {
				err("File path too long (%s, %s)", dir_path, entry->d_name);
				goto cleanup2;
			}

			char *elem = safe_malloc(length + 1);
			memcpy(elem, file_path, length + 1);
			as_vector_append(file_vec, &elem);
		}
	}

	inf("Found %u backup file(s) in %s", file_vec->size, dir_path);
	res = true;
	goto cleanup1;

cleanup2:
	for (uint32_t i = 0; i < file_vec->size; ++i) {
		cf_free(as_vector_get_ptr(file_vec, i));
	}

	as_vector_clear(file_vec);

cleanup1:
	if (closedir(dir) < 0) {
		err_code("Error while closing directory handle for %s", dir_path);
		res = false;
	}

cleanup0:
	return res;
}

///
/// Parses a `item1[,item2[,...]]` string into a vector of strings.
///
/// @param which  The type of the list to be parsed. Only used in error messages.
/// @param size   Maximal length of each individual list item.
/// @param list   The string to be parsed.
/// @param vec    The populated vector.
///
/// @result       `true`, if successful.
///
static bool
parse_list(const char *which, size_t size, char *list, as_vector *vec)
{
	bool res = false;

	if (list[0] == 0) {
		err("Empty %s list", which);
		goto cleanup0;
	}

	char *clone = safe_strdup(list);
	split_string(list, ',', true, vec);

	for (uint32_t i = 0; i < vec->size; ++i) {
		char *item = as_vector_get_ptr(vec, i);
		size_t len = strlen(item);

		if (len == 0 || len >= size) {
			err("Item with invalid length in %s list %s", which, clone);
			goto cleanup1;
		}
	}

	res = true;

cleanup1:
	cf_free(clone);

cleanup0:
	return res;
}

///
/// Signal handler for `SIGINT` and `SIGTERM`.
///
/// @param sig  The signal number.
///
static void
sig_hand(int32_t sig)
{
	(void)sig;
	err("### Restore interrupted ###");
	stop = true;
}

///
/// Print the tool's version information.
///
static void
print_version(void)
{
	fprintf(stdout, "Aerospike Restore Utility\n");
	fprintf(stdout, "Version %s\n", TOOL_VERSION);
	fprintf(stdout, "C Client Version %s\n", aerospike_client_version);
	fprintf(stdout, "Copyright 2015-2017 Aerospike. All rights reserved.\n");
}

///
/// Displays usage information.
///
/// @param name  The actual name of the `asbackup` binary.
///
static void
usage(const char *name)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", name);
	fprintf(stderr, "------------------------------------------------------------------------------");
	fprintf(stderr, "\n");
	fprintf(stderr, " -V, --version        Print ASRESTORE version information.\n");
	fprintf(stderr, " -O, --options        Print command-line options message.\n");
	fprintf(stderr, " -Z, --usage          Display this message.\n\n");
	fprintf(stderr, " -v, --verbose        Enable verbose output. Default: disabled\n");

	fprintf(stderr, "\n");
	fprintf(stderr, "Configuration File Allowed Options\n");
	fprintf(stderr, "----------------------------------\n\n");

	fprintf(stderr, "[cluster]\n");
	fprintf(stderr, " -h HOST, --host=HOST\n");
	fprintf(stderr, "                      HOST is \"<host1>[:<tlsname1>][:<port1>],...\" \n");
	fprintf(stderr, "                      Server seed hostnames or IP addresses. The tlsname is \n");
	fprintf(stderr, "                      only used when connecting with a secure TLS enabled \n");
	fprintf(stderr, "                      server. Default: localhost:3000\n");
	fprintf(stderr, "                      Examples:\n");
	fprintf(stderr, "                        host1\n");
	fprintf(stderr, "                        host1:3000,host2:3000\n");
	fprintf(stderr, "                        192.168.1.10:cert1:3000,192.168.1.20:cert2:3000\n");
	fprintf(stderr, " --services-alternate\n");
	fprintf(stderr, "                      Use to connect to alternate access address when the \n");
	fprintf(stderr, "                      cluster's nodes publish IP addresses through access-address \n");
	fprintf(stderr, "                      which are not accessible over WAN and alternate IP addresses \n");
	fprintf(stderr, "                      accessible over WAN through alternate-access-address. Default: false.\n");
	fprintf(stderr, " -p PORT, --port=PORT Server default port. Default: 3000\n");
	fprintf(stderr, " -U USER, --user=USER User name used to authenticate with cluster. Default: none\n");
	fprintf(stderr, " -P, --password\n");
	fprintf(stderr, "                      Password used to authenticate with cluster. Default: none\n");
	fprintf(stderr, "                      User will be prompted on command line if -P specified and no\n");
	fprintf(stderr, "      	               password is given.\n");
	fprintf(stdout, " --auth\n");
	fprintf(stdout, "                      Set authentication mode when user/password is defined. Modes are\n");
	fprintf(stdout, "                      (INTERNAL, EXTERNAL, EXTERNAL_INSECURE) and the default is INTERNAL.\n");
	fprintf(stdout, "                      This mode must be set EXTERNAL when using LDAP\n");
	fprintf(stderr, " --tls-enable         Enable TLS on connections. By default TLS is disabled.\n");
	// Deprecated
	//fprintf(stderr, " --tls-encrypt-only   Disable TLS certificate verification.\n");
	fprintf(stderr, " --tls-cafile=TLS_CAFILE\n");
	fprintf(stderr, "                      Path to a trusted CA certificate file.\n");
	fprintf(stderr, " --tls-capath=TLS_CAPATH.\n");
	fprintf(stderr, "                      Path to a directory of trusted CA certificates.\n");
	fprintf(stderr, " --tls-protocols=TLS_PROTOCOLS\n");
	fprintf(stderr, "                      Set the TLS protocol selection criteria. This format\n"
                    "                      is the same as Apache's SSLProtocol documented at http\n"
                    "                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
                    "                      protocol . If not specified the asrestore will use '-all\n"
                    "                      +TLSv1.2' if has support for TLSv1.2,otherwise it will\n"
                    "                      be '-all +TLSv1'.\n");
	fprintf(stderr, " --tls-cipher-suite=TLS_CIPHER_SUITE\n");
	fprintf(stderr, "                     Set the TLS cipher selection criteria. The format is\n"
                	"                     the same as Open_sSL's Cipher List Format documented\n"
                	"                     at https://www.openssl.org/docs/man1.0.2/apps/ciphers.\n"
                	"                     html\n");
	fprintf(stderr, " --tls-keyfile=TLS_KEYFILE\n");
	fprintf(stderr, "                      Path to the key for mutual authentication (if\n"
                    "                      Aerospike Cluster is supporting it).\n");
	fprintf(stderr, " --tls-keyfile-password=TLS_KEYFILE_PASSWORD\n");
	fprintf(stderr, "                      Password to load protected tls-keyfile.\n"
                    "                      It can be one of the following:\n"
                    "                      1) Environment varaible: 'env:<VAR>'\n"
                    "                      2) File: 'file:<PATH>'\n"
                    "                      3) String: 'PASSWORD'\n"
                    "                      Default: none\n"
                    "                      User will be prompted on command line if --tls-keyfile-password\n"
                    "                      specified and no password is given.\n");
	fprintf(stderr, " --tls-certfile=TLS_CERTFILE <path>\n");
	fprintf(stderr, "                      Path to the chain file for mutual authentication (if\n"
                    "                      Aerospike Cluster is supporting it).\n");
	fprintf(stderr, " --tls-cert-blacklist <path>\n");
	fprintf(stderr, "                      Path to a certificate blacklist file. The file should\n"
                    "                      contain one line for each blacklisted certificate.\n"
                    "                      Each line starts with the certificate serial number\n"
                    "                      expressed in hex. Each entry may optionally specify\n"
                    "                      the issuer name of the certificate (serial numbers are\n"
                    "                      only required to be unique per issuer).Example:\n"
                    "                      867EC87482B2\n"
                    "                      /C=US/ST=CA/O=Acme/OU=Engineering/CN=TestChainCA\n");

	fprintf(stderr, " --tls-crl-check      Enable CRL checking for leaf certificate. An error\n"
                	"                      occurs if a valid CRL files cannot be found in\n"
                    "                      tls_capath.\n");
	fprintf(stderr, " --tls-crl-checkall   Enable CRL checking for entire certificate chain. An\n"
                	"                      error occurs if a valid CRL files cannot be found in\n"
                    "                      tls_capath.\n");


	fprintf(stderr, "[asrestore]\n");
	fprintf(stderr, "  -n, --namespace <namespace>\n");
	fprintf(stderr, "                      The namespace to be backed up. Required.\n");
	fprintf(stderr, "  -d, --directory <directory>\n");
	fprintf(stderr, "                      The directory that holds the backup files. Required, \n");
	fprintf(stderr, "                      unless -i is used.\n");
	fprintf(stderr, "  -i, --input-file <file>\n");
	fprintf(stderr, "                      Restore from a single backup file. Use - for stdin.\n");
	fprintf(stderr, "                      Required, unless -d is used.\n");
	fprintf(stderr, "  -t, --threads\n");
	fprintf(stderr, "                      The number of restore threads. Default: 20.\n");
	fprintf(stderr, "  -m, --machine <path>\n");
	fprintf(stderr, "                      Output machine-readable status updates to the given path, \n");
	fprintf(stderr,"                       typically a FIFO.\n");
	fprintf(stderr, "  -B, --bin-list <bin 1>[,<bin 2>[,...]]\n");
	fprintf(stderr, "                      Only restore the given bins in the backup.\n");
	fprintf(stderr, "                      Default: restore all bins.\n");

	fprintf(stderr, "  -s, --set-list <set 1>[,<set 2>[,...]]\n");
	fprintf(stderr, "                      Only restore the given sets from the backup.\n");
	fprintf(stderr, "                      Default: restore all sets.\n");
	fprintf(stderr, "  --ignore-record-error\n");
	fprintf(stderr, "                      Ignore permanent record specific error. e.g AEROSPIKE_RECORD_TOO_BIG.\n");
	fprintf(stderr, "                      By default such errors are not ignored and asrestore terminates.\n");
	fprintf(stderr, "                      Optional: Use verbose mode to see errors in detail. \n");
	fprintf(stderr, "  -u, --unique\n");
	fprintf(stderr, "                      Skip records that already exist in the namespace;\n");
	fprintf(stderr, "                      Don't touch them.\n");
	fprintf(stderr, "  -r, --replace\n");
	fprintf(stderr, "                      Fully replace records that already exist in the \n");
	fprintf(stderr, "                      namespace; don't update them.\n");
	fprintf(stderr, "  -g, --no-generation\n");
	fprintf(stderr, "                      Don't check the generation of records that already\n");
	fprintf(stderr, "                      exist in the namespace.\n");
	fprintf(stderr, "  -N, --nice <bandwidth>,<TPS>\n");
	fprintf(stderr, "                      The limits for read storage bandwidth in MiB/s and \n");
	fprintf(stderr, "                      write operations in TPS.\n");
	fprintf(stderr, "  -R, --no-records\n");
	fprintf(stderr, "                      Don't restore any records.\n");
	fprintf(stderr, "  -I, --no-indexes\n");
	fprintf(stderr, "                      Don't restore any secondary indexes.\n");
	fprintf(stderr, "  -L, --indexes-last\n");
	fprintf(stderr, "                      Restore secondary indexes only after UDFs and records \n");
	fprintf(stderr, "                      have been restored.\n");
	fprintf(stderr, "  -F, --no-udfs\n");
	fprintf(stderr, "                      Don't restore any UDFs.\n");
	fprintf(stderr, "  -w, --wait\n");
	fprintf(stderr, "                      Wait for restored secondary indexes to finish building.\n");
	fprintf(stderr, "                      Wait for restored UDFs to be distributed across the cluster.\n");
	fprintf(stderr, " -T TIMEOUT, --timeout=TIMEOUT\n");
	fprintf(stderr, "                      Set the timeout (ms) for commands. Default: 10000\n");

	fprintf(stderr, "\n\n");
	fprintf(stderr, "Default configuration files are read from the following files in the given order:\n");
	fprintf(stderr, "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n");
	fprintf(stderr, "The following sections are read: (cluster asrestore include)\n");
	fprintf(stderr, "The following options effect configuration file behavior\n");
	fprintf(stderr, " --no-config-file \n");
	fprintf(stderr, "                      Do not read any config file. Default: disabled\n");
	fprintf(stderr, " --instance <name>\n");
	fprintf(stderr, "                      Section with these instance is read. e.g in case instance `a` is specified\n");
	fprintf(stderr, "                      sections cluster_a, asrestore_a is read.\n");
	fprintf(stderr, " --config-file <path>\n");
	fprintf(stderr, "                      Read this file after default configuration file.\n");
	fprintf(stderr, " --only-config-file <path>\n");
	fprintf(stderr, "                      Read only this configuration file.\n");
}


///
/// It all starts here.
///
int32_t
main(int32_t argc, char **argv)
{
	static struct option options[] = {

		// Non Config file options
		{ "verbose", no_argument, NULL, 'v' },
		{ "usage", no_argument, NULL, 'Z' },
		{ "version", no_argument, NULL, 'V' },

		{ "instance", required_argument, 0, CONFIG_FILE_OPT_INSTANCE},
		{ "config-file", required_argument, 0, CONFIG_FILE_OPT_FILE},
		{ "no-config-file", no_argument, 0, CONFIG_FILE_OPT_NO_CONFIG_FILE},
		{ "only-config-file", required_argument, 0, CONFIG_FILE_OPT_ONLY_CONFIG_FILE},

		// Config options
		{ "host", required_argument, 0, 'h'},
		{ "port", required_argument, 0, 'p'},
		{ "user", required_argument, 0, 'U'},
		{ "password", optional_argument, 0, 'P'},
		{ "auth", required_argument, 0, 'A' },

		{ "tlsEnable", no_argument, NULL, TLS_OPT_ENABLE },
		{ "tlsEncryptOnly", no_argument, NULL, TLS_OPT_ENCRYPT_ONLY },
		{ "tlsCaFile", required_argument, NULL, TLS_OPT_CA_FILE },
		{ "tlsCaPath", required_argument, NULL, TLS_OPT_CA_PATH },
		{ "tlsProtocols", required_argument, NULL, TLS_OPT_PROTOCOLS },
		{ "tlsCipherSuite", required_argument, NULL, TLS_OPT_CIPHER_SUITE },
		{ "tlsCrlCheck", no_argument, NULL, TLS_OPT_CRL_CHECK },
		{ "tlsCrlCheckAll", no_argument, NULL, TLS_OPT_CRL_CHECK_ALL },
		{ "tlsCertBlackList", required_argument, NULL, TLS_OPT_CERT_BLACK_LIST },
		{ "tlsLogSessionInfo", no_argument, NULL, TLS_OPT_LOG_SESSION_INFO },
		{ "tlsKeyFile", required_argument, NULL, TLS_OPT_KEY_FILE },
		{ "tlsCertFile", required_argument, NULL, TLS_OPT_CERT_FILE },

		{ "tls-enable", no_argument, NULL, TLS_OPT_ENABLE },
		{ "tls-cafile", required_argument, NULL, TLS_OPT_CA_FILE },
		{ "tls-capath", required_argument, NULL, TLS_OPT_CA_PATH },
		{ "tls-protocols", required_argument, NULL, TLS_OPT_PROTOCOLS },
		{ "tls-cipher-suite", required_argument, NULL, TLS_OPT_CIPHER_SUITE },
		{ "tls-crl-check", no_argument, NULL, TLS_OPT_CRL_CHECK },
		{ "tls-crl-check-all", no_argument, NULL, TLS_OPT_CRL_CHECK_ALL },
		{ "tls-cert-blackList", required_argument, NULL, TLS_OPT_CERT_BLACK_LIST },
		{ "tls-keyfile", required_argument, NULL, TLS_OPT_KEY_FILE },
		{ "tls-keyfile-password", optional_argument, NULL, TLS_OPT_KEY_FILE_PASSWORD },
		{ "tls-certfile", required_argument, NULL, TLS_OPT_CERT_FILE },

		// asrestore section in config file
		{ "namespace", required_argument, NULL, 'n' },
		{ "directory", required_argument, NULL, 'd' },
		{ "input-file", required_argument, NULL, 'i' },
		{ "threads", required_argument, NULL, 't' },
		{ "machine", required_argument, NULL, 'm' },
		{ "bin-list", required_argument, NULL, 'B' },
		{ "set-list", required_argument, NULL, 's' },
		{ "unique", no_argument, NULL, 'u' },
		{ "ignore-record-error", no_argument, NULL, 'K'},
		{ "replace", no_argument, NULL, 'r' },
		{ "no-generation", no_argument, NULL, 'g' },
		{ "nice", required_argument, NULL, 'N' },
		{ "no-records", no_argument, NULL, 'R' },
		{ "no-indexes", no_argument, NULL, 'I' },
		{ "indexes-last", no_argument, NULL, 'L' },
		{ "no-udfs", no_argument, NULL, 'F' },
		{ "wait", no_argument, NULL, 'w' },
		{ "services-alternate", no_argument, NULL, 'S' },
		{ "timeout", required_argument, 0, 'T' },
		{ NULL, 0, NULL, 0 }
	};

	int32_t res = EXIT_FAILURE;

	restore_config conf;
	config_default(&conf);
	
	conf.decoder = &(backup_decoder){ text_parse };


	int32_t optcase;
	uint64_t tmp;

	// option string should start with '-' to avoid argv permutation
	// we need same argv sequence in third check to support space separated optional argument value
	while ((optcase = getopt_long(argc, argv, "-h:Sp:A:U:P::n:d:i:t:vm:B:s:urgN:RILFwVZT:",
			options, 0)) != -1) {
		switch (optcase) {
			case 'V':
				print_version();
				res = EXIT_SUCCESS;
				goto cleanup1;

			case 'Z':
				usage(argv[0]);
				res = EXIT_SUCCESS;
				goto cleanup1;
		}
	}



	char *config_fname = NULL;
	bool read_conf_files = true;
	bool read_only_conf_file = false;
	char *instance = NULL;

	// Reset to optind (internal variable)
	// to parse all options again
	optind = 0;
	while ((optcase = getopt_long(argc, argv, "-h:Sp:A:U:P::n:d:i:t:vm:B:s:urgN:RILFwVZT:",
			options, 0)) != -1) {
		switch (optcase) {

			case CONFIG_FILE_OPT_FILE:
				config_fname = optarg;
				break;

			case CONFIG_FILE_OPT_INSTANCE:
				instance = optarg;
				break;

			case CONFIG_FILE_OPT_NO_CONFIG_FILE:
				read_conf_files = false;
				break;

			case CONFIG_FILE_OPT_ONLY_CONFIG_FILE:
				config_fname = optarg;
				read_only_conf_file = true;
				break;

		}
	}

	if (read_conf_files) {
		if (read_only_conf_file) {
			if (! config_from_file(&conf, instance, config_fname, 0, false)) {
				return false;
			}
		} else {
			if (! config_from_files(&conf, instance, config_fname, false)) {
				return false;
			}
		}
	} else {
		if (read_only_conf_file) {
			fprintf(stderr, "--no-config-file and only-config-file are mutually exclusive option. Please enable only one.\n");
			return false;
		}
	}

	// Reset to optind (internal variable)
	// to parse all options again
	optind = 0;
	while ((optcase = getopt_long(argc, argv, "h:Sp:A:U:P::n:d:i:t:vm:B:s:KurgN:RILFwVZT:",
			options, 0)) != -1) {
		switch (optcase) {
		case 'h':
			conf.host = optarg;
			break;

		case 'p':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > 65535) {
				err("Invalid port value %s", optarg);
				goto cleanup1;
			}

			conf.port = (int32_t)tmp;
			break;

		case 'U':
			conf.user = optarg;
			break;

		case 'P':
			if (optarg) {
				conf.password = optarg;
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					conf.password = argv[optind++];
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf.password = DEFAULTPASSWORD;
				}
			}
			break;

		case 'A':
			conf.auth_mode = optarg;
			break;

		case 'n':
			conf.ns_list = safe_strdup(optarg);
			break;

		case 'd':
			conf.directory = optarg;
			break;

		case 'i':
			conf.input_file = safe_strdup(optarg);
			break;

		case 't':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > MAX_THREADS) {
				err("Invalid threads value %s", optarg);
				goto cleanup1;
			}

			conf.threads = (uint32_t)tmp;
			break;

		case 'v':
			if (verbose) {
				enable_client_log();
			} else {
				verbose = true;
			}

			break;

		case 'm':
			conf.machine = optarg;
			break;

		case 'B':
			conf.bin_list = safe_strdup(optarg);
			break;

		case 's':
			conf.set_list = safe_strdup(optarg);
			break;

		case 'K':
			conf.ignore_rec_error = true;
			break;

		case 'u':
			conf.unique = true;
			break;

		case 'r':
			conf.replace = true;
			break;

		case 'g':
			conf.no_generation = true;
			break;

		case 'N':
			conf.nice_list = safe_strdup(optarg);
			break;

		case 'R':
			conf.no_records = true;
			break;

		case 'I':
			conf.no_indexes = true;
			break;

		case 'L':
			conf.indexes_last = true;
			break;

		case 'F':
			conf.no_udfs = true;
			break;

		case 'w':
			conf.wait = true;
			break;

		case 'S':
			conf.use_services_alternate = true;
			break;

		case TLS_OPT_ENABLE:
			conf.tls.enable = true;
			break;

		case TLS_OPT_CA_FILE:
			conf.tls.cafile = safe_strdup(optarg);
			break;

		case TLS_OPT_CA_PATH:
			conf.tls.capath = safe_strdup(optarg);
			break;

		case TLS_OPT_PROTOCOLS:
			conf.tls.protocols = safe_strdup(optarg);
			break;

		case TLS_OPT_CIPHER_SUITE:
			conf.tls.cipher_suite = safe_strdup(optarg);
			break;

		case TLS_OPT_CRL_CHECK:
			conf.tls.crl_check = true;
			break;

		case TLS_OPT_CRL_CHECK_ALL:
			conf.tls.crl_check_all = true;
			break;

		case TLS_OPT_CERT_BLACK_LIST:
			conf.tls.cert_blacklist = safe_strdup(optarg);
			break;

		case TLS_OPT_LOG_SESSION_INFO:
			conf.tls.log_session_info = true;
			break;

		case TLS_OPT_KEY_FILE:
			conf.tls.keyfile = safe_strdup(optarg);
			break;

		case TLS_OPT_KEY_FILE_PASSWORD:
			if (optarg) {
				conf.tls.keyfile_pw = safe_strdup(optarg);
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					conf.tls.keyfile_pw = safe_strdup(argv[optind++]);
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf.tls.keyfile_pw = safe_strdup(DEFAULTPASSWORD);
				}
			}
			break;

		case TLS_OPT_CERT_FILE:
			conf.tls.certfile = safe_strdup(optarg);
			break;

		case 'T':
			if (!better_atoi(optarg, &tmp)) {
				err("Invalid timeout value %s", optarg);
				goto cleanup1;
			}

			conf.timeout = (uint32_t)tmp;
			break;

		case CONFIG_FILE_OPT_FILE:
		case CONFIG_FILE_OPT_INSTANCE:
		case CONFIG_FILE_OPT_NO_CONFIG_FILE:
		case CONFIG_FILE_OPT_ONLY_CONFIG_FILE:
			break;

		default:
			usage(argv[0]);
			goto cleanup1;
		}
	}

	if (optind < argc) {
		err("Unexpected trailing argument %s", argv[optind]);
		goto cleanup1;
	}

	if (conf.directory != NULL && conf.input_file != NULL) {
		err("Invalid options: --directory and --input-file are mutually exclusive.");
		goto cleanup1;
	}

	if (conf.directory == NULL && conf.input_file == NULL) {
		err("Please specify a directory (-d option) or an input file (-i option)");
		goto cleanup1;
	}

	if (conf.unique && (conf.replace || conf.no_generation)) {
		err("Invalid options: --unique is mutually exclusive with --replace and --no-generation.");
		goto cleanup1;
	}

	signal(SIGINT, sig_hand);
	signal(SIGTERM, sig_hand);

	inf("Starting restore to %s (bins: %s, sets: %s) from %s", conf.host,
			conf.bin_list == NULL ? "[all]" : conf.bin_list,
			conf.set_list == NULL ? "[all]" : conf.set_list,
			conf.input_file != NULL ?
					strcmp(conf.input_file, "-") == 0 ? "[stdin]" : conf.input_file :
					conf.directory);

	FILE *mach_fd = NULL;

	if (conf.machine != NULL && (mach_fd = fopen(conf.machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf.machine);
		goto cleanup1;
	}

	as_config as_conf;
	as_config_init(&as_conf);
	as_conf.conn_timeout_ms = conf.timeout;
	as_conf.use_services_alternate = conf.use_services_alternate;

	if (!as_config_add_hosts(&as_conf, conf.host, (uint16_t)conf.port)) {
		err("Invalid host(s) string %s", conf.host);
		goto cleanup2;
	}

	if (conf.auth_mode && ! as_auth_mode_from_string(&as_conf.auth_mode, conf.auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / EXTERNAL / EXTERNAL_INSECURE\n",
				conf.auth_mode);
		goto cleanup2;
	}

	if (conf.user) {
		if (strcmp(conf.password, DEFAULTPASSWORD) == 0) {
			conf.password = getpass("Enter Password: ");
		}

		if (! as_config_set_user(&as_conf, conf.user, conf.password)) {
			printf("Invalid password for user name `%s`\n", conf.user);
			goto cleanup2;
		}
	}

	if (conf.tls.keyfile && conf.tls.keyfile_pw) {
		if (strcmp(conf.tls.keyfile_pw, DEFAULTPASSWORD) == 0) {
			conf.tls.keyfile_pw = getpass("Enter TLS-Keyfile Password: ");
		}

		if (!tls_read_password(conf.tls.keyfile_pw, &conf.tls.keyfile_pw)) {
			goto cleanup2;
		}
	}

	memcpy(&as_conf.tls, &conf.tls, sizeof(as_config_tls));
	memset(&conf.tls, 0, sizeof(conf.tls));

	aerospike as;
	aerospike_init(&as, &as_conf);
	conf.as = &as;
	as_error ae;

	if (verbose) {
		ver("Connecting to cluster");
	}

	if (aerospike_connect(&as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d", conf.host, conf.port, ae.code,
				ae.message, ae.file, ae.line);
		goto cleanup3;
	}

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names;
	get_node_names(as.cluster, NULL, 0, &node_names, &n_node_names);

	inf("Processing %u node(s)", n_node_names);
	conf.estimated_bytes = 0;
	cf_atomic64_set(&conf.total_bytes, 0);
	cf_atomic64_set(&conf.total_records, 0);
	cf_atomic64_set(&conf.expired_records, 0);
	cf_atomic64_set(&conf.skipped_records, 0);
	cf_atomic64_set(&conf.ignored_records, 0);
	cf_atomic64_set(&conf.inserted_records, 0);
	cf_atomic64_set(&conf.existed_records, 0);
	cf_atomic64_set(&conf.fresher_records, 0);
	cf_atomic64_set(&conf.backoff_count, 0);
	conf.index_count = 0;
	conf.udf_count = 0;

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = &conf;
	counter_args.node_names = node_names;
	counter_args.n_node_names = n_node_names;
	counter_args.mach_fd = mach_fd;

	if (verbose) {
		ver("Creating counter thread");
	}

	if (pthread_create(&counter_thread, NULL, counter_thread_func, &counter_args) != 0) {
		err_code("Error while creating counter thread");
		goto cleanup4;
	}

	pthread_t restore_threads[MAX_THREADS];
	restore_thread_args restore_args;
	restore_args.conf = &conf;
	restore_args.path = NULL;
	restore_args.shared_fd = NULL;
	restore_args.line_no = NULL;
	restore_args.legacy = false;
	cf_queue *job_queue = cf_queue_create(sizeof (restore_thread_args), true);

	if (job_queue == NULL) {
		err_code("Error while allocating job queue");
		goto cleanup5;
	}

	uint32_t line_no;
	void *fd_buf = NULL;
	as_vector file_vec, index_vec, udf_vec, ns_vec, nice_vec, bin_vec, set_vec;
	as_vector_inita(&file_vec, sizeof (void *), 25)
	as_vector_inita(&index_vec, sizeof (index_param), 25);
	as_vector_inita(&udf_vec, sizeof (udf_param), 25);
	as_vector_inita(&ns_vec, sizeof (void *), 25);
	as_vector_inita(&nice_vec, sizeof (void *), 25);
	as_vector_inita(&bin_vec, sizeof (void *), 25);
	as_vector_inita(&set_vec, sizeof (void *), 25);

	if (conf.ns_list != NULL && !parse_list("namespace", AS_MAX_NAMESPACE_SIZE, conf.ns_list,
			&ns_vec)) {
		err("Error while parsing namespace list");
		goto cleanup6;
	}

	if (ns_vec.size > 2) {
		err("Invalid namespace option");
		goto cleanup6;
	}

	if (conf.nice_list != NULL) {
		if (!parse_list("nice", 10, conf.nice_list, &nice_vec)) {
			err("Error while parsing nice list");
			goto cleanup6;
		}

		if (nice_vec.size != 2) {
			err("Invalid nice option");
			goto cleanup6;
		}

		char *item0 = as_vector_get_ptr(&nice_vec, 0);
		char *item1 = as_vector_get_ptr(&nice_vec ,1);

		if (!better_atoi(item0, &tmp) || tmp < 1) {
			err("Invalid bandwidth value %s", item0);
			goto cleanup6;
		}

		conf.bandwidth = tmp * 1024 * 1024;

		if (!better_atoi(item1, &tmp) || tmp < 1 || tmp > 1000000000) {
			err("Invalid TPS value %s", item1);
			goto cleanup6;
		}

		conf.tps = (uint32_t)tmp;
	}

	conf.bytes_limit = conf.bandwidth;
	conf.records_limit = conf.tps;

	if (conf.bin_list != NULL && !parse_list("bin", AS_BIN_NAME_MAX_SIZE, conf.bin_list,
			&bin_vec)) {
		err("Error while parsing bin list");
		goto cleanup6;
	}

	if (conf.set_list != NULL && !parse_list("set", AS_SET_MAX_SIZE, conf.set_list, &set_vec)) {
		err("Error while parsing set list");
		goto cleanup6;
	}

	restore_args.ns_vec = &ns_vec;
	restore_args.bin_vec = &bin_vec;
	restore_args.set_vec = &set_vec;

	// restoring from a directory
	if (conf.directory != NULL) {
		if (!get_backup_files(conf.directory, &file_vec)) {
			err("Error while getting backup files");
			goto cleanup6;
		}

		if (file_vec.size == 0) {
			err("No backup files found");
			goto cleanup6;
		}

		if (!conf.no_indexes || !conf.no_udfs) {
			if (verbose) {
				ver("Triaging %u backup file(s)", file_vec.size);
			}

			for (uint32_t i = 0; i < file_vec.size; ++i) {
				char *path = as_vector_get_ptr(&file_vec, i);
				FILE *fd;
				bool first;
				off_t size;
				bool legacy;

				if (!open_file(path, restore_args.ns_vec, &fd, &fd_buf, &legacy, &line_no, &first,
						NULL, &size)) {
					err("Error while triaging backup file %s [1]", path);
					goto cleanup7;
				}

				if (!conf.no_records) {
					conf.estimated_bytes += size;
				}

				// backup file contains a META_FIRST_FILE tag, so it may contain secondary index
				// information and UDF files
				if (first) {
					if (verbose) {
						ver("Found first backup file: %s", path);
					}

					// read secondary index information and UDF files into index_vec and udf_vec
					if (!get_indexes_and_udfs(fd, restore_args.ns_vec, legacy, &conf, &line_no,
							NULL, conf.no_indexes ? NULL : &index_vec, conf.no_udfs ? NULL : &udf_vec)) {
						err("Error while reading index and UDF info from backup file %s", path);
						close_file(&fd, &fd_buf);
						goto cleanup7;
					}
				}

				if (!close_file(&fd, &fd_buf)) {
					err("Error while triaging backup file %s [2]", path);
					goto cleanup8;
				}
			}
		}

		if (verbose) {
			ver("Pushing %u exclusive job(s) to job queue", file_vec.size);
		}

		// push a job for each backup file
		for (uint32_t i = 0; i < file_vec.size; ++i) {
			restore_args.path = as_vector_get_ptr(&file_vec, i);

			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup8;
			}
		}

		if (file_vec.size < conf.threads) {
			conf.threads = file_vec.size;
		}
	// restoring from a single backup file
	} else {
		inf("Restoring %s", conf.input_file);

		// open the file, file descriptor goes to restore_args.shared_fd
		if (!open_file(conf.input_file, restore_args.ns_vec, &restore_args.shared_fd, &fd_buf,
				&restore_args.legacy, &line_no, NULL, &conf.total_bytes,
				conf.no_records ? NULL : &conf.estimated_bytes)) {
			err("Error while opening shared backup file");
			goto cleanup6;
		}

		if (verbose) {
			ver("Pushing %u shared job(s) to job queue", conf.threads);
		}

		// read secondary index information and UDF files into index_vec and udf_vec
		if ((!conf.no_indexes || !conf.no_udfs) && !get_indexes_and_udfs(restore_args.shared_fd,
				restore_args.ns_vec, restore_args.legacy, &conf, &line_no, &conf.total_bytes,
				conf.no_indexes ? NULL : &index_vec, conf.no_udfs ? NULL : &udf_vec)) {
			err("Error while reading index and UDF info from backup file %s", conf.input_file);
			goto cleanup7;
		}

		restore_args.line_no = &line_no;
		restore_args.path = conf.input_file;

		// push an identical job for each thread; all threads use restore_args.shared_fd for reading
		for (uint32_t i = 0; i < conf.threads; ++i) {
			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup8;
			}
		}
	}

	if (!conf.no_udfs && !restore_udfs(&as, &udf_vec, &conf.udf_count, conf.wait, conf.timeout)) {
		err("Error while restoring UDFs to cluster");
		goto cleanup8;
	}

	if (!conf.no_indexes && !conf.indexes_last &&
			!restore_indexes(&as, &index_vec, &set_vec, &conf.index_count, conf.wait, conf.timeout)) {
		err("Error while restoring secondary indexes to cluster");
		goto cleanup8;
	}

	if (conf.no_records) {
		res = EXIT_SUCCESS;
		goto cleanup9;
	}

	inf("Restoring records");
	uint32_t threads_ok = 0;

	if (verbose) {
		ver("Creating %u restore thread(s)", conf.threads);
	}

	for (uint32_t i = 0; i < conf.threads; ++i) {
		if (pthread_create(&restore_threads[i], NULL, restore_thread_func, job_queue) != 0) {
			err_code("Error while creating restore thread");
			goto cleanup10;
		}

		++threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup10:
	if (verbose) {
		ver("Waiting for %u restore thread(s)", threads_ok);
	}

	void *thread_res;

	for (uint32_t i = 0; i < threads_ok; i++) {
		if (pthread_join(restore_threads[i], &thread_res) != 0) {
			err_code("Error while joining restore thread");
			stop = true;
			res = EXIT_FAILURE;
		}

		if (thread_res != (void *)EXIT_SUCCESS) {
			if (verbose) {
				ver("Restore thread failed");
			}

			res = EXIT_FAILURE;
		}
	}

cleanup9:
	if (res == EXIT_SUCCESS && !conf.no_indexes && conf.indexes_last &&
			!restore_indexes(&as, &index_vec, &set_vec, &conf.index_count, conf.wait, conf.timeout)) {
		err("Error while restoring secondary indexes to cluster");
		res = EXIT_FAILURE;
	}

cleanup8:
	free_indexes(&index_vec);
	free_udfs(&udf_vec);

cleanup7:
	if (conf.directory != NULL) {
		for (uint32_t i = 0; i < file_vec.size; ++i) {
			cf_free(as_vector_get_ptr(&file_vec, i));
		}
	} else if (!close_file(&restore_args.shared_fd, &fd_buf)) {
		err("Error while closing shared backup file");
		res = EXIT_FAILURE;
	}

cleanup6:
	as_vector_destroy(&set_vec);
	as_vector_destroy(&bin_vec);
	as_vector_destroy(&nice_vec);
	as_vector_destroy(&ns_vec);
	as_vector_destroy(&udf_vec);
	as_vector_destroy(&index_vec);
	as_vector_destroy(&file_vec);
	cf_queue_destroy(job_queue);

cleanup5:
	stop = true;

	if (verbose) {
		ver("Waiting for counter thread");
	}

	if (pthread_join(counter_thread, NULL) != 0) {
		err_code("Error while joining counter thread");
		res = EXIT_FAILURE;
	}

cleanup4:
	if (node_names != NULL) {
		cf_free(node_names);
	}

	aerospike_close(&as, &ae);

cleanup3:
	aerospike_destroy(&as);

cleanup2:
	if (mach_fd != NULL) {
		fclose(mach_fd);
	}

cleanup1:
	if (conf.set_list != NULL) {
		cf_free(conf.set_list);
	}

	if (conf.bin_list != NULL) {
		cf_free(conf.bin_list);
	}

	if (conf.ns_list != NULL) {
		cf_free(conf.ns_list);
	}

	if (conf.input_file != NULL) {
		cf_free(conf.input_file);
	}

	if (conf.nice_list != NULL) {
		cf_free(conf.nice_list);
	}

	if (conf.tls.cafile != NULL) {
		cf_free(conf.tls.cafile);
	}

	if (conf.tls.capath != NULL) {
		cf_free(conf.tls.capath);
	}

	if (conf.tls.protocols != NULL) {
		cf_free(conf.tls.protocols);
	}

	if (conf.tls.cipher_suite != NULL) {
		cf_free(conf.tls.cipher_suite);
	}

	if (conf.tls.cert_blacklist != NULL) {
		cf_free(conf.tls.cert_blacklist);
	}

	if (conf.tls.keyfile != NULL) {
		cf_free(conf.tls.keyfile);
	}

	if (conf.tls.keyfile_pw != NULL) {
		cf_free(conf.tls.keyfile_pw);
	}

	if (conf.tls.certfile != NULL) {
		cf_free(conf.tls.certfile);
	}

	if (verbose) {
		ver("Exiting with status code %d", res);
	}

	return res;
}

static void
config_default(restore_config *conf)
{
	conf->host = DEFAULT_HOST;
	conf->use_services_alternate = false;
	conf->port = DEFAULT_PORT;
	conf->user = NULL;
	conf->password = DEFAULTPASSWORD;
	conf->auth_mode = NULL;

	conf->threads = DEFAULT_THREADS;
	conf->nice_list = NULL;
	conf->no_records = false;
	conf->no_indexes = false;
	conf->indexes_last = false;
	conf->no_udfs = false;
	conf->wait = false;
	conf->ns_list = NULL;
	conf->directory = NULL;
	conf->input_file = NULL;
	conf->machine = NULL;
	conf->bin_list = NULL;
	conf->set_list = NULL;
	conf->ignore_rec_error = false;
	conf->unique = false;
	conf->replace = false;
	conf->no_generation = false;
	conf->bandwidth = 0;
	conf->tps = 0;
	conf->timeout = TIMEOUT;
	memset(&conf->tls, 0, sizeof(as_config_tls));
};

static void
print_stat(per_thread_context *ptc, cf_clock *prev_log, uint64_t *prev_records,	
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
