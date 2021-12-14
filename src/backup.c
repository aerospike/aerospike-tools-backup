/*
 * Copyright 2015-2021 Aerospike, Inc.
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

#include <getopt.h>

#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"

#include <aerospike/as_exp.h>

#pragma GCC diagnostic warning "-Wconversion"
#pragma GCC diagnostic warning "-Wsign-conversion"

#include <backup.h>
#include <backup_state.h>
#include <enc_text.h>
#include <utils.h>
#include <conf.h>


//==========================================================
// Typedefs & constants.
//

#define OPTIONS_SHORT "h:Sp:A:U:P::n:s:d:o:c:F:rvxCB:l:X:D:M:m:eN:RIuVZa:b:L:q:w:z:y:f:"


// The C client's version string
extern char *aerospike_client_version;

static pthread_mutex_t g_stop_lock;
static pthread_cond_t g_stop_cond;
// Makes background threads exit.
static bool g_stop = false;

// Indicates that the one-time work (secondary indexes and UDF files) is complete.
// This variable shares the stop lock/condvar so that stop() calls will interrupt
// threads waiting on the one shot condition.
static bool g_one_shot_done = false;

// Used by threads when writing to one file to ensure mutual exclusion on access
// to the file
static pthread_mutex_t file_write_mutex = PTHREAD_MUTEX_INITIALIZER;
// Used by the counter thread to signal newly available bandwidth to the backup
// threads.
static pthread_cond_t bandwidth_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t bandwidth_mutex = PTHREAD_MUTEX_INITIALIZER;

// Used when reading/updating rec_count_total_committed/byte_count_total_committed
// in the global backup_config_t, since these values must always be read/updated
// together
static pthread_mutex_t committed_count_mutex = PTHREAD_MUTEX_INITIALIZER;

static backup_config_t* g_conf;

// If g_backup_state is set to this, the backup has been aborted and should not
// be saved.
#define BACKUP_STATE_ABORTED ((backup_state_t*) -0x1LU)
static backup_state_t* g_backup_state = NULL;


//==========================================================
// Forward Declarations.
//

static bool one_shot_done(void);
static void wait_one_shot(void);
static void signal_one_shot(void);
static bool has_stopped(void);
static void stop(void);
static void stop_nolock(void);
static void stop_counter(void);
static void abort_backup(void);
static void sleep_for(uint64_t n_secs);
static void disk_space_check(const char *dir, uint64_t disk_space);
static int update_file_pos(io_write_proxy_t* fd, uint64_t* byte_count_file,
		uint64_t* byte_count_job, uint64_t* byte_count_total);
static int update_shared_file_pos(io_write_proxy_t* fd,
		uint64_t* byte_count_total);
static bool close_file(io_write_proxy_t *fd);
static bool open_file(const char *file_path, const char *ns,
		uint64_t disk_space, io_write_proxy_t *fd,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey);
static bool close_dir_file(backup_job_context_t *bjc);
static bool open_dir_file(backup_job_context_t *bjc);
static char* gen_backup_state_file_path(const backup_config_t* conf);
static bool init_backup_state_file(void);
static backup_state_t* load_backup_state(const char* state_file_path);
static void save_scan_state(const as_partitions_status*);
static void save_job_state(const backup_thread_args_t* args);
static bool complete_job(cf_queue* complete_queue, const backup_thread_args_t*);
static as_scan* prepare_scan(as_scan* scan, const backup_job_context_t* bjc);
static bool scan_callback(const as_val *val, void *cont);
static bool process_secondary_indexes(backup_job_context_t *bjc);
static bool process_udfs(backup_job_context_t *bjc);
static void * backup_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static bool prepare_output_file(const char *file_path, bool clear);
static bool prepare_directory(const char *dir_path);
static bool scan_directory(const backup_config_t* conf, backup_status_t* status);
static bool sort_partition_filters(as_vector* partition_ranges);
static bool parse_partition_range(char *str, as_partition_filter *range);
static bool parse_digest(const char *str, as_partition_filter *filter);
static bool parse_partition_list(char *partition_list, as_vector *partition_filters);
static bool parse_after_digest(char *str, as_vector* partition_filters);
static bool parse_node_list(char *node_list, node_spec **node_specs,
		uint32_t *n_node_specs);
static bool narrow_partition_filters(backup_state_t* state,
		as_vector* partition_filters);
static bool parse_sets(const as_vector* set_list, char* set_name,
		exp_component_t* set_list_expr);
static bool calc_node_list_partitions(as_cluster *clust, const as_namespace ns,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names,
		as_vector* partition_filters);
static bool init_scan_bins(char *bin_list, as_scan *scan);
static void add_default_tls_host(as_config *as_conf, const char* tls_name);
static bool check_for_ldt_callback(void *context_, const char *key, const char *value);
static bool check_for_ldt(aerospike *as, const char *namespace,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, bool *has_ldt);
static bool check_server_version(backup_status_t* status, const backup_config_t* conf);
static bool ns_count_callback(void *context_, const char *key, const char *value);
static bool set_count_callback(void *context_, const char *key_, const char *value_);
static bool get_object_count(aerospike *as, const char *namespace, as_vector* set_list,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, uint64_t *obj_count);
static void show_estimate(FILE *mach_fd, uint64_t *samples, uint32_t n_samples,
		uint64_t rec_count_estimate, io_write_proxy_t* fd);
static void sig_hand(int32_t sig);
static int32_t safe_join(pthread_t thread, void **thread_res);
static void print_version(void);
static void usage(const char *name);


//==========================================================
// Public API.
//

int32_t
backup_main(int32_t argc, char **argv)
{
	static struct option options[] = {

		// Non Config file options
		{ "verbose", no_argument, NULL, 'v' },
		{ "usage", no_argument, NULL, 'Z' },
		{ "help", no_argument, NULL, 'Z' },
		{ "options", no_argument, NULL, 'Z' },
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
		{ "tlsName", required_argument, NULL, TLS_OPT_NAME },
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
		{ "tls-name", required_argument, NULL, TLS_OPT_NAME },
		{ "tls-cafile", required_argument, NULL, TLS_OPT_CA_FILE },
		{ "tls-capath", required_argument, NULL, TLS_OPT_CA_PATH },
		{ "tls-protocols", required_argument, NULL, TLS_OPT_PROTOCOLS },
		{ "tls-cipher-suite", required_argument, NULL, TLS_OPT_CIPHER_SUITE },
		{ "tls-crl-check", no_argument, NULL, TLS_OPT_CRL_CHECK },
		{ "tls-crl-check-all", no_argument, NULL, TLS_OPT_CRL_CHECK_ALL },
		{ "tls-cert-blacklist", required_argument, NULL, TLS_OPT_CERT_BLACK_LIST },
		{ "tls-log-session-info", no_argument, NULL, TLS_OPT_LOG_SESSION_INFO },
		{ "tls-keyfile", required_argument, NULL, TLS_OPT_KEY_FILE },
		{ "tls-keyfile-password", optional_argument, NULL, TLS_OPT_KEY_FILE_PASSWORD },
		{ "tls-certfile", required_argument, NULL, TLS_OPT_CERT_FILE },

		// asbackup section in config file
		{ "compact", no_argument, NULL, 'C' },
		{ "parallel", required_argument, NULL, 'w' },
		{ "compress", required_argument, NULL, 'z' },
		{ "encrypt", required_argument, NULL, 'y' },
		{ "encryption-key-file", required_argument, NULL, '1' },
		{ "encryption-key-env", required_argument, NULL, '2' },
		{ "no-bins", no_argument, NULL, 'x' },
		{ "bin-list", required_argument, NULL, 'B' },
		{ "node-list", required_argument, NULL, 'l' },
		{ "no-records", no_argument, NULL, 'R' },
		{ "no-indexes", no_argument, NULL, 'I' },
		{ "no-udfs", no_argument, NULL, 'u' },
		{ "services-alternate", no_argument, NULL, 'S' },
		{ "namespace", required_argument, NULL, 'n' },
		{ "set", required_argument, NULL, 's' },
		{ "directory", required_argument, NULL, 'd' },
		{ "output-file", required_argument, NULL, 'o' },
		{ "output-file-prefix", required_argument, NULL, 'q' },
		{ "continue", required_argument, NULL, 'c' },
		{ "state-file-dst", required_argument, NULL, '3' },
		{ "file-limit", required_argument, NULL, 'F' },
		{ "remove-files", no_argument, NULL, 'r' },
		{ "partition-list", required_argument, NULL, 'X' },
		{ "after-digest", required_argument, NULL, 'D' },
		{ "filter-exp", required_argument, NULL, 'f' },
		{ "modified-after", required_argument, NULL, 'a' },
		{ "modified-before", required_argument, NULL, 'b' },
		{ "no-ttl-only", no_argument, NULL, COMMAND_OPT_NO_TTL_ONLY },
		{ "records-per-second", required_argument, NULL, 'L' },
		{ "max-records", required_argument, NULL, 'M' },
		{ "machine", required_argument, NULL, 'm' },
		{ "estimate", no_argument, NULL, 'e' },
		{ "nice", required_argument, NULL, 'N' },
		{ "socket-timeout", required_argument, NULL, COMMAND_OPT_SOCKET_TIMEOUT },
		{ "total-timeout", required_argument, NULL, COMMAND_OPT_TOTAL_TIMEOUT },
		{ "max-retries", required_argument, NULL, COMMAND_OPT_MAX_RETRIES },
		{ "sleep-between-retries", required_argument, NULL, COMMAND_OPT_RETRY_DELAY },
		// support the `--retry-delay` option until a major version bump.
		{ "retry-delay", required_argument, NULL, COMMAND_OPT_RETRY_DELAY },
		{ NULL, 0, NULL, 0 }
	};

	int32_t res = EXIT_FAILURE;

	bool do_backup_save_state = false;

	enable_client_log();

	backup_config_t conf;
	backup_config_default(&conf);
	g_conf = &conf;

	int32_t opt;
	uint64_t tmp;

	// Don't print error messages for the first two argument parsers
	opterr = 0;

	// Option string should start with '-' to avoid argv permutation.
	// We need same argv sequence in third check to support space separated
	// optional argument value.
	while ((opt = getopt_long(argc, argv, "-" OPTIONS_SHORT, options, 0)) != -1) {

		switch (opt) {
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

	// Reset optind (internal variable) to parse all options again
	optind = 1;
	while ((opt = getopt_long(argc, argv, "-" OPTIONS_SHORT, options, 0)) != -1) {
		switch (opt) {

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
			if (! config_from_file(&conf, instance, config_fname, 0, true)) {
				return false;
			}
		} else {
			if (! config_from_files(&conf, instance, config_fname, true)) {
				return false;
			}
		}
	} else { 
		if (read_only_conf_file) {
			err("--no-config-file and only-config-file are mutually exclusive "
					"option. Please enable only one.");
			return false;
		}
	}

	// Now print error messages
	opterr = 1;
	// Reset optind (internal variable) to parse all options again
	optind = 1;
	while ((opt = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {
		switch (opt) {
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
			as_strncpy(conf.ns, optarg, AS_NAMESPACE_MAX_SIZE);
			break;

		case 's':
			if (!parse_set_list(&conf.set_list, optarg)) {
				goto cleanup1;
			}
			break;

		case 'd':
			conf.directory = optarg;
			break;

		case 'q':
			conf.prefix = optarg;
			break;

		case 'c':
			conf.state_file = safe_strdup(optarg);
			break;

		case '3':
			conf.state_file_dst = safe_strdup(optarg);
			break;

		case 'o':
			conf.output_file = optarg;
			break;

		case 'F':
			if (!better_atoi(optarg, &tmp) || tmp < 1) {
				err("Invalid file limit value %s", optarg);
				goto cleanup1;
			}

			conf.file_limit = tmp * 1024 * 1024;
			break;

		case 'r':
			conf.remove_files = true;
			break;

		case 'L':
			if (!better_atoi(optarg, &tmp)) {
				err("Invalid records-per-second value %s", optarg);
				goto cleanup1;
			}

			conf.records_per_second = (uint32_t)tmp;
			break;

		case 'v':
			as_log_set_level(AS_LOG_LEVEL_TRACE);
			verbose = true;
			break;

		case 'x':
			conf.no_bins = true;
			break;

		case 'C':
			conf.compact = true;
			break;

		case 'w':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > MAX_PARALLEL) {
				err("Invalid parallelism value %s", optarg);
				goto cleanup1;
			}
			conf.parallel = (int32_t) tmp;
			break;

		case 'z':
			if (parse_compression_type(optarg, &conf.compress_mode) != 0) {
				err("Invalid compression type \"%s\"", optarg);
				goto cleanup1;
			}
			break;

		case 'y':
			if (parse_encryption_type(optarg, &conf.encrypt_mode) != 0) {
				err("Invalid encryption type \"%s\"", optarg);
				goto cleanup1;
			}
			break;

		case '1':
			// encryption key file
			if (conf.pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env");
				goto cleanup1;
			}
			conf.pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
			if (io_proxy_read_private_key_file(optarg, conf.pkey) != 0) {
				goto cleanup1;
			}
			break;

		case '2':
			// encryption key environment variable
			if (conf.pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env");
				goto cleanup1;
			}
			conf.pkey = parse_encryption_key_env(optarg);
			if (conf.pkey == NULL) {
				goto cleanup1;
			}
			break;

		case 'B':
			conf.bin_list = safe_strdup(optarg);
			break;

		case 'l':
			conf.node_list = safe_strdup(optarg);
			break;

		case 'X':
			conf.partition_list = safe_strdup(optarg);
			break;

		case 'D':
			conf.after_digest = safe_strdup(optarg);
			break;

		case 'f':
			conf.filter_exp = safe_strdup(optarg);
			break;

		case 'M':
			if (!better_atoi(optarg, &tmp)) {
				err("Invalid max-records value %s", optarg);
				goto cleanup1;
			}

			conf.max_records = tmp;
			break;

		case 'm':
			conf.machine = optarg;
			break;

		case 'e':
			conf.estimate = true;
			break;

		case 'N':
			if (!better_atoi(optarg, &tmp) || tmp < 1) {
				err("Invalid bandwidth value %s", optarg);
				goto cleanup1;
			}

			conf.bandwidth = tmp * 1024 * 1024;
			break;

		case 'R':
			conf.no_records = true;
			break;

		case 'I':
			conf.no_indexes = true;
			break;

		case 'u':
			conf.no_udfs = true;
			break;

		case 'S':
			conf.use_services_alternate = true;
			break;

		case TLS_OPT_ENABLE:
			conf.tls.enable = true;
			break;

		case TLS_OPT_NAME:
			conf.tls_name = safe_strdup(optarg);
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
					// No password specified should force it to default password
					// to trigger prompt.
					conf.tls.keyfile_pw = safe_strdup(DEFAULTPASSWORD);
				}
			}
			break;

		case TLS_OPT_CERT_FILE:
			conf.tls.certfile = safe_strdup(optarg);
			break;

		case 'a':
			if (!parse_date_time(optarg, &conf.mod_after)) {
				err("Invalid date and time string %s", optarg);
				goto cleanup1;
			}

			break;

		case 'b':
			if (!parse_date_time(optarg, &conf.mod_before)) {
				err("Invalid date and time string %s", optarg);
				goto cleanup1;
			}

			break;

		case COMMAND_OPT_NO_TTL_ONLY:
			conf.ttl_zero = true;
			break;

		case COMMAND_OPT_SOCKET_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp > UINT_MAX) {
				err("Invalid socket timeout value %s", optarg);
				goto cleanup1;
			}
			conf.socket_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_TOTAL_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp > UINT_MAX) {
				err("Invalid total timeout value %s", optarg);
				goto cleanup1;
			}
			conf.total_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_MAX_RETRIES:
			if (!better_atoi(optarg, &tmp) || tmp > UINT_MAX) {
				err("Invalid max retries value %s", optarg);
				goto cleanup1;
			}
			conf.max_retries = (uint32_t) tmp;
			break;

		case COMMAND_OPT_RETRY_DELAY:
			if (!better_atoi(optarg, &tmp) || tmp > UINT_MAX) {
				err("Invalid retry delay value %s", optarg);
				goto cleanup1;
			}
			conf.retry_delay = (uint32_t) tmp;
			break;

		case CONFIG_FILE_OPT_FILE:
		case CONFIG_FILE_OPT_INSTANCE:
		case CONFIG_FILE_OPT_NO_CONFIG_FILE:
		case CONFIG_FILE_OPT_ONLY_CONFIG_FILE:
			break;

		default:
			fprintf(stderr, "Run with --help for usage information and flag options\n");
			goto cleanup1;
		}
	}

	if (optind < argc) {
		err("Unexpected trailing argument %s", argv[optind]);
		goto cleanup1;
	}

	if (conf.port < 0) {
		conf.port = DEFAULT_PORT;
	}

	if (conf.host == NULL) {
		conf.host = DEFAULT_HOST;
	}

	if (conf.ns[0] == 0) {
		err("Please specify a namespace (-n option)");
		goto cleanup1;
	}

	if (conf.set_list.size > 1 && conf.filter_exp != NULL) {
		err("Multi-set backup and filter-exp are mutually exclusive");
		goto cleanup1;
	}

	if ((conf.pkey != NULL) ^ (conf.encrypt_mode != IO_PROXY_ENCRYPT_NONE)) {
		err("Must specify both encryption mode and a private key "
				"file/environment variable");
		goto cleanup1;
	}

	int32_t out_count = 0;
	out_count += conf.directory != NULL ? 1 : 0;
	out_count += conf.output_file != NULL ? 1 : 0;
	out_count += conf.estimate ? 1 : 0;

	if (out_count > 1) {
		err("Invalid options: --directory, --output-file, and --estimate are mutually exclusive.");
		goto cleanup1;
	}

	if (out_count == 0) {
		err("Please specify a directory (-d), an output file (-o), or make an estimate (-e).");
		goto cleanup1;
	}

	if (conf.estimate && conf.no_records) {
		err("Invalid options: -e and -R are mutually exclusive.");
		goto cleanup1;
	}

	if (conf.partition_list != NULL && conf.after_digest != NULL) {
		err("after-digest and partition-list arguments are mutually exclusive");
		goto cleanup1;
	}
	if (conf.node_list != NULL &&
			(conf.partition_list != NULL || conf.after_digest != NULL)) {
		err("node-list is mutually exclusive with after-digest and partition-list");
		goto cleanup1;
	}

	if (conf.state_file != NULL && conf.estimate) {
		err("--continue and --estimate arguments are mutually exclusive");
		goto cleanup1;
	}
	if (conf.state_file != NULL && conf.remove_files) {
		err("--continue and --remove-files arguments are mutually exclusive");
		goto cleanup1;
	}

	if (conf.estimate) {
		if (conf.filter_exp != NULL || conf.node_list != NULL ||
				conf.mod_after > 0 || conf.mod_before > 0 || conf.ttl_zero ||
				conf.after_digest != NULL || conf.partition_list != NULL) {
			inf("Warning: using estimate with any of the following will ignore their effects when calculating estimated time/storage: filter-exp, node-list, modified-after, modified-before, no-ttl-only, after-digest, partition-list");
		}
	}

	{
		const char *before;
		const char *after;
		const char *ttl_zero_msg;
		char before_buff[100];
		char after_buff[100];

		if (!format_date_time(conf.mod_before, before_buff, sizeof(before_buff))) {
			err("Error while formatting modified-since time");
			goto cleanup1;
		}
		if (!format_date_time(conf.mod_after, after_buff, sizeof(after_buff))) {
			err("Error while formatting modified-since time");
			goto cleanup1;
		}

		before = before_buff;
		after = after_buff;
		ttl_zero_msg = conf.ttl_zero ? "true" : "false";

		inf("Starting backup of %s (namespace: %s, set: [%s], bins: %s, "
				"after: %s, before: %s, no ttl only: %s, limit: %" PRId64
				") to %s",
				conf.host, conf.ns,
				conf.set_list.size == 0 ? "all" : str_vector_tostring(&conf.set_list),
				conf.bin_list == NULL ? "[all]" : conf.bin_list,
				after, before, ttl_zero_msg, conf.max_records,
				conf.output_file != NULL ?
				strcmp(conf.output_file, "-") == 0 ? "[stdout]" : conf.output_file :
				conf.directory != NULL ? conf.directory : "[none]");
	}

	backup_status_t status;
	if (!backup_status_init(&status, &conf)) {
		goto cleanup1;
	}

	FILE *mach_fd = NULL;

	if (conf.machine != NULL && (mach_fd = fopen(conf.machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf.machine);
		goto cleanup2;
	}

	// initialize the global lock + condition variable used for the stop condition
	if (pthread_mutex_init(&g_stop_lock, NULL) != 0) {
		err("Failed to initialize mutex");
		goto cleanup3;
	}
	if (pthread_cond_init(&g_stop_cond, NULL) != 0) {
		err("Failed to initialize condition variable");
		pthread_mutex_destroy(&g_stop_lock);
		goto cleanup3;
	}

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names;
	get_node_names(status.as->cluster, status.node_specs, status.n_node_specs,
			&node_names, &n_node_names);

	if (n_node_names < status.n_node_specs) {
		err("Invalid node list. Potentially duplicate nodes or nodes from different clusters.");
		goto cleanup5;
	}

	if (conf.node_list != NULL && conf.state_file == NULL) {
		// calculate partitions from these nodes, unless continuing a failed
		// backup, in which case we use the same partitions from the given nodes
		// that was calculated in the first run
		as_vector_init(&status.partition_filters, sizeof(as_partition_filter), 8);
		if (!calc_node_list_partitions(status.as->cluster, conf.ns, node_names,
					n_node_names, &status.partition_filters)) {
			goto cleanup5;
		}

		if (conf.parallel == 0) {
			conf.parallel = DEFAULT_NODE_BACKUP_PARALLEL;
		}
	}

	inf("Processing %u node(s)", n_node_names);

	if (!get_object_count(status.as, conf.ns, &conf.set_list, node_names,
				n_node_names, &status.rec_count_estimate)) {
		err("Error while counting cluster objects");
		goto cleanup5;
	}

	inf("Namespace contains %" PRIu64 " record(s)", status.rec_count_estimate);

	bool has_ldt;

	if (!check_for_ldt(status.as, conf.ns, node_names, n_node_names, &has_ldt)) {
		err("Error while checking for LDT");
		goto cleanup5;
	}

	if (has_ldt) {
		err("The cluster has LDT enabled for namespace %s; please use an older version of "
				"this tool to create a backup", conf.ns);
		goto cleanup5;
	}

	if (conf.estimate && status.rec_count_estimate > NUM_SAMPLES) {
		status.rec_count_estimate = NUM_SAMPLES;
	}
	if (conf.max_records > 0 && status.rec_count_estimate > conf.max_records) {
		status.rec_count_estimate = conf.max_records;
	}

	pthread_t backup_threads[MAX_PARALLEL];
	uint32_t n_threads = (uint32_t) (conf.parallel == 0 ? DEFAULT_PARALLEL : conf.parallel);
	static uint64_t samples[NUM_SAMPLES];
	static uint32_t n_samples = 0;
	backup_thread_args_t backup_args;
	backup_args.conf = &conf;
	backup_args.status = &status;
	backup_args.shared_fd = NULL;
	backup_args.samples = samples;
	backup_args.n_samples = &n_samples;

	cf_queue *job_queue = cf_queue_create(sizeof(backup_thread_args_t), true);
	cf_queue *complete_queue = cf_queue_create(sizeof(backup_thread_args_t), true);
	backup_args.complete_queue = complete_queue;

	backup_state_t* backup_state = NULL;

	if (job_queue == NULL || backup_args.complete_queue == NULL) {
		err_code("Error while allocating job queue");
		goto cleanup5;
	}

	if (status.partition_filters.size <= 1) {
		// since only one partition range is being backed up, evenly divide the range into 'n_threads' segments
		as_partition_filter range;

		if (status.partition_filters.size == 0) {
			as_partition_filter* range_ptr = (as_partition_filter*)
				as_vector_reserve(&status.partition_filters);
			as_partition_filter_set_range(range_ptr, 0, MAX_PARTITIONS);
		}

		range = *(as_partition_filter*) as_vector_get(&status.partition_filters, 0);

		if (n_threads > range.count) {
			inf("Warning: --parallel %u is higher than the number of partitions being "
					"backed up (%u), setting number of threads to %u.",
					n_threads, range.count, range.count);
			n_threads = range.count;
		}

		// don't divide up partition ranges if doing --after-digest of partition 4095
		if (n_threads > 1) {
			as_vector_clear(&status.partition_filters);

			for (uint32_t i = 0; i < n_threads; i++) {
				as_partition_filter* range_ptr = (as_partition_filter*)
					as_vector_reserve(&status.partition_filters);

				uint16_t begin = (uint16_t) ((uint32_t) range.begin +
						((uint32_t) range.count * i) / n_threads);
				uint16_t count = (uint16_t) ((uint32_t) range.begin +
						((uint32_t) range.count * (i + 1)) / n_threads) - begin;
				as_partition_filter_set_range(range_ptr, begin, count);
			}
		}
	}

	if (conf.state_file != NULL) {
		backup_state = load_backup_state(conf.state_file);

		if (backup_state == NULL) {
			goto cleanup6;
		}

		if (!narrow_partition_filters(backup_state, &status.partition_filters)) {
			goto cleanup6;
		}

		backup_state_load_global_status(backup_state, &status);

		// set the byte count limit "conf.bandwidth" bytes above the current
		// byte count so we don't have to wait for byte_count_limit to surpass
		// byte_count_total
		as_store_uint64(&status.byte_count_limit,
				status.byte_count_total + conf.bandwidth);

		if (conf.max_records > 0) {
			// If we are resuming with --max-records, subtract the number of
			// records that have already been backed up.
			if (conf.max_records < status.rec_count_total) {
				err("Continuing backup with %" PRIu64 " records already backed "
						"up, but --max-records set to %" PRIu64,
						status.rec_count_total, conf.max_records);
				goto cleanup6;
			}
			else {
				conf.max_records -= status.rec_count_total;
			}
		}
	}

	uint32_t n_filters = status.partition_filters.size;
	if (n_threads > n_filters) {
		inf("Warning: --parallel %u is higher than the number of partition "
				"filters given (%u), setting number of threads to %u.",
				n_threads, n_filters, n_filters);
		n_threads = n_filters;
	}

	// now that we've finalized the number of threads/tasks, let the backup
	// status struct know
	backup_status_set_n_threads(&status, &conf, n_filters, n_threads);

	// backing up to a single backup file: open the file now and store the file descriptor in
	// backup_args.shared_fd; it'll be shared by all backup threads
	if (conf.output_file != NULL) {
		if (conf.state_file != NULL) {
			// if the backup is being resumed, use the reopened io_proxy in the backup
			// state
			if (backup_state->files.size != 1) {
				err("Expected 1 backup file save state for resuming "
						"backup-to-file, but found %u in the backup state file",
						backup_state->files.size);
				goto cleanup6;
			}

			backup_state_file_t file =
				*(backup_state_file_t*) as_vector_get(&backup_state->files, 0);

			if (strcmp(file.file_name, conf.output_file) != 0) {
				err("Expected output file name of \"%s\", but found \"%s\" in "
						"the backup state file", conf.output_file, file.file_name);
				goto cleanup6;
			}

			backup_args.shared_fd = file.io_proxy;
			io_proxy_init_compression(backup_args.shared_fd, conf.compress_mode);
			io_proxy_init_encryption(backup_args.shared_fd, conf.pkey,
					conf.encrypt_mode);
			io_proxy_always_buffer(backup_args.shared_fd);

			if (io_proxy_initialize(backup_args.shared_fd) != 0) {
				goto cleanup6;
			}

			cf_free(file.file_name);
			as_vector_clear(&backup_state->files);
		}
		else {
			if (!prepare_output_file(conf.output_file, conf.remove_files)) {
				goto cleanup6;
			}

			backup_args.shared_fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
			if (!open_file(conf.output_file, conf.ns, 0, backup_args.shared_fd,
						conf.compress_mode, conf.encrypt_mode, conf.pkey)) {
				err("Error while opening shared backup file \"%s\"",
						conf.output_file);
				goto cleanup6;
			}
		}
	}
	else if (conf.estimate) {
		backup_args.shared_fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));

		if (!open_file(NULL, conf.ns, 0, backup_args.shared_fd,
					conf.compress_mode, conf.encrypt_mode, conf.pkey)) {
			goto cleanup6;
		}
	}
	else {
		backup_args.file_queue = cf_queue_create(sizeof(queued_backup_fd_t), true);

		if (backup_args.file_queue == NULL) {
			err("Failed to create cf_queue");
			goto cleanup6;
		}

		if (!prepare_directory(conf.directory)) {
			goto cleanup6;
		}

		if (!scan_directory(&conf, &status)) {
			goto cleanup6;
		}

		if (backup_state != NULL) {
			for (uint32_t i = 0; i < backup_state->files.size; i++) {
				backup_state_file_t file =
					*(backup_state_file_t*) as_vector_get(&backup_state->files, i);

				io_proxy_init_compression(file.io_proxy, conf.compress_mode);
				io_proxy_init_encryption(file.io_proxy, conf.pkey, conf.encrypt_mode);
				io_proxy_always_buffer(file.io_proxy);

				queued_backup_fd_t q = {
					.fd = file.io_proxy,
					.file_name = file.file_name,
					.rec_count_file = file.rec_count_file,
					.byte_count_file =
						(uint64_t) io_write_proxy_bytes_written(file.io_proxy)
				};

				if (cf_queue_push(backup_args.file_queue, &q) != CF_QUEUE_OK) {
					err_code("Failed to push reopened file %s to the queue", file.file_name);
					goto cleanup6;
				}
			}

			as_vector_clear(&backup_state->files);
		}
	}

	if (backup_state != NULL) {
		backup_state_free(backup_state);
		cf_free(backup_state);
		backup_state = NULL;
	}

	{
		char* state_file_loc = gen_backup_state_file_path(&conf);

		if (state_file_loc == NULL && !conf.estimate) {
			goto cleanup7;
		}

		cf_free(conf.state_file_dst);
		conf.state_file_dst = state_file_loc;
	}

	bool first;
	// only process indices/udfs if we are not resuming a failed/interrupted backup
	if (conf.state_file != NULL) {
		first = false;
		as_store_uint8((uint8_t*) &g_one_shot_done, 1);
	}
	else {
		first = true;
	}

	as_vector* partition_filters = &status.partition_filters;

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
			goto cleanup7;
		}
	}

	signal(SIGINT, sig_hand);
	signal(SIGTERM, sig_hand);

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = &conf;
	counter_args.status = &status;
	counter_args.mach_fd = mach_fd;

	if (verbose) {
		ver("Creating counter thread");
	}

	if (pthread_create(&counter_thread, NULL, counter_thread_func, &counter_args) != 0) {
		err_code("Error while creating counter thread");
		goto cleanup7;
	}

	uint32_t n_threads_ok = 0;

	if (verbose) {
		ver("Creating %u backup thread(s)", n_threads);
	}

	for (uint32_t i = 0; i < n_threads; ++i) {
		if (pthread_create(&backup_threads[i], NULL, backup_thread_func, job_queue) != 0) {
			err_code("Error while creating backup thread");
			goto cleanup8;
		}

		++n_threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup8:
	if (verbose) {
		ver("Waiting for %u backup thread(s)", n_threads_ok);
	}

	void *thread_res;

	for (uint32_t i = 0; i < n_threads_ok; i++) {
		if (safe_join(backup_threads[i], &thread_res) != 0) {
			err_code("Error while joining backup thread");
			stop();
			res = EXIT_FAILURE;
		}
		else if (thread_res != (void *)EXIT_SUCCESS) {
			if (verbose) {
#ifdef __APPLE__
				ver("Backup thread %p failed", backup_threads[i]);
#else
				ver("Backup thread %lu failed", backup_threads[i]);
#endif /* __APPLE__ */
			}

			res = EXIT_FAILURE;
		}
	}

	// Since we won't be acquiring any more locks from here on
	as_fence_memory();
	backup_state = as_load_ptr(&g_backup_state);
	do_backup_save_state = backup_state != NULL && backup_state != BACKUP_STATE_ABORTED;

	if (conf.estimate) {
		io_proxy_flush(backup_args.shared_fd);
		show_estimate(mach_fd, samples, n_samples, status.rec_count_estimate,
				backup_args.shared_fd);
	}
	else if (conf.output_file == NULL) {
		// backing up to a directory, clear out the file queue
		queued_backup_fd_t queued_fd;
		while (cf_queue_pop(backup_args.file_queue, &queued_fd, CF_QUEUE_NOWAIT) == CF_QUEUE_OK) {
			if (do_backup_save_state) {
				io_proxy_flush(queued_fd.fd);
				// Update the global byte count total after flushing the file.
				uint64_t tmp = 0;
				update_file_pos(queued_fd.fd, &queued_fd.byte_count_file, &tmp,
						&status.byte_count_total);

				backup_state_save_file(backup_state, queued_fd.file_name, queued_fd.fd,
						queued_fd.rec_count_file);
			}
			else {
				close_file(queued_fd.fd);
				cf_free(queued_fd.fd);
			}
			cf_free(queued_fd.file_name);
		}
	}
	else if (do_backup_save_state) {
		// backing up to a file, save the io proxy to the backup file if necessary
		io_proxy_flush(backup_args.shared_fd);
		update_shared_file_pos(backup_args.shared_fd, &status.byte_count_total);

		backup_state_save_file(backup_state, conf.output_file,
				backup_args.shared_fd, 0);
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

		backup_state_set_global_status(backup_state, &status);
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

	stop_counter();

	if (verbose) {
		ver("Waiting for counter thread");
	}

	if (safe_join(counter_thread, NULL) != 0) {
		err_code("Error while joining counter thread");
		res = EXIT_FAILURE;
	}

	if (do_backup_save_state) {
		inf("Backup was interrupted, to resume, run backup with `--continue %s` "
				"and all the same arguments (except --remove-files)",
				conf.state_file_dst);
	}

cleanup7:
	if (conf.output_file != NULL || conf.estimate) {
		// if we are saving the backup state, the shared fd has been passed to the
		// backup state struct, so we are no longer responsible for freeing it
		if (!do_backup_save_state) {
			if (!close_file(backup_args.shared_fd)) {
				err("Error while closing shared backup file \"%s\"", conf.output_file);
				res = EXIT_FAILURE;
			}
			cf_free(backup_args.shared_fd);
		}
	}
	else {
		cf_queue_destroy(backup_args.file_queue);
	}

cleanup6:
	cf_queue_destroy(job_queue);
	cf_queue_destroy(complete_queue);

	if (backup_state != NULL && backup_state != BACKUP_STATE_ABORTED) {
		if (one_shot_done() && !backup_state_complete(backup_state)) {
			// only save the backup state if the one shot work finished and at
			// least one partition isn't complete, since one shot work isn't
			// done in backup resumption and it's possible for the backup state
			// to have been created after all scans completed
			backup_state_save(backup_state);
		}
		backup_state_free(backup_state);
		cf_free(backup_state);
	}

cleanup5:
	if (node_names != NULL) {
		cf_free(node_names);
	}

	pthread_mutex_destroy(&g_stop_lock);
	pthread_cond_destroy(&g_stop_cond);

cleanup3:
	if (mach_fd != NULL) {
		fclose(mach_fd);
	}

cleanup2:
	backup_status_destroy(&status);

cleanup1:
	backup_config_destroy(&conf);

	if (verbose) {
		ver("Exiting with status code %d", res);
	}

	return res;
}

void
backup_config_default(backup_config_t *conf)
{
	conf->host = NULL;
	conf->port = -1;
	conf->use_services_alternate = false;
	conf->user = NULL;
	conf->password = DEFAULTPASSWORD;
	conf->auth_mode = NULL;

	memset(conf->ns, 0, sizeof(as_namespace));
	conf->no_bins = false;

	conf->state_file = NULL;
	conf->state_file_dst = NULL;

	as_vector_init(&conf->set_list, sizeof(as_set), 8);
	conf->bin_list = NULL;
	conf->node_list = NULL;
	conf->partition_list = NULL;
	conf->after_digest = NULL;
	conf->filter_exp = NULL;
	conf->mod_after = 0;
	conf->mod_before = 0;
	conf->ttl_zero = false;

	conf->remove_files = false;
	conf->directory = NULL;
	conf->output_file = NULL;
	conf->prefix = NULL;
	conf->compact = false;
	conf->parallel = 0;
	conf->compress_mode = IO_PROXY_COMPRESS_NONE;
	conf->encrypt_mode = IO_PROXY_ENCRYPT_NONE;
	conf->pkey = NULL;
	conf->machine = NULL;
	conf->estimate = false;
	conf->bandwidth = 0;
	conf->max_records = 0;
	conf->records_per_second = 0;
	conf->no_records = false;
	conf->no_indexes = false;
	conf->no_udfs = false;
	conf->file_limit = DEFAULT_FILE_LIMIT * 1024 * 1024;

	memset(&conf->tls, 0, sizeof(as_config_tls));
	conf->tls_name = NULL;

	conf->socket_timeout = 10 * 1000;
	conf->total_timeout = 0;
	conf->max_retries = 5;
	conf->retry_delay = 0;
}

void
backup_config_destroy(backup_config_t *conf)
{
	if (conf->pkey != NULL) {
		encryption_key_free(conf->pkey);
		cf_free(conf->pkey);
	}

	if (conf->partition_list != NULL) {
		cf_free(conf->partition_list);
	}

	if (conf->after_digest != NULL) {
		cf_free(conf->after_digest);
	}

	if (conf->filter_exp != NULL) {
		cf_free(conf->filter_exp);
	}

	if (conf->state_file != NULL) {
		cf_free(conf->state_file);
	}

	if (conf->state_file_dst != NULL) {
		cf_free(conf->state_file_dst);
	}

	as_vector_destroy(&conf->set_list);

	if (conf->bin_list != NULL) {
		cf_free(conf->bin_list);
	}

	if (conf->tls_name != NULL) {
		cf_free(conf->tls_name);
	}

	if (conf->tls.cafile != NULL) {
		cf_free(conf->tls.cafile);
	}

	if (conf->tls.capath != NULL) {
		cf_free(conf->tls.capath);
	}

	if (conf->tls.protocols != NULL) {
		cf_free(conf->tls.protocols);
	}

	if (conf->tls.cipher_suite != NULL) {
		cf_free(conf->tls.cipher_suite);
	}

	if (conf->tls.cert_blacklist != NULL) {
		cf_free(conf->tls.cert_blacklist);
	}

	if (conf->tls.keyfile != NULL) {
		cf_free(conf->tls.keyfile);
	}

	if (conf->tls.keyfile_pw != NULL) {
		cf_free(conf->tls.keyfile_pw);
	}

	if (conf->tls.certfile != NULL) {
		cf_free(conf->tls.certfile);
	}
}

bool
backup_status_init(backup_status_t* status, const backup_config_t* conf)
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

	char* host = conf->host;
	uint32_t port = (uint32_t) conf->port;

	char* tls_name = conf->tls_name;

	if (conf->partition_list != NULL) {
		if (verbose) {
			ver("Parsing partition-list '%s'", conf->partition_list);
		}

		if (!parse_partition_list(conf->partition_list, &status->partition_filters)) {
			err("Error while parsing partition-list '%s'", conf->partition_list);
			goto cleanup1;
		}
	}
	else if (conf->after_digest != NULL) {
		if (verbose) {
			ver("Parsing after-digest '%s'", conf->after_digest);
		}

		if (!parse_after_digest(conf->after_digest, &status->partition_filters)) {
			err("Error while parsing after-digest '%s'", conf->after_digest);
			goto cleanup1;
		}
	}
	else if (conf->node_list != NULL) {
		if (verbose) {
			ver("Parsing node list %s", conf->node_list);
		}

		if (!parse_node_list(conf->node_list, &status->node_specs,
					&status->n_node_specs)) {
			err("Error while parsing node list");
			goto cleanup1;
		}

		host = status->node_specs[0].addr_string;
		port = ntohs(status->node_specs[0].port);

		if (status->node_specs[0].family == AF_INET6) {
			if (strnlen(host, IP_ADDR_SIZE) > IP_ADDR_SIZE - 3) {
				err("Hostname \"%.*s\" too long (max is %d characters)",
						IP_ADDR_SIZE, host, IP_ADDR_SIZE - 3);
				goto cleanup1;
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
			goto cleanup1;
		}

		status->policy->base.filter_exp = expr;

		// Still need to parse the set name. We can safely pass NULL as the
		// set_list_expr, since multiset backup is mutually exclusive with
		// filter-exp.
		if (!parse_sets(&conf->set_list, status->set, NULL)) {
			goto cleanup1;
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
			goto cleanup1;
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
			goto cleanup1;
		}
		else if (combined_expr != NULL) {
			status->policy->base.filter_exp = combined_expr;
		}
	}

	as_config as_conf;
	as_config_init(&as_conf);
	as_conf.conn_timeout_ms = TIMEOUT;
	as_conf.use_services_alternate = conf->use_services_alternate;
	memcpy(&as_conf.tls, &conf->tls, sizeof(as_config_tls));

	if (!as_config_add_hosts(&as_conf, host, (uint16_t) port)) {
		err("Invalid conf.host(s) string %s", host);
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

		if (!tls_read_password(tls_keyfile_pw, &as_conf.tls.keyfile_pw)) {
			goto cleanup2;
		}
	}

	memset(&((backup_config_t*) conf)->tls, 0, sizeof(conf->tls));

	status->as = cf_malloc(sizeof(aerospike));
	if (status->as == NULL) {
		err("Failed to malloc aerospike struct");
		goto cleanup2;
	}

	aerospike_init(status->as, &as_conf);
	as_error ae;

	if (verbose) {
		ver("Connecting to cluster");
	}

	if (aerospike_connect(status->as, &ae) != AEROSPIKE_OK) {
		err("Error while connecting to %s:%d - code %d: %s at %s:%d", host, port,
				ae.code, ae.message, ae.file, ae.line);
		goto cleanup2;
	}

	if (!check_server_version(status, conf)) {
		goto cleanup3;
	}

	return true;

cleanup3:
	aerospike_close(status->as, &ae);

cleanup2:
	if (status->as != NULL) {
		aerospike_destroy(status->as);
	}

cleanup1:
	as_exp_destroy(status->policy->base.filter_exp);
	cf_free(status->node_specs);

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


//==========================================================
// Local helpers.
//

static bool
one_shot_done(void)
{
	return as_load_uint8((uint8_t*) &g_one_shot_done);
}

/*
 * Waits until the one-time work (secondary indexes and UDF files) is complete.
 */
static void
wait_one_shot(void)
{
	if (!one_shot_done()) {
		safe_lock(&g_stop_lock);

		while (!one_shot_done() && !has_stopped()) {
			safe_wait(&g_stop_cond, &g_stop_lock);
		}

		safe_unlock(&g_stop_lock);
	}
}

/*
 * Signals that the one-time work (secondary indexes and UDF files) is complete.
 */
static void
signal_one_shot(void)
{
	safe_lock(&g_stop_lock);
	as_store_uint8((uint8_t*) &g_one_shot_done, 1);
	safe_signal(&g_stop_cond);
	safe_unlock(&g_stop_lock);
}

/*
 * Returns true if the program has stoppped
 */
static bool
has_stopped(void)
{
	return as_load_uint8((uint8_t*) &g_stop);
}

/*
 * Stops the program
 */
static void
stop(void)
{
	pthread_mutex_lock(&g_stop_lock);

	// try initializing the backup file, which may have already been done
	init_backup_state_file();

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&g_stop_cond);

	pthread_mutex_unlock(&g_stop_lock);
}

/*
 * Stops the program, which is safe in interrupt contexts
 */
static void
stop_nolock(void)
{
	bool was_locked = (pthread_mutex_trylock(&g_stop_lock) == 0);

	// this may induce a race condition on initializing the backup file if
	// the stop lock mutex is not acquired (which we can't safely wait on in
	// an interrupt context without risk of deadlock), though the worst that
	// can happen is merely a memory leak of one of the backup state file
	// objects
	init_backup_state_file();

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	// wakes all threads waiting on the stop condition
	// this can potentially miss some threads waiting on a condition variable if
	// trylock failed, but they will eventually time out
	pthread_cond_broadcast(&g_stop_cond);

	if (was_locked) {
		pthread_mutex_unlock(&g_stop_lock);
	}
}

/*
 * Stops the program, but should only be called after all backup job threads
 * have been joined
 */
static void
stop_counter(void)
{
	pthread_mutex_lock(&g_stop_lock);

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&g_stop_cond);

	pthread_mutex_unlock(&g_stop_lock);
}

/*
 * Aborts the backup without saving the backup state to a file. This should only
 * be called if the backup state file would have been corrupted/an error
 * occurred that caused the backup state to be unrecoverable.
 */
static void
abort_backup(void)
{
	pthread_mutex_lock(&g_stop_lock);

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	backup_state_t* prev_state =
		(backup_state_t*) as_fas_uint64((uint64_t*) &g_backup_state,
				(uint64_t) BACKUP_STATE_ABORTED);

	if (prev_state != NULL && prev_state != BACKUP_STATE_ABORTED) {
		backup_state_free(prev_state);
		cf_free(prev_state);
	}

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&g_stop_cond);

	pthread_mutex_unlock(&g_stop_lock);
}

/*
 * Sleep on the stop condition, exiting from the sleep early if the program is
 * stopped
 */
static void
sleep_for(uint64_t n_secs)
{
#ifdef __APPLE__
	// MacOS uses gettimeofday instead of the monotonic clock for timed waits on
	// mutexes
	struct timespec t;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	TIMEVAL_TO_TIMESPEC(&tv, &t);
#else
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
#endif /* __APPLE__ */

	t.tv_sec += (int64_t) n_secs;

	pthread_mutex_lock(&g_stop_lock);
	while (!as_load_uint8((uint8_t*) &g_stop) && timespec_has_not_happened(&t)) {
		pthread_cond_timedwait(&g_stop_cond, &g_stop_lock, &t);
	}
	pthread_mutex_unlock(&g_stop_lock);
}

/*
 * Ensures that there is enough disk space available. Outputs a warning, if there isn't.
 *
 * @param dir         A file or directory path on the disk to be checked.
 * @param disk_space  The number of bytes required on the disk.
 */
static void
disk_space_check(const char *dir, uint64_t disk_space)
{
	struct statvfs buf;

	if (verbose) {
		ver("Checking disk space on %s for %" PRIu64 " byte(s)", dir, disk_space);
	}

	if (statvfs(dir, &buf) < 0) {
		err_code("Error while getting file system info for %s", dir);
		return;
	}

	size_t available = buf.f_bavail * buf.f_bsize;

	if (available < disk_space) {
		err("Running out of disk space, less than %" PRIu64 " bytes available (%zu)", disk_space,
				available);
	}
}

/*
 * To be called after data has been written to the io_proxy. Checks if any data
 * was written to the file, and if so, updates the global byte counts.
 *
 * This method should only be called in directory mode.
 */
static int
update_file_pos(io_write_proxy_t* fd, uint64_t* byte_count_file,
		uint64_t* byte_count_job, uint64_t* byte_count_total)
{
	int64_t pos = io_write_proxy_bytes_written(fd);
	if (pos < 0) {
		err("Failed to get the file position");
		return -1;
	}
	uint64_t diff = (uint64_t) pos - *byte_count_file;

	*byte_count_file = (uint64_t) pos;
	*byte_count_job += diff;
	as_add_uint64(byte_count_total, diff);

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
update_shared_file_pos(io_write_proxy_t* fd, uint64_t* byte_count_total)
{
	int64_t pos = io_write_proxy_bytes_written(fd);
	if (pos < 0) {
		err("Failed to get the file position");
		return -1;
	}

	as_store_uint64(byte_count_total, (uint64_t) pos);

	return 0;
}

/*
 * Closes a backup file and frees the associated I/O buffer.
 *
 * @param fd      The file descriptor of the backup file to be closed.
 */
static bool
close_file(io_write_proxy_t *fd)
{
	if (fd->fd == NULL) {
		return true;
	}

	if (verbose) {
		ver("Closing backup file");
	}

	if (io_proxy_flush(fd) == EOF) {
		err_code("Error while flushing backup file");
		return false;
	}

	if (fd->fd == stdout) {
		if (verbose) {
			ver("Not closing stdout");
		}

		// not closing, but we still have to detach our I/O buffer, as we're going to free it
		setlinebuf(stdout);
	} else {
		if (verbose) {
			ver("Closing file descriptor");
		}

		FILE* _f = fd->fd;
		io_proxy_free(fd);

		if (fclose(_f) == EOF) {
			err_code("Error while closing backup file");
			return false;
		}
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
		io_write_proxy_t *fd, compression_opt c_opt,
		encryption_opt e_opt, encryption_key_t* pkey)
{
	FILE* _f;

	if (verbose) {
		ver("Opening backup file %s", file_path);
	}

	if (file_path == NULL) {
		if (verbose) {
			ver("Backup up to \"/dev/null\" for estimate");
		}

		if ((_f = fopen("/dev/null", "w")) == NULL) {
			err_code("Unable to open \"/dev/null\"");
			return false;
		}
	}
	else if (strcmp(file_path, "-") == 0) {
		if (verbose) {
			ver("Backup file is stdout");
		}

		_f = stdout;
	}
	else {
		if (verbose) {
			ver("Creating backup file at %s", file_path);
		}

		if ((_f = fopen(file_path, "r")) != NULL) {
			fclose(_f);
			if (verbose) {
				ver("Backup file %s already exists", file_path);
				return false;
			}
		}

		char *tmp_path = safe_strdup(file_path);
		char *dir_path = dirname(tmp_path);
		disk_space_check(dir_path, disk_space);
		cf_free(tmp_path);

		if ((_f = fopen(file_path, "w")) == NULL) {
			err_code("Error while creating backup file %s", file_path);
			return false;
		}

		inf("Created new backup file %s", file_path);
	}

	if (verbose) {
		ver("Initializing backup file %s", file_path);
	}

	io_write_proxy_init(fd, _f);
	io_proxy_init_compression(fd, c_opt);
	io_proxy_init_encryption(fd, pkey, e_opt);

	// always buffer since we need the file pos when reopening a saved backup
	// file in backup resumption
	io_proxy_always_buffer(fd);

	if (io_proxy_printf(fd, "Version " VERSION_3_1 "\n") < 0) {
		err_code("Error while writing header to backup file %s", file_path);
		close_file(fd);
		return false;
	}

	if (io_proxy_printf(fd, META_PREFIX META_NAMESPACE " %s\n", escape(ns)) < 0) {
		err_code("Error while writing meta data to backup file %s", file_path);
		close_file(fd);
		return false;
	}

	return true;
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
	// flush the file before calculating the size
	if (io_proxy_flush(bjc->fd) == EOF) {
		err_code("Error while flushing backup file %s", bjc->file_name);
		return false;
	}
	int64_t file_size = io_write_proxy_bytes_written(bjc->fd);

	if ((uint64_t) file_size < bjc->conf->file_limit) {
		// add the fd to the queue
		queued_backup_fd_t q = {
			.fd = bjc->fd,
			.file_name = bjc->file_name,
			.rec_count_file = bjc->rec_count_file,
			.byte_count_file = bjc->byte_count_file
		};
		if (cf_queue_push(bjc->file_queue, &q) == CF_QUEUE_OK) {
			if (verbose) {
				ver("File %s size is %" PRId64 ", pushing to the queue",
						bjc->file_name, file_size);
			}
			return true;
		}

		// if pushing to the queue failed, fall through to commit the file
		if (verbose) {
			ver("Could not commit file %s to queue, closing instead",
					bjc->file_name);
		}
	}

	cf_free(bjc->file_name);
	pthread_mutex_lock(&committed_count_mutex);
	as_add_uint64(&bjc->status->rec_count_total_committed, (int64_t) bjc->rec_count_file);
	as_add_uint64(&bjc->status->byte_count_total_committed, file_size);
	pthread_mutex_unlock(&committed_count_mutex);

	if (!close_file(bjc->fd)) {
		return false;
	}

	if (verbose) {
		ver("File size is %" PRId64 " for %s", file_size, bjc->file_name);
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

		if (verbose) {
			ver("Found %s in queue", queued_fd.file_name);
		}

		bjc->fd = queued_fd.fd;
		bjc->file_name = queued_fd.file_name;
		bjc->rec_count_file = queued_fd.rec_count_file;
		bjc->byte_count_file = queued_fd.byte_count_file;
	}
	else {
		int64_t file_count = (int64_t) as_faa_uint64(&bjc->status->file_count, 1);

		uint64_t file_path_size = (size_t) snprintf(NULL, 0, "%s/%s_%05" PRId64 ".asb",
				bjc->conf->directory,
				bjc->conf->prefix == NULL ? bjc->conf->ns : bjc->conf->prefix,
				file_count);

		char* file_path = (char*) cf_malloc((file_path_size + 1) * sizeof(char));
		if (file_path == NULL) {
			err("Unable to malloc file path name of length %" PRIu64, file_path_size);
			return false;
		}

		snprintf(file_path, file_path_size + 1, "%s/%s_%05" PRId64 ".asb",
				bjc->conf->directory,
				bjc->conf->prefix == NULL ? bjc->conf->ns : bjc->conf->prefix,
				file_count);

		uint64_t rec_count_estimate = bjc->status->rec_count_estimate;
		uint64_t rec_count_total = as_load_uint64(&bjc->status->rec_count_total);

		pthread_mutex_lock(&committed_count_mutex);
		uint64_t rec_count_total_committed =
			as_load_uint64(&bjc->status->rec_count_total_committed);
		uint64_t byte_count_total_committed =
			as_load_uint64(&bjc->status->byte_count_total_committed);
		pthread_mutex_unlock(&committed_count_mutex);

		uint64_t rec_remain = rec_count_total > rec_count_estimate ? 0 :
			rec_count_estimate - rec_count_total;
		uint64_t rec_size = rec_count_total_committed == 0 ? 0 :
			byte_count_total_committed / rec_count_total_committed;

		if (verbose) {
			ver("%" PRIu64 " remaining record(s), %" PRIu64 " B/rec average size", rec_remain,
					rec_size);
		}

		bjc->fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));

		if (!open_file(file_path, bjc->conf->ns, rec_remain * rec_size,
					bjc->fd, bjc->conf->compress_mode, bjc->conf->encrypt_mode,
					bjc->conf->pkey)) {
			cf_free(file_path);
			return false;
		}

		bjc->file_name = file_path;
		bjc->rec_count_file = 0;
		bjc->byte_count_file = 0;
		if (update_file_pos(bjc->fd, &bjc->byte_count_file, &bjc->byte_count_job,
					&bjc->status->byte_count_total) < 0) {
			return false;
		}
	}

	return true;
}

/*
 * Generates the path to the backup state file and verifies that the path is
 * valid (i.e. will be able to be opened if the backup fails and the state of
 * the file system does not change).
 *
 * Returns NULL on error (or if in estimate mode), otherwise a pointer to a
 * malloc-ed string of the generated file path.
 */
static char*
gen_backup_state_file_path(const backup_config_t* conf)
{
	char* backup_state_file;

	if (conf->state_file_dst != NULL) {
		DIR *dir = opendir(conf->state_file_dst);

		if (dir == NULL) {
			// this is not a path to an existing directory, assume it is a path
			// to a new file and verify that it can be created or already exists
			int fd = open(conf->state_file_dst, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);

			if (fd == -1) {
				// if the file already exists, this is no problem, we will just
				// overwrite it. Check for any other kind of error
				if (errno != EEXIST) {
					err("Failed to open state file \"%s\", reason: %s",
							conf->state_file_dst, strerror(errno));
					return NULL;
				}

				// we still need to try opening the file to see if we have
				// permission to overwrite it
				fd = open(conf->state_file_dst, O_RDWR);

				if (fd == -1) {
					err("Failed to open state file \"%s\", reason: %s",
							conf->state_file_dst, strerror(errno));
					return NULL;
				}

				close(fd);
			}
			else {
				close(fd);
				unlink(conf->state_file_dst);
			}

			backup_state_file = safe_strdup(conf->state_file_dst);
		}
		else {
			// state_file_dst points to a directory, so generate a path to a
			// file in this directory that we will write the backup state to
			closedir(dir);

			uint64_t len = (uint64_t) snprintf(NULL, 0, "%s/%s.asb.state",
					conf->state_file_dst,
					conf->prefix == NULL ? conf->ns : conf->prefix);

			backup_state_file = cf_malloc((len + 1) * sizeof(char));
			if (backup_state_file == NULL) {
				err("Unable to allocate %" PRId64 " bytes for backup state file name",
						len + 1);
				return NULL;
			}

			snprintf(backup_state_file, len + 1, "%s/%s.asb.state",
					conf->state_file_dst,
					conf->prefix == NULL ? conf->ns : conf->prefix);
		}
	}
	else {
		if (conf->directory != NULL) {
			uint64_t len = (uint64_t) snprintf(NULL, 0, "%s/%s.asb.state",
					conf->directory,
					conf->prefix == NULL ? conf->ns : conf->prefix);

			backup_state_file = cf_malloc((len + 1) * sizeof(char));
			if (backup_state_file == NULL) {
				err("Unable to allocate %" PRId64 " bytes for backup state file name",
						len + 1);
				return NULL;
			}

			snprintf(backup_state_file, len + 1, "%s/%s.asb.state",
					conf->directory,
					conf->prefix == NULL ? conf->ns : conf->prefix);
		}
		else if (conf->output_file != NULL) {
			const char* prefix;
			if (conf->output_file[0] == '-') {
				prefix = conf->ns;
			}
			else {
				prefix = conf->output_file;
			}

			uint64_t len = (uint64_t) snprintf(NULL, 0, "%s.state", prefix);

			backup_state_file = cf_malloc((len + 1) * sizeof(char));
			if (backup_state_file == NULL) {
				err("Unable to allocate %" PRId64 " bytes for backup state file name",
						len + 1);
				return NULL;
			}

			snprintf(backup_state_file, len + 1, "%s.state", prefix);
		}
		else {
			// running in estimate mode, no need to save the backup state
			return NULL;
		}
	}

	return backup_state_file;
}

/*
 * Initializes the backup state file to save the current scan status of all
 * running backup jobs to be continued in another run.
 *
 * This method must be called while holding the g_stop_lock.
 */
static bool
init_backup_state_file(void)
{
	const char* backup_state_file = g_conf->state_file_dst;

	if (backup_state_file == NULL) {
		// Only will happen in --estimate mode, no need to make a backup state.
		return false;
	}

	backup_state_t* cur_backup_state = as_load_ptr(&g_backup_state);
	if (cur_backup_state != NULL) {
		// a backup state alrady exists, or we've aborted the backup, do nothing
		return false;
	}

	backup_state_t* state = (backup_state_t*) cf_malloc(sizeof(backup_state_t));
	if (state == NULL) {
		err("Unable to allocate %zu bytes for backup state struct",
				sizeof(backup_state_t));
		return false;
	}

	if (backup_state_init(state, backup_state_file) != 0) {
		cf_free(state);
		return false;
	}

	// compare and swap g_backup_state from NULL to state, so if g_backup_state
	// was anything but NULL before, it won't be overwritten
	if (!as_cas_uint64((uint64_t*) &g_backup_state, (uint64_t) NULL, (uint64_t) state)) {
		backup_state_free(state);
		cf_free(state);
		return false;
	}

	inf("Created backup state file %s", backup_state_file);

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

/*
 * Saves the scan state of the given scan object to the backup state file.
 */
static void
save_scan_state(const as_partitions_status* parts)
{
	pthread_mutex_lock(&g_stop_lock);

	backup_state_t* state = as_load_ptr(&g_backup_state);

	if (state == BACKUP_STATE_ABORTED) {
		pthread_mutex_unlock(&g_stop_lock);
		return;
	}

	for (uint32_t i = 0; i < parts->part_count; i++) {
		const as_partition_status* status = &parts->parts[i];
		uint16_t part_id = status->part_id;

		if (!parts->parts[i].done) {

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
				backup_state_mark_not_started(state, part_id);
			}
		}
	}
	pthread_mutex_unlock(&g_stop_lock);
}

static void
save_job_state(const backup_thread_args_t* args)
{
	const as_partition_filter* filter = &args->filter;

	if (filter->parts_all == NULL) {
		pthread_mutex_lock(&g_stop_lock);
		backup_state_t* state = (backup_state_t*) as_load_ptr(&g_backup_state);

		if (state == BACKUP_STATE_ABORTED) {
			pthread_mutex_unlock(&g_stop_lock);
			return;
		}

		for (uint32_t part_id = filter->begin; part_id < filter->begin + filter->count;
				part_id++) {
			backup_state_mark_not_started(state, (uint16_t) part_id);
		}

		pthread_mutex_unlock(&g_stop_lock);
	}
	else {
		// if we are saving a resumed backup job, parts_all will have been
		// initialized even for the backup jobs still on the queue, and we want
		// to preserve the status of those states
		save_scan_state(filter->parts_all);
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
		if (verbose) {
			ver("Received scan end marker");
		}

		return true;
	}

	if (has_stopped()) {
		if (verbose) {
			ver("Callback detected failure");
		}

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
		if (verbose) {
			ver("Crossed %" PRIu64 " bytes, switching backup file", bjc->conf->file_limit);
		}

		if (!close_dir_file(bjc)) {
			err("Error while closing old backup file");
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
		safe_lock(&file_write_mutex);
	}

	bool ok;
	if (bjc->conf->estimate) {
		if (*bjc->n_samples >= NUM_SAMPLES) {
			inf("Backed up enough samples for estimate");
			safe_unlock(&file_write_mutex);
			bjc->interrupted = true;
			return false;
		}

		int64_t prev_pos = io_write_proxy_absolute_pos(bjc->fd);
		ok = bjc->status->encoder.put_record(bjc->fd, bjc->conf->compact, rec);
		int64_t post_pos = io_write_proxy_absolute_pos(bjc->fd);

		if (prev_pos < 0 || post_pos < 0) {
			err("Error reading the file position from the io_proxy while running estimate");
			ok = false;
		}

		bjc->samples[*bjc->n_samples] = (uint64_t) (post_pos - prev_pos);
		++(*bjc->n_samples);
	}
	else {
		ok = bjc->status->encoder.put_record(bjc->fd, bjc->conf->compact, rec);
	}

	++bjc->rec_count_file;
	++bjc->rec_count_job;
	as_incr_uint64(&bjc->status->rec_count_total);

	if (bjc->conf->output_file != NULL) {
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
		safe_unlock(&file_write_mutex);
	}

	if (!ok) {
		err("Error while storing record in backup file, aborting scan. The "
				"backup state is currently unrecoverable in this state, so "
				"backup resumption is not possible.");
		abort_backup();
		bjc->interrupted = true;
		return false;
	}

	if (bjc->conf->bandwidth > 0) {
		safe_lock(&bandwidth_mutex);

		while (as_load_uint64(&bjc->status->byte_count_total) >=
				as_load_uint64(&bjc->status->byte_count_limit) &&
				!has_stopped()) {
			safe_wait(&bandwidth_cond, &bandwidth_mutex);
		}

		safe_unlock(&bandwidth_mutex);
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
	if (verbose) {
		ver("Processing secondary indexes");
	}

	bool res = false;

	size_t value_size = sizeof "sindex-list:ns=" - 1 + strlen(bjc->conf->ns) + 1;
	char value[value_size];
	snprintf(value, value_size, "sindex-list:ns=%s", bjc->conf->ns);

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

		if (verbose) {
			ver("Storing index %s", index.name);
		}

		uint32_t n_sets = bjc->conf->set_list.size;
		if (n_sets == 0 || (index.set != NULL &&
					str_vector_contains(&bjc->conf->set_list, index.set))) {

			// backing up to a single backup file: allow one thread at a time to write
			if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
				safe_lock(&file_write_mutex);
			}

			bool ok = bjc->status->encoder.put_secondary_index(bjc->fd, &index);

			if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
				safe_unlock(&file_write_mutex);
			}

			if (!ok) {
				err("Error while storing secondary index in backup file");
				goto cleanup3;
			}

			if (bjc->conf->output_file != NULL) {
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
	if (verbose) {
		ver("Processing UDFs");
	}

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
		if (verbose) {
			ver("Fetching UDF file %u: %s", i + 1, files.entries[i].name);
		}

		if (aerospike_udf_get(bjc->status->as, &ae, &policy, files.entries[i].name,
				files.entries[i].type, &file) != AEROSPIKE_OK) {
			err("Error while fetching UDF file %s - code %d: %s at %s:%d", files.entries[i].name,
					ae.code, ae.message, ae.file, ae.line);
			goto cleanup2;
		}

		// backing up to a single backup file: allow one thread at a time to write
		if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
			safe_lock(&file_write_mutex);
		}

		bool ok = bjc->status->encoder.put_udf_file(bjc->fd, &file);

		if (bjc->conf->output_file != NULL || bjc->conf->estimate) {
			safe_unlock(&file_write_mutex);
		}

		if (!ok) {
			err("Error while storing UDF file in backup file");
			goto cleanup2;
		}

		if (bjc->conf->output_file != NULL) {
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
	if (verbose) {
		ver("Entering backup thread 0x%" PRIx64, (uint64_t)pthread_self());
	}

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;

	while (true) {
		if (has_stopped()) {
			if (verbose) {
				ver("Backup thread detected failure");
			}

			break;
		}

		backup_thread_args_t args;
		int32_t q_res = cf_queue_pop(job_queue, &args, CF_QUEUE_NOWAIT);

		if (q_res == CF_QUEUE_EMPTY) {
			if (verbose) {
				ver("Job queue is empty");
			}

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
			if (verbose) {
				ver("Using shared file descriptor");
			}

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
			if (verbose) {
				ver("Picked up first job, doing one shot work");
			}

			if (io_proxy_printf(bjc.fd, META_PREFIX META_FIRST_FILE "\n") < 0) {
				err_code("Error while writing meta data to backup file");
				stop();
				goto close_file;
			}

			if (bjc.conf->output_file != NULL) {
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
				if (verbose) {
					ver("Skipping index backup");
				}
			} else if (!process_secondary_indexes(&bjc)) {
				err("Error while processing secondary indexes");
				stop();
				goto close_file;
			}

			if (bjc.conf->no_udfs) {
				if (verbose) {
					ver("Skipping UDF backup");
				}
			} else if (!process_udfs(&bjc)) {
				err("Error while processing UDFs");
				stop();
				goto close_file;
			}

			if (verbose) {
				ver("Signaling one shot work completion");
			}

			// all other jobs wait until the first job is done with the secondary indexes and UDF files
			signal_one_shot();
		} else {
			if (verbose) {
				ver("Ensuring one shot work completion");
			}

			wait_one_shot();

			if (has_stopped()) {
				goto close_file;
			}
		}

		inf("Starting backup for %s", bjc.desc);

		as_error ae;
		as_status status;

		if (bjc.conf->no_records) {
			if (verbose) {
				ver("Skipping record backup");
			}
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
		}

		if (status != AEROSPIKE_OK) {
			if (ae.code == AEROSPIKE_OK) {
				inf("Abort scan for %s", bjc.desc);
			} else {
				err("Error while running scan for %s - code %d: %s at %s:%d", bjc.desc,
						ae.code, ae.message, ae.file, ae.line);
			}

			stop();
			goto close_file;
		}

		if (!bjc.interrupted) {
			inf("Completed backup for %s, records: %" PRIu64 ", size: %" PRIu64 " "
					"(~%" PRIu64 " B/rec)", bjc.desc, bjc.rec_count_job,
					bjc.byte_count_job,
					bjc.rec_count_job == 0 ? 0 : bjc.byte_count_job / bjc.rec_count_job);
		}
		else {
			inf("Backup of %s interrupted, records: %" PRIu64 ", size: %" PRIu64 " "
					"(~%" PRIu64 " B/rec)", bjc.desc, bjc.rec_count_job,
					bjc.byte_count_job,
					bjc.rec_count_job == 0 ? 0 : bjc.byte_count_job / bjc.rec_count_job);

			stop();
		}

close_file:
		// backing up to a single backup file: do nothing
		if (bjc.conf->output_file != NULL) {
			if (verbose) {
				ver("Not closing shared file descriptor");
			}

			bjc.fd = NULL;
		}
		// backing up to a directory: close the last backup file for the current job
		else if (bjc.conf->directory != NULL) {
			if (!close_dir_file(&bjc)) {
				err("Error while closing backup file");
				cf_free(bjc.fd);
				bjc.fd = NULL;
				stop();
			}
		}

		if (scan_ptr == NULL || scan_ptr->parts_all == NULL) {
			// it's possible scan_ptr->parts_all == NULL and we haven't failed
			// if no_records is set
			if (has_stopped()) {
				save_job_state(&args);
			}
		}
		else if (has_stopped()) {
			save_scan_state(scan_ptr->parts_all);
		}
		else if (!complete_job(args.complete_queue, &args)) {
			stop();
			save_scan_state(scan_ptr->parts_all);
		}

		if (args.filter.parts_all != NULL) {
			as_partitions_status_release(args.filter.parts_all);
		}

		as_scan_destroy(scan_ptr);
	}

	if (res != (void *)EXIT_SUCCESS) {
		if (verbose) {
			ver("Indicating failure to other threads");
		}

		stop();
	}

	if (verbose) {
		ver("Leaving backup thread");
	}

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
	if (verbose) {
		ver("Entering counter thread 0x%" PRIx64, (uint64_t)pthread_self());
	}

	counter_thread_args *args = (counter_thread_args *)cont;
	const backup_config_t *conf = args->conf;
	backup_status_t *status = args->status;

	cf_clock prev_ms = cf_getms();

	uint32_t iter = 0;
	cf_clock print_prev_ms = prev_ms;
	uint64_t print_prev_bytes = as_load_uint64(&status->byte_count_total);
	uint64_t print_prev_recs = as_load_uint64(&status->rec_count_total);

	uint64_t mach_prev_recs = print_prev_recs;

	while (true) {
		sleep_for(1);

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		prev_ms = now_ms;

		if (status->rec_count_estimate > 0) {
			uint64_t now_bytes = as_load_uint64(&status->byte_count_total);
			uint64_t now_recs = as_load_uint64(&status->rec_count_total);

			int32_t percent = (int32_t)(now_recs * 100 / status->rec_count_estimate);

			// rec_count_estimate may be a little off, make sure that we only print up to 99%
			if (percent < 100) {
				if (iter++ % 10 == 0) {
					uint32_t ms = (uint32_t)(now_ms - print_prev_ms);
					print_prev_ms = now_ms;

					uint64_t bytes = now_bytes - print_prev_bytes;
					uint64_t recs = now_recs - print_prev_recs;

					int32_t eta = recs == 0 ? -1 :
						(int32_t)(((uint64_t) status->rec_count_estimate - now_recs) *
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
						(int32_t)(((uint64_t) status->rec_count_estimate - now_recs) *
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

		safe_lock(&bandwidth_mutex);

		if (conf->bandwidth > 0) {
			if (ms > 0) {
				as_store_uint64(&status->byte_count_limit,
						status->byte_count_limit + conf->bandwidth * 1000 / ms);
			}

			safe_signal(&bandwidth_cond);
		}

		bool tmp_stop = has_stopped();
		safe_unlock(&bandwidth_mutex);

		if (tmp_stop) {
			break;
		}
	}

	uint64_t records = as_load_uint64(&status->rec_count_total);
	uint64_t bytes = as_load_uint64(&status->byte_count_total);
	inf("Backed up %" PRIu64 " record(s), %u secondary index(es), %u UDF file(s), "
			"%" PRIu64 " byte(s) in total (~%" PRIu64 " B/rec)", records,
			status->index_count, status->udf_count, bytes,
			records == 0 ? 0 : bytes / records);

	if (args->mach_fd != NULL && (fprintf(args->mach_fd,
					"SUMMARY:%" PRIu64 ":%u:%u:%" PRIu64 ":%" PRIu64 "\n",
					records, status->index_count, status->udf_count, bytes,
					records == 0 ? 0 : bytes / records) < 0 ||
				fflush(args->mach_fd) == EOF)) {
		err_code("Error while writing machine-readable summary");
	}

	if (verbose) {
		ver("Leaving counter thread");
	}

	return (void *)EXIT_SUCCESS;
}

/*
 * Tests whether the given backup file exists.
 *
 * @param file_path  The path of the backup file.
 * @param clear      What to do, if the file already exists. `true` to remove
 *                   it, `false` to report back an error.
 * @param resume     `true` if we are resuming a failed/interrupted backup.
 *
 * @result           `true`, if successful.
 */
static bool
prepare_output_file(const char *file_path, bool clear)
{
	if (verbose) {
		ver("Checking output file %s", file_path);
	}

	if (strcmp(file_path, "-") == 0) {
		return true;
	}

	struct stat buf;

	if (stat(file_path, &buf) < 0) {
		if (errno == ENOENT) {
			return true;
		}

		err_code("Error while checking output file %s", file_path);
		return false;
	}

	if (!clear) {
		err("Output file %s already exists; use -r to remove", file_path);
		return false;
	}

	if (remove(file_path) < 0) {
		err_code("Error while removing existing output file %s", file_path);
		return false;
	}

	return true;
}

/*
 * Prepares the given directory for a backup.
 *
 *   - Creates the directory, if it doesn't exist.
 *
 * @param dir_path  The path of the directory.
 * @param clear     What to do, if the directory already contains backup files.
 *                  'true' to remove them, `false` to report back an error.
 * @param resume    'true' if we are resuming a failed/interrupted backup.
 *
 * @result          'true', if successful.
 */
static bool
prepare_directory(const char *dir_path)
{
	if (verbose) {
		ver("Preparing backup directory %s", dir_path);
	}

	DIR *dir = opendir(dir_path);

	if (dir == NULL) {
		if (errno != ENOENT) {
			err_code("Error while opening directory %s", dir_path);
			return false;
		}

		inf("Directory %s does not exist, creating", dir_path);

		if (mkdir(dir_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0) {
			err_code("Error while creating directory %s", dir_path);
			return false;
		}
	}
	else if (closedir(dir) < 0) {
		err_code("Error while closing directory handle for %s", dir_path);
		return false;
	}

	inf("Directory %s prepared for backup", dir_path);
	return true;
}

/*
 * Scans the directory, doing one of the following:
 *  If !clear && !resume, checks that it contains no '.asb' files.
 *  If clear && !resume, removes all '.asb' files.
 *  If !clear && resume, sets file_count to the number of '.asb' files found.
 */
static bool
scan_directory(const backup_config_t* conf, backup_status_t* status)
{
	struct dirent *entry;
	const char* dir_path = conf->directory;

	DIR *dir = opendir(dir_path);
	if (dir == NULL) {
		err_code("Error while opening directory %s for scanning/clearing", dir_path);
		return false;
	}

	uint64_t file_count = 0;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name + strlen(entry->d_name) - 4, ".asb") == 0) {
			char file_path[PATH_MAX];

			if ((size_t)snprintf(file_path, sizeof file_path, "%s/%s", dir_path,
						entry->d_name) >= sizeof file_path) {
				err("File path too long (%s, %s)", dir_path, entry->d_name);
				closedir(dir);
				return false;
			}

			if (conf->remove_files) {
				if (remove(file_path) < 0) {
					err_code("Error while removing existing backup file %s", file_path);
					closedir(dir);
					return false;
				}
			}
			else if (conf->state_file != NULL) {
				file_count++;
			}
			else {
				err("Directory %s seems to contain an existing backup; "
						"use -r to clear directory", dir_path);
				closedir(dir);
				return false;
			}
		}
	}

	if (closedir(dir) < 0) {
		err_code("Error while closing directory handle for %s", dir_path);
		return false;
	}

	if (file_count != as_load_uint64(&status->file_count)) {
		err("Expected %" PRIu64 " backup files per the backup state, but found "
				"%" PRIu64, status->file_count, file_count);
		return false;
	}

	return true;
}

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
 * Reads the backup progress statuses from the state file and narrows the
 * partition ranges/digests in the partition_filters vector.
 *
 * This method also validates the partition ranges/digests, i.e. ensures that
 * they cover all partitions in the backup file, failing if that is not the
 * case.
 */
static bool
narrow_partition_filters(backup_state_t* state, as_vector* partition_filters)
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

		for (uint16_t part_id = filter->begin; part_id < filter->begin + filter->count;
				part_id++) {
			uint8_t status = backup_state_get_status(state, part_id, digest_val);
			as_partition_status* pstat = &parts_all->parts[part_id - filter->begin];
			pstat->part_id = part_id;
			pstat->done = false;

			switch (status) {
				case BACKUP_STATE_STATUS_NONE:
					err("Partition %u was not saved in the backup state file", part_id);
					cf_free(parts_all);
					return false;

				case BACKUP_STATE_STATUS_NOT_STARTED:
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

	if (bin_list[0] == 0) {
		err("Empty bin list");
		goto cleanup1;
	}

	split_string(bin_list, ',', true, &bin_vec);

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
		if (verbose) {
			ver("Node supports LDT");
		}

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
	if (verbose) {
		ver("Checking for LDT");
	}

	bool tmp_has_ldt = false;

	size_t value_size = sizeof "namespace/" - 1 + strlen(namespace) + 1;
	char value[value_size];
	snprintf(value, value_size, "namespace/%s", namespace);

	for (uint32_t i = 0; i < n_node_names; ++i) {
		if (verbose) {
			ver("Checking for LDT on node %s", (*node_names)[i]);
		}

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
 * Checks that all features being used in this backup run are supported by the
 * version of the server running.
 */
static bool
check_server_version(backup_status_t* status, const backup_config_t* conf)
{
	as_error ae;
	char* response;

	if (aerospike_info_any(status->as, &ae, NULL, "version", &response) != AEROSPIKE_OK) {
		err("Error while querying server version for %s:%d - code %d:\n"
				"%s at %s:%d",
				conf->host, conf->port, ae.code,
				ae.message, ae.file, ae.line);
		return false;
	}

	char* build_str = strstr(response, "build");
	if (build_str == NULL || strlen(build_str) <= 6) {
		err("Invalid info request response from server: %s\n", response);
		cf_free(response);
		return false;
	}

	char* version_str = build_str + 6;
	uint32_t major, minor;
	if (sscanf(version_str, "%" PRIu32 ".%" PRIu32 ".%*" PRIu32 ".%*" PRIu32 "\n",
				&major, &minor) != 2) {
		err("Invalid info request build number: %s\n", version_str);
		cf_free(response);
		return false;
	}

	cf_free(response);

	if (major < 4 || (major == 4 && minor < 9)) {
		err("Aerospike Server version 4.9 or greater is required to run "
				"asbackup, but version %" PRIu32 ".%" PRIu32 " is in use.",
				major, minor);
		return false;
	}

	if ((conf->mod_before != 0 || conf->mod_after != 0) && (major < 5 ||
				(major == 5 && minor < 2))) {
		err("Aerospike Server version 5.2 or greater is required for "
				"--modified-before and --modified-after, but version "
				"%" PRIu32 ".%" PRIu32 " is in use",
				major, minor);
		return false;
	}

	if (conf->set_list.size > 1 && (major < 5 || (major == 5 && minor < 2))) {
		err("Aerospike Server version 5.2 or greater is required for multi-set "
				"backup, but version %" PRIu32 ".%" PRIu32 " is in use",
				major, minor);
		return false;
	}

	if (conf->ttl_zero && (major < 5 || (major == 5 && minor < 2))) {
		err("Aerospike Server version 5.2 or greater is required for "
				"--no-ttl-only, but version %" PRIu32 ".%" PRIu32 " is in use",
				major, minor);
		return false;
	}

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
	if (verbose) {
		ver("Getting cluster object count");
	}

	*obj_count = 0;

	size_t value_size = sizeof "namespace/" - 1 + strlen(namespace) + 1;
	char value[value_size];
	snprintf(value, value_size, "namespace/%s", namespace);
	inf("%-20s%-15s%-15s", "Node ID", "Objects", "Replication");
	ns_count_context ns_context = { 0, 0 };

	for (uint32_t i = 0; i < n_node_names; ++i) {
		if (verbose) {
			ver("Getting object count for node %s", (*node_names)[i]);
		}

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

/*
 * Estimates and outputs the average record size based on the given record size samples.
 *
 * The estimate is the upper bound for a 99.9999% confidence interval. The 99.9999% is where the
 * 4.7 constant comes from.
 *
 * @param mach_fd             The file descriptor for the machine-readable output.
 * @param samples             The array of record size samples.
 * @param n_samples           The number of elements in the sample array.
 * @param rec_count_estimate  The total number of records.
 * @param fd                  The io_proxy that was written to
 */
static void
show_estimate(FILE *mach_fd, uint64_t *samples, uint32_t n_samples,
		uint64_t rec_count_estimate, io_write_proxy_t* fd)
{
	uint64_t upper = 0;
	if (n_samples > 0) {

		double exp_value = 0.0;

		for (uint32_t i = 0; i < n_samples; ++i) {
			exp_value += (double)samples[i];
		}

		exp_value /= n_samples;
		double stand_dev = 0.0;

		for (uint32_t i = 0; i < n_samples; ++i) {
			double diff = (double)samples[i] - exp_value;
			stand_dev += diff * diff;
		}

		stand_dev = sqrt(stand_dev / n_samples);
		upper = (uint64_t) ceil(exp_value + 4.7 * stand_dev / sqrt(n_samples));
	}

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
	stop_nolock();
}

/*
 * Joins a thread and expects it to exit within a reasonable amount of time after `stop` was
 * set to abort all threads.
 *
 * @param thread      The thread to be joined.
 * @param thread_res  The joined thread's return value.
 *
 * @result            `ETIMEDOUT` on a timeout, otherwise the same as `pthread_join()`.
 */
static int32_t
safe_join(pthread_t thread, void **thread_res)
{
	if (verbose) {
		ver("Joining thread 0x%" PRIx64, (uint64_t)thread);
	}

	int32_t since_stop = 0;

	while (true) {
#if !defined __APPLE__
		time_t deadline = time(NULL) + 5;
		struct timespec ts = { deadline, 0 };
		int32_t res = pthread_timedjoin_np(thread, thread_res, &ts);
#else
		int32_t res = pthread_join(thread, thread_res);
#endif

		if (res == 0 || res != ETIMEDOUT) {
			return res;
		}

		if (!has_stopped()) {
			continue;
		}

		if (verbose) {
			ver("Expecting thread 0x%" PRIx64 " to finish (%d)", (uint64_t)thread, since_stop);
		}

		if (++since_stop >= 4) {
			err("Stuck thread detected");
			errno = ETIMEDOUT;
			return ETIMEDOUT;
		}
	}
}

/*
 * Print the tool's version information.
 */
static void
print_version(void)
{
	fprintf(stdout, "Aerospike Backup Utility\n");
	fprintf(stdout, "Version %s\n", TOOL_VERSION);
	fprintf(stdout, "C Client Version %s\n", aerospike_client_version);
	fprintf(stdout, "Copyright 2015-2021 Aerospike. All rights reserved.\n");
}

/*
 * Displays usage information.
 *
 * @param name  The actual name of the `asbackup` binary.
 */
static void
usage(const char *name)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", name);
	fprintf(stderr, "------------------------------------------------------------------------------");
	fprintf(stderr, "\n");
	fprintf(stderr, " -V, --version        Print ASBACKUP version information.\n");
	fprintf(stderr, " -O, --options        Print command-line options message.\n");
	fprintf(stderr, " -Z, --usage          Display this message.\n\n");
	fprintf(stderr, " -v, --verbose        Enable verbose output. Default: disabled\n");
	fprintf(stderr, " -r, --remove-files\n");
	fprintf(stderr, "                      Remove existing backup file (-o) or files (-d).\n");
	fprintf(stderr, "                      NOT allowed in configuration file\n");

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
	fprintf(stderr, " -S, --services-alternate\n");
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
	fprintf(stdout, " -A, --auth\n");
	fprintf(stdout, "                      Set authentication mode when user/password is defined. Modes are\n");
	fprintf(stdout, "                      (INTERNAL, EXTERNAL, EXTERNAL_INSECURE, PKI) and the default is INTERNAL.\n");
	fprintf(stdout, "                      This mode must be set EXTERNAL when using LDAP\n");
	fprintf(stderr, " --tls-enable         Enable TLS on connections. By default TLS is disabled.\n");
	// Deprecated
	//fprintf(stderr, " --tls-encrypt-only   Disable TLS certificate verification.\n");
	fprintf(stderr, " --tls-name           The default tls-name to use to authenticate each TLS socket connection.\n");
	fprintf(stderr, " --tls-cafile=TLS_CAFILE\n");
	fprintf(stderr, "                      Path to a trusted CA certificate file.\n");
	fprintf(stderr, " --tls-capath=TLS_CAPATH.\n");
	fprintf(stderr, "                      Path to a directory of trusted CA certificates.\n");
	fprintf(stderr, " --tls-protocols=TLS_PROTOCOLS\n");
	fprintf(stderr, "                      Set the TLS protocol selection criteria. This format\n"
					"                      is the same as Apache's SSLProtocol documented at http\n"
					"                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
					"                      protocol . If not specified the asbackup will use '-all\n"
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
	fprintf(stderr, " --tls-log-session-info\n");
	fprintf(stderr, "                      Enable logging session information for each TLS connection.\n");


	fprintf(stderr, "[asbackup]\n");
	fprintf(stderr, "  -n, --namespace <namespace>\n");
	fprintf(stderr, "                      The namespace to be backed up. Required.\n");
	fprintf(stderr, "  -s, --set <set>[,<set2>[,...]]\n");
	fprintf(stderr, "                      The set(s) to be backed up. Default: all sets.\n");
	fprintf(stderr, "                      If multiple sets are being backed up, filter-exp cannot be used\n");
	fprintf(stderr, "  -d, --directory <directory>\n");
	fprintf(stderr, "                      The directory that holds the backup files. Required, \n");
	fprintf(stderr, "                      unless -o or -e is used.\n");
	fprintf(stderr, "  -o, --output-file <file>\n");
	fprintf(stderr, "                      Backup to a single backup file. Use - for stdout.\n");
	fprintf(stderr, "                      Required, unless -d or -e is used.\n");
	fprintf(stderr, "  -q, --output-file-prefix <prefix>\n");
	fprintf(stderr, "                      When using directory parameter, prepend a prefix to the names of the generated files.\n");
	fprintf(stderr, "  -c, --continue <state_file>\n");
	fprintf(stderr, "                      Resumes an interrupted/failed backup from where it was left off, given the .state file\n");
	fprintf(stderr, "                      that was generated from the interrupted/failed run.\n");
	fprintf(stderr, "  --state-file-dst <path>\n");
	fprintf(stderr, "                      Either a path with a file name or a directory in which the backup state file will be\n");
	fprintf(stderr, "                      placed if the backup is interrupted/fails. If a path with a file name is used, that\n");
	fprintf(stderr, "                      exact path is where the backup file will be placed. If a directory is given, the backup\n");
	fprintf(stderr, "                      state will be placed in the directory with name `<namespace>.asb.state`, or\n");
	fprintf(stderr, "                      `<prefix>.asb.state` if `--output-file-prefix` is given.\n");
	fprintf(stderr, "  -F, --file-limit\n");
	fprintf(stderr, "                      Rotate backup files, when their size crosses the given\n");
	fprintf(stderr, "                      value (in MiB) Only used when backing up to a directory.\n");
	fprintf(stderr, "                      Default: 250.\n");
	fprintf(stderr, "  -L, --records-per-second <rps>\n");
	fprintf(stderr, "                      Limit returned records per second (rps) rate for each server.\n");
	fprintf(stderr, "                      Do not apply rps limit if records-per-second is zero.\n");
	fprintf(stderr, "                      Default: 0.\n");
	fprintf(stderr, "  -v, --verbose\n");
	fprintf(stderr, "                      Enable more detailed logging.\n");
	fprintf(stderr, "  -x, --no-bins\n");
	fprintf(stderr, "                      Do not include bin data in the backup.\n");
	fprintf(stderr, "  -C, --compact\n");
	fprintf(stderr, "                      Do not apply base-64 encoding to BLOBs; results in smaller\n");
	fprintf(stderr, "                      backup files.\n");
	fprintf(stderr, "  -z, --compress <compression_algorithm>\n");
	fprintf(stderr, "                      Enables compressing of backup files using the specified compression algorithm.\n");
	fprintf(stderr, "                      Supported compression algorithms are: zstd\n");
	fprintf(stderr, "  -y, --encrypt <encryption_algorithm>\n");
	fprintf(stderr, "                      Enables encryption of backup files using the specified encryption algorithm.\n");
	fprintf(stderr, "                      A private key must be given, either via the --encryption-key-file option or\n");
	fprintf(stderr, "                      the --encryption-key-env option.\n");
	fprintf(stderr, "                      Supported encryption algorithms are: aes128, aes256\n");
	fprintf(stderr, "      --encryption-key-file <path>\n");
	fprintf(stderr, "                      Grabs the encryption key from the given file, which must be in PEM format.\n");
	fprintf(stderr, "      --encryption-key-env <env_var_name>\n");
	fprintf(stderr, "                      Grabs the encryption key from the given environment variable, which must be base-64 encoded.\n");
	fprintf(stderr, "  -B, --bin-list <bin 1>[,<bin 2>[,...]]\n");
	fprintf(stderr, "                      Only include the given bins in the backup.\n");
	fprintf(stderr, "                      Default: include all bins.\n");
	fprintf(stderr, "  -l, --node-list <IP addr 1>:<port 1>[,<IP addr 2>:<port 2>[,...]]\n");
	fprintf(stderr, "                      <IP addr 1>:<TLS_NAME 1>:<port 1>[,<IP addr 2>:<TLS_NAME 2>:<port 2>[,...]]\n");
	fprintf(stderr, "                      Backup the given cluster nodes only.\n");
	fprintf(stderr, "                      This argument is mutually exclusive to partition-list/after-digest arguments.\n");
	fprintf(stderr, "                      Default: backup all nodes in the cluster\n");
	fprintf(stderr, "  -w, --parallel <n>\n");
	fprintf(stderr, "                      Maximum number of scan calls to run in parallel. Default: 1\n");
	fprintf(stderr, "                      If only one partition range is given, or the entire namespace is being backed up, the range\n");
	fprintf(stderr, "                      of partitions will be evenly divided by this number to be processed in parallel. Otherwise, each\n");
	fprintf(stderr, "                      filter cannot be parallelized individually, so you may only achieve as much parallelism as there are\n");
	fprintf(stderr, "                      partition filters.\n");
	fprintf(stderr, "  -X, --partition-list <filter[,<filter>[...]]>\n");
	fprintf(stderr, "                      List of partitions to back up. Partition filters can be ranges, individual partitions, or \n");
	fprintf(stderr, "                      records after a specific digest within a single partition.\n");
	fprintf(stderr, "                      This argument is mutually exclusive to after-digest.\n");
	fprintf(stderr, "                      Note: each partition filter is an individual task which cannot be parallelized, so you can only\n");
	fprintf(stderr, "                      achieve as much parallelism as there are partition filters. You may increase parallelism by dividing up\n");
	fprintf(stderr, "                      partition ranges manually.\n");
	fprintf(stderr, "                      Filter: <begin partition>[-<partition count>]|<digest>\n");
	fprintf(stderr, "                      begin partition: 0-4095\n");
	fprintf(stderr, "                      partition count: 1-4096 Default: 1\n");
	fprintf(stderr, "                      digest: base64 encoded string\n");
	fprintf(stderr, "                      Examples: 0-1000, 1000-1000, 2222, EjRWeJq83vEjRRI0VniavN7xI0U=\n");
	fprintf(stderr, "                      Default: 0-4096 (all partitions)\n");
	fprintf(stderr, "  -D, --after-digest <digest>\n");
	fprintf(stderr, "                      Backup records after record digest in record's partition plus all succeeding\n");
	fprintf(stderr, "                      partitions. Used to resume backup with last record received from previous\n");
	fprintf(stderr, "                      incomplete backup.\n");
	fprintf(stderr, "                      This argument is mutually exclusive to partition-list.\n");
	fprintf(stderr, "                      Format: base64 encoded string\n");
	fprintf(stderr, "                      Example: EjRWeJq83vEjRRI0VniavN7xI0U=\n");
	fprintf(stderr, "  -f, --filter-exp <b64 encoded expression>\n");
	fprintf(stderr, "                      Use the encoded filter expression in each scan call,\n");
	fprintf(stderr, "                      which can be used to do a partial backup.\n");
	fprintf(stderr, "                      The expression to be used can be base64 encoded through any client.\n");
	fprintf(stderr, "                      This argument is mutually exclusive with multi-set backup\n");
	fprintf(stderr, "  -M, --max-records <number of records>\n");
	fprintf(stderr, "                      The number of records approximately to back up. Default: all records\n");
	fprintf(stderr, "  -m, --machine <path>\n");
	fprintf(stderr, "                      Output machine-readable status updates to the given path, \n");
	fprintf(stderr,"                       typically a FIFO.\n");
	fprintf(stderr, "  -e, --estimate\n");
	fprintf(stderr, "                      Estimate the backed-up record size from a random sample of \n");
	fprintf(stderr, "                      10,000 records at 99.9999%% confidence.\n");
	fprintf(stderr, "  -N, --nice <bandwidth>\n");
	fprintf(stderr, "                      The limit for write storage bandwidth in MiB/s.\n");
	fprintf(stderr, "  -R, --no-records\n");
	fprintf(stderr, "                      Don't backup any records.\n");
	fprintf(stderr, "  -I, --no-indexes\n");
	fprintf(stderr, "                      Don't backup any indexes.\n");
	fprintf(stderr, "  -u, --no-udfs\n");
	fprintf(stderr, "                      Don't backup any UDFs.\n");
	fprintf(stderr, "  -a, --modified-after <YYYY-MM-DD_HH:MM:SS>\n");
	fprintf(stderr, "                      Perform an incremental backup; only include records \n");
	fprintf(stderr, "                      that changed after the given date and time. The system's \n");
	fprintf(stderr, "                      local timezone applies. If only HH:MM:SS is specified, then\n");
	fprintf(stderr, "                      today's date is assumed as the date. If only YYYY-MM-DD is \n");
	fprintf(stderr, "                      specified, then 00:00:00 (midnight) is assumed as the time.\n");
	fprintf(stderr, "  -b, --modified-before <YYYY-MM-DD_HH:MM:SS>\n");
	fprintf(stderr, "                      Only include records that last changed before the given\n");
	fprintf(stderr, "                      date and time. May combined with --modified-after to specify\n");
	fprintf(stderr, "                      a range.\n");
	fprintf(stderr, "      --no-ttl-only\n");
	fprintf(stderr, "                      Only include records that have no ttl set (persistent records).\n");
	fprintf(stderr, "      --socket-timeout <ms>\n");
	fprintf(stderr, "                      Socket timeout in milliseconds. Default is 10 seconds.\n");
	fprintf(stderr, "                      If this value is 0, its set to total-timeout. If both are 0,\n");
	fprintf(stderr, "                      there is no socket idle time limit\n");
	fprintf(stderr, "      --total-timeout <ms>\n");
	fprintf(stderr, "                      Total socket timeout in milliseconds. Default is 0, i.e. no timeout.\n");
	fprintf(stderr, "      --max-retries <n>\n");
	fprintf(stderr, "                      Maximum number of retries before aborting the current transaction.\n");
	fprintf(stderr, "                      The default is 5.\n");
	fprintf(stderr, "      --sleep-between-retries <ms>\n");
	fprintf(stderr, "                      The amount of time to sleep between retries. Default is 0.\n\n");

	fprintf(stderr, "\n\n");
	fprintf(stderr, "Default configuration files are read from the following files in the given order:\n");
	fprintf(stderr, "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n");
	fprintf(stderr, "The following sections are read: (cluster asbackup include)\n");
	fprintf(stderr, "The following options effect configuration file behavior\n");
	fprintf(stderr, " --no-config-file \n");
	fprintf(stderr, "                      Do not read any config file. Default: disabled\n");
	fprintf(stderr, " --instance <name>\n");
	fprintf(stderr, "                      Section with these instance is read. e.g in case instance `a` is specified\n");
	fprintf(stderr, "                      sections cluster_a, asbackup_a is read.\n");
	fprintf(stderr, " --config-file <path>\n");
	fprintf(stderr, "                      Read this file after default configuration file.\n");
	fprintf(stderr, " --only-config-file <path>\n");
	fprintf(stderr, "                      Read only this configuration file.\n");
}

