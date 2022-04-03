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

// The C client's version string.
extern char *aerospike_client_version;

static pthread_mutex_t g_stop_lock;
static pthread_cond_t g_stop_cond;
// Makes background threads exit.
static volatile bool g_stop = false;

// Used by threads when reading from one file to ensure mutual exclusion on access
// to the file
static pthread_mutex_t file_read_mutex = PTHREAD_MUTEX_INITIALIZER;
// Used by the counter thread to signal newly available bandwidth or
// transactions to the restore threads.
static pthread_cond_t limit_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t limit_mutex = PTHREAD_MUTEX_INITIALIZER;


//==========================================================
// Forward Declarations.
//

static bool has_stopped(void);
static void stop(void);
static void stop_nolock(void);
static void sleep_for(uint64_t n_secs);
static int update_file_pos(per_thread_context_t* ptc);
static bool close_file(io_read_proxy_t *fd);
static bool open_file(const char *file_path, as_vector *ns_vec, io_read_proxy_t *fd,
		bool *legacy, uint32_t *line_no, bool *first_file, off_t *size,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey);
static void free_udf(udf_param *param);
static void free_udfs(as_vector *udf_vec);
static void free_index(index_param *param);
static void free_indexes(as_vector *index_vec);
static bool check_set(char *set, as_vector *set_vec);
static void * restore_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static const char * print_set(const char *set);
static bool compare_sets(const char *set1, const char *set2);
static index_status check_index(aerospike *as, index_param *index, uint32_t timeout);
static bool restore_index(aerospike *as, index_param *index,
		as_vector *set_vec, restore_thread_args*, uint32_t timeout);
static bool wait_index(index_param *index);
static bool restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec,
		restore_thread_args*, bool wait, uint32_t timeout);
static bool restore_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static bool wait_udf(aerospike *as, udf_param *udf, uint32_t timeout);
static bool parse_list(const char *which, size_t size, char *list, as_vector *vec);
static void add_default_tls_host(as_config *as_conf, const char* tls_name);
static void sig_hand(int32_t sig);
static void print_version(void);
static void usage(const char *name);
static void print_stat(per_thread_context_t *ptc, cf_clock *prev_log,
		uint64_t *prev_records,	cf_clock *now, cf_clock *store_time, cf_clock *read_time);


//==========================================================
// Public API.
//

int32_t
restore_main(int32_t argc, char **argv)
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
		{ "tls-cert-blackList", required_argument, NULL, TLS_OPT_CERT_BLACK_LIST },
		{ "tls-log-session-info", no_argument, NULL, TLS_OPT_LOG_SESSION_INFO },
		{ "tls-keyfile", required_argument, NULL, TLS_OPT_KEY_FILE },
		{ "tls-keyfile-password", optional_argument, NULL, TLS_OPT_KEY_FILE_PASSWORD },
		{ "tls-certfile", required_argument, NULL, TLS_OPT_CERT_FILE },

		// asrestore section in config file
		{ "namespace", required_argument, NULL, 'n' },
		{ "directory", required_argument, NULL, 'd' },
		{ "input-file", required_argument, NULL, 'i' },
		{ "compress", required_argument, NULL, 'z' },
		{ "encrypt", required_argument, NULL, 'y' },
		{ "encryption-key-file", required_argument, NULL, '1' },
		{ "encryption-key-env", required_argument, NULL, '2' },
		{ "parallel", required_argument, NULL, 't' },
		{ "threads", required_argument, NULL, '_' },
		{ "machine", required_argument, NULL, 'm' },
		{ "bin-list", required_argument, NULL, 'B' },
		{ "set-list", required_argument, NULL, 's' },
		{ "unique", no_argument, NULL, 'u' },
		{ "ignore-record-error", no_argument, NULL, 'K'},
		{ "replace", no_argument, NULL, 'r' },
		{ "no-generation", no_argument, NULL, 'g' },
		{ "extra-ttl", required_argument, NULL, 'l' },
		{ "nice", required_argument, NULL, 'N' },
		{ "no-records", no_argument, NULL, 'R' },
		{ "no-indexes", no_argument, NULL, 'I' },
		{ "indexes-last", no_argument, NULL, 'L' },
		{ "no-udfs", no_argument, NULL, 'F' },
		{ "wait", no_argument, NULL, 'w' },
		{ "services-alternate", no_argument, NULL, 'S' },
		{ "timeout", required_argument, 0, 'T' },
		{ "socket-timeout", required_argument, NULL, COMMAND_OPT_SOCKET_TIMEOUT },
		{ "total-timeout", required_argument, NULL, COMMAND_OPT_TOTAL_TIMEOUT },
		{ "max-retries", required_argument, NULL, COMMAND_OPT_MAX_RETRIES },
		{ "retry-delay", required_argument, NULL, COMMAND_OPT_RETRY_DELAY },

		{ "s3-region", required_argument, NULL, COMMAND_OPT_S3_REGION },
		{ "s3-profile", required_argument, NULL, COMMAND_OPT_S3_PROFILE },
		{ "s3-endpoint-override", required_argument, NULL, COMMAND_OPT_S3_ENDPOINT_OVERRIDE },
		{ "s3-max-async-downloads", required_argument, NULL, COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS },
		{ NULL, 0, NULL, 0 }
	};

	int32_t res = EXIT_FAILURE;

	restore_config_t conf;
	restore_config_default(&conf);
	
	conf.decoder = &(backup_decoder_t){ text_parse };

	int32_t optcase;
	uint64_t tmp;

	// Don't print error messages for the first two argument parsers
	opterr = 0;

	// option string should start with '-' to avoid argv permutation
	// we need same argv sequence in third check to support space separated optional argument value
	while ((optcase = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {
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
	optind = 1;
	while ((optcase = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {
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
			fprintf(stderr, "--no-config-file and --only-config-file are mutually exclusive option. Please enable only one.\n");
			return false;
		}
	}

	// Now print error messages
	opterr = 1;
	// Reset to optind (internal variable)
	// to parse all options again
	optind = 1;
	while ((optcase = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {
		switch (optcase) {
		case 'h':
			cf_free(conf.host);
			conf.host = safe_strdup(optarg);
			break;

		case 'p':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > 65535) {
				err("Invalid port value %s", optarg);
				goto cleanup1;
			}

			conf.port = (int32_t)tmp;
			break;

		case 'U':
			conf.user = safe_strdup(optarg);
			break;

		case 'P':
			cf_free(conf.password);
			if (optarg) {
				conf.password = safe_strdup(optarg);
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					conf.password = safe_strdup(argv[optind++]);
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf.password = safe_strdup(DEFAULTPASSWORD);
				}
			}
			break;

		case 'A':
			conf.auth_mode = safe_strdup(optarg);
			break;

		case 'n':
			conf.ns_list = safe_strdup(optarg);
			break;

		case 'd':
			conf.directory = safe_strdup(optarg);
			break;

		case 'i':
			conf.input_file = safe_strdup(optarg);
			break;

		case 'z':
			if (parse_compression_type(optarg, &conf.compress_mode) != 0) {
				err("Invalid compression type \"%s\"\n", optarg);
				goto cleanup1;
			}
			break;

		case 'y':
			if (parse_encryption_type(optarg, &conf.encrypt_mode) != 0) {
				err("Invalid encryption type \"%s\"\n", optarg);
				goto cleanup1;
			}
			break;

		case '1':
			// encryption key file
			if (conf.pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env\n");
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
				err("Cannot specify both encryption-key-file and encryption-key-env\n");
				goto cleanup1;
			}
			conf.pkey = parse_encryption_key_env(optarg);
			if (conf.pkey == NULL) {
				goto cleanup1;
			}
			break;

		case '_':
			err("WARNING: '--threads' option is deprecated, use `--parallel` instead");
		case 't':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > MAX_THREADS) {
				err("Invalid threads value %s", optarg);
				goto cleanup1;
			}

			conf.parallel = (uint32_t)tmp;
			break;

		case 'v':
			if (as_load_bool(&g_verbose)) {
				enable_client_log();
			} else {
				as_store_bool(&g_verbose, true);
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

		case 'l':
			if (! better_atoi(optarg, &tmp)) {
				err("Invalid extra-ttl value %s", optarg);
				goto cleanup1;
			}

			conf.extra_ttl = (int32_t)tmp;
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

		case COMMAND_OPT_S3_REGION:
			conf.s3_region = strdup(optarg);
			break;

		case COMMAND_OPT_S3_PROFILE:
			conf.s3_profile = strdup(optarg);
			break;

		case COMMAND_OPT_S3_ENDPOINT_OVERRIDE:
			conf.s3_endpoint_override = strdup(optarg);
			break;

		case COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS:
			if (!better_atoi(optarg, &tmp) || tmp == 0 || tmp > UINT_MAX) {
				err("Invalid S3 max async downloads value %s", optarg);
				goto cleanup1;
			}
			conf.s3_max_async_downloads = (uint32_t) tmp;
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

	if ((conf.pkey != NULL) ^ (conf.encrypt_mode != IO_PROXY_ENCRYPT_NONE)) {
		err("Must specify both encryption mode and a private key "
				"file/environment variable\n");
		goto cleanup1;
	}

	if (conf.s3_region != NULL) {
		s3_set_region(conf.s3_region);
	}

	if (conf.s3_profile != NULL) {
		s3_set_profile(conf.s3_profile);
	}

	if (conf.s3_endpoint_override != NULL) {
		s3_set_endpoint(conf.s3_endpoint_override);
	}

	s3_set_max_async_downloads(conf.s3_max_async_downloads);

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

	if (conf.tls_name != NULL) {
		add_default_tls_host(&as_conf, conf.tls_name);
	}

	if (conf.auth_mode && ! as_auth_mode_from_string(&as_conf.auth_mode, conf.auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / "
				"EXTERNAL / EXTERNAL_INSECURE / PKI\n",
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

	ver("Connecting to cluster");

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
	as_store_uint64(&conf.total_bytes, 0);
	as_store_uint64(&conf.total_records, 0);
	as_store_uint64(&conf.expired_records, 0);
	as_store_uint64(&conf.skipped_records, 0);
	as_store_uint64(&conf.ignored_records, 0);
	as_store_uint64(&conf.inserted_records, 0);
	as_store_uint64(&conf.existed_records, 0);
	as_store_uint64(&conf.fresher_records, 0);
	as_store_uint64(&conf.backoff_count, 0);
	as_store_uint32(&conf.index_count, 0);
	as_store_uint32(&conf.skipped_indexes, 0);
	as_store_uint32(&conf.matched_indexes, 0);
	as_store_uint32(&conf.mismatched_indexes, 0);
	as_store_uint32(&conf.udf_count, 0);

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = &conf;
	counter_args.node_names = node_names;
	counter_args.n_node_names = n_node_names;
	counter_args.mach_fd = mach_fd;

	ver("Creating counter thread");

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

	if (pthread_mutex_init(&restore_args.idx_udf_lock, NULL) != 0) {
		err("Failed to initialize mutex lock");
		goto cleanup5;
	}

	cf_queue *job_queue = cf_queue_create(sizeof (restore_thread_args), true);

	if (job_queue == NULL) {
		err_code("Error while allocating job queue");
		goto cleanup6;
	}

	uint32_t line_no;
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
		goto cleanup7;
	}

	if (ns_vec.size > 2) {
		err("Invalid namespace option");
		goto cleanup7;
	}

	if (conf.nice_list != NULL) {
		if (!parse_list("nice", 10, conf.nice_list, &nice_vec)) {
			err("Error while parsing nice list");
			goto cleanup7;
		}

		if (nice_vec.size != 2) {
			err("Invalid nice option");
			goto cleanup7;
		}

		char *item0 = as_vector_get_ptr(&nice_vec, 0);
		char *item1 = as_vector_get_ptr(&nice_vec ,1);

		if (!better_atoi(item0, &tmp) || tmp < 1) {
			err("Invalid bandwidth value %s", item0);
			goto cleanup7;
		}

		conf.bandwidth = tmp * 1024 * 1024;

		if (!better_atoi(item1, &tmp) || tmp < 1 || tmp > 1000000000) {
			err("Invalid TPS value %s", item1);
			goto cleanup7;
		}

		conf.tps = (uint32_t)tmp;
	}

	conf.bytes_limit = conf.bandwidth;
	conf.records_limit = conf.tps;

	if (conf.bin_list != NULL && !parse_list("bin", AS_BIN_NAME_MAX_SIZE, conf.bin_list,
			&bin_vec)) {
		err("Error while parsing bin list");
		goto cleanup7;
	}

	if (conf.set_list != NULL && !parse_list("set", AS_SET_MAX_SIZE, conf.set_list, &set_vec)) {
		err("Error while parsing set list");
		goto cleanup7;
	}

	restore_args.ns_vec = &ns_vec;
	restore_args.bin_vec = &bin_vec;
	restore_args.set_vec = &set_vec;
	restore_args.index_vec = &index_vec;
	restore_args.udf_vec = &udf_vec;

	// restoring from a directory
	if (conf.directory != NULL) {
		if (!get_backup_files(conf.directory, &file_vec)) {
			err("Error while getting backup files");
			goto cleanup7;
		}

		if (file_vec.size == 0) {
			err("No backup files found");
			goto cleanup7;
		}

		if (!conf.no_records) {
			ver("Triaging %u backup file(s)", file_vec.size);

			for (uint32_t i = 0; i < file_vec.size; ++i) {
				char *path = as_vector_get_ptr(&file_vec, i);
				off_t size = get_file_size(path);
				if (size == -1) {
					err("Failed to get the size of file %s", path);
					goto cleanup7;
				}

				conf.estimated_bytes += size;
			}
		}

		ver("Pushing %u exclusive job(s) to job queue", file_vec.size);

		// push a job for each backup file
		for (uint32_t i = 0; i < file_vec.size; ++i) {
			restore_args.path = as_vector_get_ptr(&file_vec, i);

			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup8;
			}
		}

		if (file_vec.size < conf.parallel) {
			conf.parallel = file_vec.size;
		}
	}
	// restoring from a single backup file
	else {
		inf("Restoring %s", conf.input_file);

		restore_args.shared_fd =
			(io_read_proxy_t*) cf_malloc(sizeof(io_read_proxy_t));
		// open the file, file descriptor goes to restore_args.shared_fd
		if (!open_file(conf.input_file, restore_args.ns_vec, restore_args.shared_fd,
				&restore_args.legacy, &line_no, NULL,
				conf.no_records ? NULL : &conf.estimated_bytes,
				conf.compress_mode, conf.encrypt_mode, conf.pkey)) {
			err("Error while opening shared backup file");
			cf_free(restore_args.shared_fd);
			goto cleanup7;
		}

		ver("Pushing %u shared job(s) to job queue", conf.parallel);

		restore_args.line_no = &line_no;
		restore_args.path = conf.input_file;

		// push an identical job for each thread; all threads use restore_args.shared_fd for reading
		for (uint32_t i = 0; i < conf.parallel; ++i) {
			if (cf_queue_push(job_queue, &restore_args) != CF_QUEUE_OK) {
				err("Error while queueing restore job");
				goto cleanup8;
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
			goto cleanup9;
		}

		++threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup9:
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
			!restore_indexes(&as, &index_vec, &set_vec, &restore_args, conf.wait, conf.timeout)) {
		err("Error while restoring secondary indexes to cluster");
		res = EXIT_FAILURE;
	}

	if (res == EXIT_SUCCESS && conf.wait) {
		for (uint32_t i = 0; i < udf_vec.size; i++) {
			udf_param* udf = as_vector_get(&udf_vec, i);
			if (!wait_udf(&as, udf, conf.timeout)) {
				err("Error while waiting for UDF upload");
				res = EXIT_FAILURE;
			}
		}
	}

cleanup8:
	free_indexes(&index_vec);
	free_udfs(&udf_vec);

	if (conf.directory != NULL) {
		for (uint32_t i = 0; i < file_vec.size; ++i) {
			cf_free(as_vector_get_ptr(&file_vec, i));
		}
	}
	else {
		if (!close_file(restore_args.shared_fd)) {
			err("Error while closing shared backup file");
			res = EXIT_FAILURE;
		}
		cf_free(restore_args.shared_fd);
	}

cleanup7:
	as_vector_destroy(&set_vec);
	as_vector_destroy(&bin_vec);
	as_vector_destroy(&nice_vec);
	as_vector_destroy(&ns_vec);
	as_vector_destroy(&udf_vec);
	as_vector_destroy(&index_vec);
	as_vector_destroy(&file_vec);
	cf_queue_destroy(job_queue);

cleanup6:
	pthread_mutex_destroy(&restore_args.idx_udf_lock);

cleanup5:
	stop();

	ver("Waiting for counter thread");

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
	restore_config_destroy(&conf);

	file_proxy_cloud_shutdown();

	ver("Exiting with status code %d", res);

	return res;
}

void
restore_config_default(restore_config_t *conf)
{
	conf->host = safe_strdup(DEFAULT_HOST);
	conf->use_services_alternate = false;
	conf->port = DEFAULT_PORT;
	conf->user = NULL;
	conf->password = safe_strdup(DEFAULTPASSWORD);
	conf->auth_mode = NULL;

	conf->s3_region = NULL;
	conf->s3_profile = NULL;
	conf->s3_endpoint_override = NULL;
	conf->s3_max_async_downloads = S3_DEFAULT_MAX_ASYNC_DOWNLOADS;

	conf->parallel = DEFAULT_THREADS;
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
	conf->pkey = NULL;
	conf->compress_mode = IO_PROXY_COMPRESS_NONE;
	conf->encrypt_mode = IO_PROXY_ENCRYPT_NONE;
	conf->ignore_rec_error = false;
	conf->unique = false;
	conf->replace = false;
	conf->extra_ttl = 0;
	conf->no_generation = false;
	conf->bandwidth = 0;
	conf->tps = 0;
	conf->timeout = TIMEOUT;

	conf->socket_timeout = 10 * 1000;
	conf->total_timeout = 0;
	conf->max_retries = 0;
	conf->retry_delay = 0;

	memset(&conf->tls, 0, sizeof(as_config_tls));
	conf->tls_name = NULL;
	conf->as = NULL;
	conf->decoder = NULL;
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


//==========================================================
// Local helpers.
//

/*
 * returns true if the program has stoppped
 */
static bool
has_stopped(void)
{
	return as_load_uint8((uint8_t*) &g_stop);
}

/*
 * stops the program
 */
static void
stop(void)
{
	pthread_mutex_lock(&g_stop_lock);

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	// wakes all threads waiting on the stop condition
	pthread_cond_broadcast(&g_stop_cond);

	pthread_mutex_unlock(&g_stop_lock);

	s3_disable_request_processing();
}

/*
 * stops the program, which is safe in interrupt contexts
 */
static void
stop_nolock(void)
{
	bool was_locked = (pthread_mutex_trylock(&g_stop_lock) == 0);

	// sets the stop variable
	as_store_uint8((uint8_t*) &g_stop, 1);

	// wakes all threads waiting on the stop condition
	// this can potentially miss some threads waiting on a condition variable if
	// trylock failed, but they will eventually time out
	pthread_cond_broadcast(&g_stop_cond);

	if (was_locked) {
		pthread_mutex_unlock(&g_stop_lock);
	}

	s3_disable_request_processing();
}

/*
 * sleep on the stop condition, exiting from the sleep early if the program is
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
	as_add_uint64(&ptc->conf->total_bytes, diff);

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
 * Deallocates the fields of a udf_param UDF file record.
 *
 * @param param  The udf_param to be deallocated.
 */
static void
free_udf(udf_param *param)
{
	cf_free(param->name);
	cf_free(param->data);
}

/*
 * Deallocates a vector of udf_param UDF file records.
 *
 * @param udf_vec  The vector of udf_param records to be deallocated.
 */
static void
free_udfs(as_vector *udf_vec)
{
	ver("Freeing %u UDF file(s)", udf_vec->size);

	for (uint32_t i = 0; i < udf_vec->size; ++i) {
		udf_param *param = as_vector_get(udf_vec, i);
		free_udf(param);
	}
}

/*
 * Deallocates the fields of an index_param secondary index information record.
 *
 * @param param  The index_param to be deallocated.
 */
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

/*
 * Deallocates a vector of index_param secondary index information records.
 *
 * @param index_vec  The vector of index_param records to be deallocated.
 */
static void
free_indexes(as_vector *index_vec)
{
	ver("Freeing %u index(es)", index_vec->size);

	for (uint32_t i = 0; i < index_vec->size; ++i) {
		index_param *param = as_vector_get(index_vec, i);
		free_index(param);
	}
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
 *   - Pops the restore_thread_args for a backup file off the job queue.
 *     - When restoring from a single file, all restore_thread_args elements in the queue are
 *       identical and there are initially as many elements in the queue as there are threads.
 *     - When restoring from a directory, the queue initially contains one element for each backup
 *       file in the directory.
 *   - Initializes a per_thread_context for that backup file.
 *   - If restoring from a single file: uses the shared file descriptor given by
 *     restore_thread_args.shared_fd.
 *   - If restoring from a directory: opens the backup file given by restore_thread_args.path.
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
	ver("Entering restore thread");

	cf_queue *job_queue = cont;
	void *res = (void *)EXIT_FAILURE;

	while (true) {
		if (has_stopped()) {
			ver("Restore thread detected failure");

			break;
		}

		restore_thread_args args;
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

		uint32_t line_no;
		per_thread_context_t ptc;
		ptc.conf = args.conf;
		ptc.path = args.path;
		ptc.shared_fd = args.shared_fd;
		ptc.line_no = args.line_no != NULL ? args.line_no : &line_no;
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
				safe_lock(&file_read_mutex);
			}

			// check the stop flag inside the critical section; makes sure that we do not try to
			// read from the shared file descriptor after another thread encountered an error and
			// set the stop flag
			if (has_stopped()) {
				if (ptc.conf->input_file != NULL) {
					safe_unlock(&file_read_mutex);
				}

				break;
			}

			cf_clock read_start = as_load_bool(&g_verbose) ? cf_getus() : 0;
			decoder_status res = ptc.conf->decoder->parse(ptc.fd, ptc.legacy,
					ptc.ns_vec, ptc.bin_vec, ptc.line_no, &rec,
					ptc.conf->extra_ttl, &expired, &index, &udf);
			cf_clock read_time = as_load_bool(&g_verbose) ? cf_getus() - read_start : 0;

			// set the stop flag inside the critical section; see check above
			if (res == DECODER_ERROR) {
				stop();
			}

			if (ptc.conf->input_file != NULL) {
				safe_unlock(&file_read_mutex);
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
						!restore_index(args.conf->as, &index, ptc.set_vec,
							&args, args.conf->timeout)) {
					err("Error while restoring secondary index");
					break;
				}

				pthread_mutex_lock(&args.idx_udf_lock);
				as_vector_append(args.index_vec, &index);
				pthread_mutex_unlock(&args.idx_udf_lock);

				as_incr_uint32(&args.conf->index_count);
				continue;
			}

			if (res == DECODER_UDF) {
				if (args.conf->no_udfs) {
					ver("Ignoring UDF file block");
					free_udf(&udf);
					continue;
				}
				else if (!restore_udf(args.conf->as, &udf, args.conf->timeout)) {
					err("Error while restoring UDF");
					break;
				}

				pthread_mutex_lock(&args.idx_udf_lock);
				as_vector_append(args.udf_vec, &udf);
				pthread_mutex_unlock(&args.idx_udf_lock);

				as_incr_uint32(&args.conf->udf_count);
				continue;
			}

			if (res == DECODER_RECORD) {
				if (args.conf->no_records) {
					break;
				}

				if (expired) {
					as_incr_uint64(&ptc.conf->expired_records);
				} else if (rec.bins.size == 0 || !check_set(rec.key.set, ptc.set_vec)) {
					as_incr_uint64(&ptc.conf->skipped_records);
				} else {
					useconds_t backoff = INITIAL_BACKOFF * 1000;
					int32_t tries;

					for (tries = 0; tries < MAX_TRIES && !has_stopped(); ++tries) {
						as_error ae;
						policy.key = rec.key.valuep != NULL ? AS_POLICY_KEY_SEND :
								AS_POLICY_KEY_DIGEST;
						cf_clock store_start = as_load_bool(&g_verbose) ? cf_getus() : 0;
						as_status put = aerospike_key_put(ptc.conf->as, &ae, &policy, &rec.key,
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
								as_incr_uint64(&ptc.conf->ignored_records);

								if (! flag_ignore_rec_error) {
									stop();
									err("Error while storing record - code %d: %s at %s:%d", ae.code, ae.message, ae.file, ae.line);
									err("Encountered error while restoring. Skipping retries and aborting!!");
								}
								break;

							// Conditional error based on input config. No
							// retries.
							case AEROSPIKE_ERR_RECORD_GENERATION:
								as_incr_uint64(&ptc.conf->fresher_records);
								break;

							case AEROSPIKE_ERR_RECORD_EXISTS:
								as_incr_uint64(&ptc.conf->existed_records);
								break;

							case AEROSPIKE_OK:
								print_stat(&ptc, &prev_log, &prev_records,
										&now, &store_time, &read_time);
								as_incr_uint64(&ptc.conf->inserted_records);
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
									as_incr_uint64(&ptc.conf->backoff_count);
								} else {
									backoff = INITIAL_BACKOFF * 1000;
									sleep_for(1);
								} 
								break;

						}

						if (!do_retry) {
							break;
						}
					}
				}

				as_incr_uint64(&ptc.conf->total_records);
				as_record_destroy(&rec);

				if (ptc.conf->bandwidth > 0 && ptc.conf->tps > 0) {
					safe_lock(&limit_mutex);

					while ((as_load_uint64(&ptc.conf->total_bytes) >= ptc.conf->bytes_limit ||
								as_load_uint64(&ptc.conf->total_records) >= ptc.conf->records_limit) &&
							!has_stopped()) {
						safe_wait(&limit_cond, &limit_mutex);
					}

					safe_unlock(&limit_mutex);
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

	cf_clock prev_ms = cf_getms();

	uint32_t iter = 0;
	cf_clock print_prev_ms = prev_ms;
	uint64_t prev_bytes = as_load_uint64(&conf->total_bytes);
	uint64_t mach_prev_bytes = prev_bytes;
	uint64_t prev_records = as_load_uint64(&conf->total_records);

	while (true) {
		sleep_for(1);
		bool last_iter = has_stopped();

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		prev_ms = now_ms;

		uint64_t now_bytes = as_load_uint64(&conf->total_bytes);
		uint64_t now_records = as_load_uint64(&conf->total_records);

		uint64_t expired_records = as_load_uint64(&conf->expired_records);
		uint64_t skipped_records = as_load_uint64(&conf->skipped_records);
		uint64_t ignored_records = as_load_uint64(&conf->ignored_records);
		uint64_t inserted_records = as_load_uint64(&conf->inserted_records);
		uint64_t existed_records = as_load_uint64(&conf->existed_records);
		uint64_t fresher_records = as_load_uint64(&conf->fresher_records);
		uint64_t backoff_count = as_load_uint64(&conf->backoff_count);
		uint32_t index_count = as_load_uint32(&conf->index_count);
		uint32_t udf_count = as_load_uint32(&conf->udf_count);

		int32_t percent = conf->estimated_bytes == 0 ? -1 :
			(int32_t)(now_bytes * 100 / (uint64_t)conf->estimated_bytes);

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

			int32_t eta = (bytes == 0 || conf->estimated_bytes == 0) ? -1 :
				(int32_t)(((uint64_t)conf->estimated_bytes - now_bytes) * ms / bytes / 1000);
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

			int32_t eta = (bytes == 0 || conf->estimated_bytes == 0) ? -1 :
				(int32_t)(((uint64_t)conf->estimated_bytes - now_bytes) * ms / bytes / 1000);
			char eta_buff[ETA_BUF_SIZE];
			format_eta(eta, eta_buff, sizeof eta_buff);

			if (eta >= 0 && (fprintf(args->mach_fd, "REMAINING:%s\n", eta_buff) < 0 ||
					fflush(args->mach_fd) == EOF)) {
				err_code("Error while writing machine-readable remaining time");
			}

			mach_prev_bytes = now_bytes;
		}

		safe_lock(&limit_mutex);

		if (conf->bandwidth > 0 && conf->tps > 0) {
			if (ms > 0) {
				conf->bytes_limit += conf->bandwidth * 1000 / ms;
				conf->records_limit += conf->tps * 1000 / ms;
			}

			safe_signal(&limit_cond);
		}

		safe_unlock(&limit_mutex);

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
		restore_thread_args* args, uint32_t timeout)
{
	path_param *path = as_vector_get(&index->path_vec, 0);

	if (!check_set(index->set, set_vec)) {
		ver("Skipping index with unwanted set %s:%s:%s (%s)", index->ns, index->set,
				index->name, path->path);
		as_incr_uint32(&args->conf->skipped_indexes);

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
			sleep_for(1);
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
				as_incr_uint32(&args->conf->mismatched_indexes);
			}
			else {
				as_incr_uint32(&args->conf->matched_indexes);
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
restore_indexes(aerospike *as, as_vector *index_vec, as_vector *set_vec, restore_thread_args* args,
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

	uint32_t skipped = as_load_uint32(&args->conf->skipped_indexes);
	uint32_t matched = as_load_uint32(&args->conf->matched_indexes);
	uint32_t mismatched = as_load_uint32(&args->conf->mismatched_indexes);

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
 * Parses a `item1[,item2[,...]]` string into a vector of strings.
 *
 * @param which  The type of the list to be parsed. Only used in error messages.
 * @param size   Maximal length of each individual list item.
 * @param list   The string to be parsed.
 * @param vec    The populated vector.
 *
 * @result       `true`, if successful.
 */
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
 * Signal handler for `SIGINT` and `SIGTERM`.
 *
 * @param sig  The signal number.
 */
static void
sig_hand(int32_t sig)
{
	(void)sig;
	err("### Restore interrupted ###");
	stop_nolock();
}

/*
 * Print the tool's version information.
 */
static void
print_version(void)
{
	fprintf(stdout, "Aerospike Restore Utility\n");
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
	fprintf(stderr, " --tls-log-session-info\n");
	fprintf(stderr, "                      Enable logging session information for each TLS connection.\n");


	fprintf(stderr, "[asrestore]\n");
	fprintf(stderr, "  -n, --namespace <namespace>\n");
	fprintf(stderr, "                      Used to restore to a different namespace.\n");
	fprintf(stderr, "  -d, --directory <directory>\n");
	fprintf(stderr, "                      The directory that holds the backup files. Required, \n");
	fprintf(stderr, "                      unless -i is used.\n");
	fprintf(stderr, "  -i, --input-file <file>\n");
	fprintf(stderr, "                      Restore from a single backup file. Use - for stdin.\n");
	fprintf(stderr, "                      Required, unless -d is used.\n");
	fprintf(stderr, "  -z, --compress <compression_algorithm>\n");
	fprintf(stderr, "                      Enables decompressing of backup files using the specified compression algorithm.\n");
	fprintf(stderr, "                      This must match the compression mode used when backing up the data.\n");
	fprintf(stderr, "                      Supported compression algorithms are: zstd\n");
	fprintf(stderr, "  -y, --encrypt <encryption_algorithm>\n");
	fprintf(stderr, "                      Enables decryption of backup files using the specified encryption algorithm.\n");
	fprintf(stderr, "                      This must match the encryption mode used when backing up the data.\n");
	fprintf(stderr, "                      A private key must be given, either via the --encryption-key-file option or\n");
	fprintf(stderr, "                      the --encryption-key-env option.\n");
	fprintf(stderr, "                      Supported encryption algorithms are: aes128, aes256\n");
	fprintf(stderr, "      --encryption-key-file <path>\n");
	fprintf(stderr, "                      Grabs the encryption key from the given file, which must be in PEM format.\n");
	fprintf(stderr, "      --encryption-key-env <env_var_name>\n");
	fprintf(stderr, "                      Grabs the encryption key from the given environment variable, which must be base-64 encoded.\n");
	fprintf(stderr, "  -t, --parallel\n");
	fprintf(stderr, "                      The number of restore threads. Default: 20.\n");
	fprintf(stderr, "  -t, --threads\n");
	fprintf(stderr, "                      The number of restore threads. DEPRECATED: use 'parallel' now. Default: 20.\n");
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
	fprintf(stderr, "  -l, --extra-ttl\n");
	fprintf(stderr, "                      For records with expirable void-times, add N seconds of extra-ttl to the\n");
	fprintf(stderr, "                      recorded void-time.\n");
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
	fprintf(stderr, "  -T TIMEOUT, --timeout=TIMEOUT\n");
	fprintf(stderr, "                      Set the timeout (ms) for commands. Default: 10000\n");
	fprintf(stderr, "      --socket-timeout <ms>\n");
	fprintf(stderr, "                      Socket timeout for write transactions in milliseconds.\n");
	fprintf(stderr, "                      Default is 10 seconds.\n");
	fprintf(stderr, "                      If this value is 0, its set to total-timeout. If both are 0,\n");
	fprintf(stderr, "                      there is no socket idle time limit.\n");
	fprintf(stderr, "      --total-timeout <ms>\n");
	fprintf(stderr, "                      Total socket timeout for write transactions in milliseconds.\n");
	fprintf(stderr, "                      If this value is 0 and --timeout is set, then the --timeout\n");
	fprintf(stderr, "                      value is used as the write transaction timeout.\n");
	fprintf(stderr, "                      Default is 0, i.e. no timeout.\n");
	fprintf(stderr, "      --max-retries <n>\n");
	fprintf(stderr, "                      Maximum number of retries before aborting the current write transaction.\n");
	fprintf(stderr, "                      The default is 0.\n");
	fprintf(stderr, "      --retry-delay <ms>\n");
	fprintf(stderr, "                      The amount of time to sleep between retries of write transactions.\n");
	fprintf(stderr, "                      Default is 0.\n");
	fprintf(stderr, "      --s3-region <region>\n");
	fprintf(stderr, "                      The S3 region that the bucket(s) exist in.\n");
	fprintf(stderr, "      --s3-profile <profile_name>\n");
	fprintf(stderr, "                      The S3 profile to use for credentials (the default is \"default\").\n");
	fprintf(stderr, "      --s3-endpoint-override <url>\n");
	fprintf(stderr, "                      An alternate url endpoint to send S3 API calls to.\n");
	fprintf(stderr, "      --s3-max-async-downloads <n>\n");
	fprintf(stderr, "                      The maximum number of simultaneous download requests from S3.\n\n");

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

