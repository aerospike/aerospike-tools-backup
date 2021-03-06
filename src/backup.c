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

#include <aerospike/as_exp.h>

#include <backup.h>
#include <enc_text.h>
#include <utils.h>
#include <conf.h>


//==========================================================
// Typedefs & constants.
//

#define MAX_PARTITIONS 4096

#define OPTIONS_SHORT "h:Sp:A:U:P::n:s:d:o:F:r:vxCB:X:D:M:m:eN:RIuVZa:b:L:q:z:y:"


// The C client's version string
extern char *aerospike_client_version;

static pthread_mutex_t g_stop_lock;
static pthread_cond_t g_stop_cond;
// Makes background threads exit.
static volatile bool g_stop = false;

// Indicates that the one-time work (secondary indexes and UDF files) is complete.
static volatile bool one_shot_done = false;
// Signals completion of the one-time work (secondary indexes and UDF files) to
// other threads.
static pthread_cond_t one_shot_cond = PTHREAD_COND_INITIALIZER;
// Used by the counter thread to signal newly available bandwidth to the backup
// threads.
static pthread_cond_t bandwidth_cond = PTHREAD_COND_INITIALIZER;


//==========================================================
// Forward Declarations.
//

static void wait_one_shot(void);
static void signal_one_shot(void);
static bool has_stopped(void);
static void
stop(void);
static void stop_nolock(void);
static void sleep_for(uint64_t n_secs);
static void disk_space_check(const char *dir, uint64_t disk_space);
static bool close_file(io_write_proxy_t *fd, void **fd_buf);
static bool open_file(uint64_t *bytes, const char *file_path, const char *ns,
		uint64_t disk_space, io_write_proxy_t *fd, void **fd_buf,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey);
static bool close_dir_file(per_node_context *pnc);
static bool open_dir_file(per_node_context *pnc);
static bool scan_callback(const as_val *val, void *cont);
static bool process_secondary_indexes(per_node_context *pnc);
static bool process_udfs(per_node_context *pnc);
static void * backup_thread_func(void *cont);
static void * counter_thread_func(void *cont);
static bool clean_output_file(const char *file_path, bool clear);
static bool clean_directory(const char *dir_path, bool clear);
static bool parse_partition_range(char *str, as_partition_filter *range);
static bool parse_digest(const char *str, as_digest *digest);
static bool parse_after_digest(char *str, as_partition_filter* filter);
static bool parse_sets(as_vector* set_list, as_scan* scan, as_policy_scan* policy);
static bool init_scan_bins(char *bin_list, as_scan *scan);
static bool check_for_ldt_callback(void *context_, const char *key, const char *value);
static bool check_for_ldt(aerospike *as, const char *namespace,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, bool *has_ldt);
static bool ns_count_callback(void *context_, const char *key, const char *value);
static bool set_count_callback(void *context_, const char *key_, const char *value_);
static bool get_object_count(aerospike *as, const char *namespace, as_vector* set_list,
		char (*node_names)[][AS_NODE_NAME_SIZE], uint32_t n_node_names, uint64_t *obj_count);
static void show_estimate(FILE *mach_fd, uint64_t *samples, uint32_t n_samples,
		uint64_t rec_count_estimate);
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

		// asbackup section in config file
		{ "compact", no_argument, NULL, 'C' },
		{ "compress", required_argument, NULL, 'z' },
		{ "encrypt", required_argument, NULL, 'y' },
		{ "encryption-key-file", required_argument, NULL, '1' },
		{ "encryption-key-env", required_argument, NULL, '2' },
		{ "parallel", required_argument, NULL, 'w' },
		{ "no-bins", no_argument, NULL, 'x' },
		{ "bin-list", required_argument, NULL, 'B' },
		{ "no-records", no_argument, NULL, 'R' },
		{ "no-indexes", no_argument, NULL, 'I' },
		{ "no-udfs", no_argument, NULL, 'u' },
		{ "services-alternate", no_argument, NULL, 'S' },
		{ "namespace", required_argument, NULL, 'n' },
		{ "set", required_argument, NULL, 's' },
		{ "directory", required_argument, NULL, 'd' },
		{ "output-file", required_argument, NULL, 'o' },
		{ "output-file-prefix", required_argument, NULL, 'q' },
		{ "file-limit", required_argument, NULL, 'F' },
		{ "remove-files", no_argument, NULL, 'r' },
		{ "partition-filter", required_argument, NULL, 'X' },
		{ "after-digest", required_argument, NULL, 'D' },
		{ "modified-after", required_argument, NULL, 'a' },
		{ "modified-before", required_argument, NULL, 'b' },
		{ "no-ttl-only", no_argument, NULL, COMMAND_OPT_NO_TTL_ONLY },
		{ "records-per-second", required_argument, NULL, 'L' },
		{ "max-records", required_argument, NULL, 'M' },
		{ "machine", required_argument, NULL, 'm' },
		{ "estimate", no_argument, NULL, 'e' },
		{ "nice", required_argument, NULL, 'N' },
		{ NULL, 0, NULL, 0 }
	};

	int32_t res = EXIT_FAILURE;

	enable_client_log();

	backup_config conf;
	backup_config_default(&conf);

	conf.encoder = &(backup_encoder){
		text_put_record, text_put_udf_file, text_put_secondary_index
	};

	as_policy_scan policy;
	as_policy_scan_init(&policy);
	policy.base.socket_timeout = 10 * 60 * 1000;
	conf.policy = &policy;

	as_scan scan;
	as_scan_init(&scan, "", "");
	scan.deserialize_list_map = false;
	conf.scan = &scan;

	int32_t opt;
	uint64_t tmp;

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
	optind = 0;
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
			fprintf(stderr, "--no-config-file and only-config-file are mutually exclusive option. Please enable only one.\n");
			return false;
		}
	}

	// Reset optind (internal variable) to parse all options again
	optind = 0;
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
			as_strncpy(scan.ns, optarg, AS_NAMESPACE_MAX_SIZE);
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

			policy.records_per_second = (uint32_t)tmp;
			break;

		case 'v':
			as_log_set_level(AS_LOG_LEVEL_TRACE);
			verbose = true;
			break;

		case 'x':
			scan.no_bins = true;
			break;

		case 'C':
			conf.compact = true;
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

		case 'B':
			conf.bin_list = safe_strdup(optarg);
			break;

		case 'X':
			conf.partition_list = safe_strdup(optarg);
			break;

		case 'D':
			conf.after_digest = safe_strdup(optarg);
			break;

		case 'M':
			if (!better_atoi(optarg, &tmp)) {
				err("Invalid max-records value %s", optarg);
				goto cleanup1;
			}

			policy.max_records = tmp;
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

	if (conf.port < 0) {
		conf.port = DEFAULT_PORT;
	}

	if (conf.host == NULL) {
		conf.host = DEFAULT_HOST;
	}

	if (scan.ns[0] == 0) {
		err("Please specify a namespace (-n option)");
		goto cleanup1;
	}

	if (!parse_sets(&conf.set_list, &scan, &policy)) {
		goto cleanup1;
	}

	if ((conf.pkey != NULL) ^ (conf.encrypt_mode != IO_PROXY_ENCRYPT_NONE)) {
		err("Must specify both encryption mode and a private key "
				"file/environment variable\n");
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
		err("digest and partition-list arguments are mutually exclusive");
		goto cleanup1;
	}

	if (conf.partition_list != NULL) {
		if (verbose) {
			ver("Parsing partition-list '%s'", conf.partition_list);
		}

		if (!parse_partition_range(conf.partition_list, &conf.p_filter)) {
			err("Error while parsing partition-list '%s'", conf.partition_list);
			goto cleanup1;
		}
	}
	else if (conf.after_digest != NULL) {
		if (verbose) {
			ver("Parsing after-digest '%s'", conf.after_digest);
		}

		if (!parse_after_digest(conf.after_digest, &conf.p_filter)) {
			err("Error while parsing after-digest '%s'", conf.after_digest);
			goto cleanup1;
		}
	}
	else {
		// neither partition_list nor after_digest are set, filter out nothing
		as_partition_filter_set_range(&conf.p_filter, 0, 0);
	}

	signal(SIGINT, sig_hand);
	signal(SIGTERM, sig_hand);

	const char *before;
	const char *after;
	const char *ttl_zero_msg;
	char before_buff[100];
	char after_buff[100];

	uint16_t predexp_size = 0;

	if (conf.mod_before > 0)
	{
		predexp_size = (uint16_t)(predexp_size + 3);
	}

	if (conf.mod_after > 0)
	{
		predexp_size = (uint16_t)(predexp_size + 3);
	}

	if (conf.ttl_zero)
	{
		predexp_size = (uint16_t)(predexp_size + 3);
	}

	predexp_size = (uint16_t)(predexp_size + ((predexp_size / 3) - 1));

	if (predexp_size > 0)
	{
		as_scan_predexp_inita(&scan, predexp_size);
	}

	if (conf.mod_before > 0) {
		as_scan_predexp_add(&scan, as_predexp_rec_last_update());
		as_scan_predexp_add(&scan, as_predexp_integer_value(conf.mod_before));
		as_scan_predexp_add(&scan, as_predexp_integer_less());

		if (!format_date_time(conf.mod_before, before_buff, sizeof before_buff)) {
			err("Error while formatting modified-since time");
			goto cleanup1;
		}

		before = before_buff;
	} else {
		before = "[none]";
	}

	if (conf.mod_after > 0) {
		as_scan_predexp_add(&scan, as_predexp_rec_last_update());
		as_scan_predexp_add(&scan, as_predexp_integer_value(conf.mod_after));
		as_scan_predexp_add(&scan, as_predexp_integer_greatereq());

		if (!format_date_time(conf.mod_after, after_buff, sizeof after_buff)) {
			err("Error while formatting modified-since time");
			goto cleanup1;
		}

		after = after_buff;
	} else {
		after = "[none]";
	}

	if (conf.mod_before > 0 && conf.mod_after > 0) {
		as_scan_predexp_add(&scan, as_predexp_and(2));
	}

	if (conf.ttl_zero) {
		as_scan_predexp_add(&scan, as_predexp_rec_void_time());
		as_scan_predexp_add(&scan, as_predexp_integer_value(0));
		as_scan_predexp_add(&scan, as_predexp_integer_equal());

		ttl_zero_msg = "true";
	} else {
		ttl_zero_msg = "false";
	}

	if (conf.ttl_zero && predexp_size > 3) {
		as_scan_predexp_add(&scan, as_predexp_and(2));
	}

	inf("Starting backup of %s (namespace: %s, set: [%s], bins: %s, after: %s, before: %s, no ttl only: %s, limit: %" PRId64 ") to %s",
			conf.host, scan.ns, conf.set_list.size == 0 ? "all" : str_vector_tostring(&conf.set_list),
			conf.bin_list == NULL ? "[all]" : conf.bin_list, after, before, ttl_zero_msg, policy.max_records,
			conf.output_file != NULL ?
					strcmp(conf.output_file, "-") == 0 ? "[stdout]" : conf.output_file :
					conf.directory != NULL ?
							conf.directory : "[none]");

	if (conf.bin_list != NULL && !init_scan_bins(conf.bin_list, &scan)) {
		err("Error while setting scan bin list");
		goto cleanup1;
	}

	FILE *mach_fd = NULL;

	if (conf.machine != NULL && (mach_fd = fopen(conf.machine, "a")) == NULL) {
		err_code("Error while opening machine-readable file %s", conf.machine);
		goto cleanup1;
	}

	as_config as_conf;
	as_config_init(&as_conf);
	as_conf.conn_timeout_ms = TIMEOUT;
	as_conf.use_services_alternate = conf.use_services_alternate;

	if (! as_config_add_hosts(&as_conf, conf.host, (uint16_t)conf.port)) {
		err("Invalid conf.host(s) string %s", conf.host);
		goto cleanup3;
	}

	if (conf.auth_mode && ! as_auth_mode_from_string(&as_conf.auth_mode, conf.auth_mode)) {
		err("Invalid authentication mode %s. Allowed values are INTERNAL / EXTERNAL / EXTERNAL_INSECURE\n",
				conf.auth_mode);
		goto cleanup3;
	}

	if (conf.user) {
		if (strcmp(conf.password, DEFAULTPASSWORD) == 0) {
			conf.password = getpass("Enter Password: ");
		}

		if (! as_config_set_user(&as_conf, conf.user, conf.password)) {
			printf("Invalid password for user name `%s`\n", conf.user);
			goto cleanup3;
		}
	}

	if (conf.tls.keyfile && conf.tls.keyfile_pw) {
		if (strcmp(conf.tls.keyfile_pw, DEFAULTPASSWORD) == 0) {
			conf.tls.keyfile_pw = getpass("Enter TLS-Keyfile Password: ");
		}

		if (!tls_read_password(conf.tls.keyfile_pw, &conf.tls.keyfile_pw)) {
			goto cleanup3;
		}
	}

	memcpy(&as_conf.tls, &conf.tls, sizeof(as_config_tls));
	memset(&conf.tls, 0, sizeof(conf.tls));

	// initialize the global lock + condition variable used for the stop condition
	if (pthread_mutex_init(&g_stop_lock, NULL) != 0) {
		err("Failed to initialize mutex\n");
		goto cleanup3;
	}
	if (pthread_cond_init(&g_stop_cond, NULL) != 0) {
		err("Failed to initialize condition variable\n");
		pthread_mutex_destroy(&g_stop_lock);
		goto cleanup3;
	}

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
		goto cleanup4;
	}

	node_spec *node_specs = NULL;
	uint32_t n_node_specs = 0;

	char (*node_names)[][AS_NODE_NAME_SIZE] = NULL;
	uint32_t n_node_names;
	get_node_names(as.cluster, node_specs, n_node_specs, &node_names, &n_node_names);

	inf("Processing %u node(s)", n_node_names);
	cf_atomic64_set(&conf.rec_count_total, 0);
	cf_atomic64_set(&conf.byte_count_total, 0);
	conf.byte_count_limit = conf.bandwidth;
	conf.index_count = 0;
	conf.udf_count = 0;
	uint64_t rec_count_estimate;

	if (!get_object_count(&as, scan.ns, &conf.set_list, node_names, n_node_names, &rec_count_estimate)) {
		err("Error while counting cluster objects");
		goto cleanup5;
	}

	conf.rec_count_estimate = rec_count_estimate;

	inf("Namespace contains %" PRIu64 " record(s)", conf.rec_count_estimate);

	bool has_ldt;

	if (!check_for_ldt(&as, scan.ns, node_names, n_node_names, &has_ldt)) {
		err("Error while checking for LDT");
		goto cleanup5;
	}

	if (has_ldt) {
		err("The cluster has LDT enabled for namespace %s; please use an older version of "
				"this tool to create a backup", scan.ns);
		goto cleanup5;
	}

	if (conf.estimate && conf.rec_count_estimate > NUM_SAMPLES) {
		conf.rec_count_estimate = NUM_SAMPLES;
	}

	if (conf.directory != NULL && !clean_directory(conf.directory, conf.remove_files)) {
		goto cleanup5;
	}

	if (conf.output_file != NULL && !clean_output_file(conf.output_file, conf.remove_files)) {
		goto cleanup5;
	}

	pthread_t counter_thread;
	counter_thread_args counter_args;
	counter_args.conf = &conf;
	counter_args.mach_fd = mach_fd;

	if (verbose) {
		ver("Creating counter thread");
	}

	if (pthread_create(&counter_thread, NULL, counter_thread_func, &counter_args) != 0) {
		err_code("Error while creating counter thread");
		goto cleanup5;
	}

	pthread_t backup_threads[1];
	uint32_t n_threads = 1;
	static uint64_t samples[NUM_SAMPLES];
	static uint32_t n_samples = 0;
	backup_thread_args backup_args;
	backup_args.conf = &conf;
	backup_args.shared_fd = NULL;
	backup_args.bytes = 0;
	backup_args.samples = samples;
	backup_args.n_samples = &n_samples;
	cf_queue *job_queue = cf_queue_create(sizeof (backup_thread_args), true);

	if (job_queue == NULL) {
		err_code("Error while allocating job queue");
		goto cleanup6;
	}

	void *fd_buf = NULL;

	// backing up to a single backup file: open the file now and store the file descriptor in
	// backup_args.shared_fd; it'll be shared by all backup threads
	if (conf.output_file != NULL) {
		backup_args.shared_fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
		if (!open_file(&backup_args.bytes, conf.output_file, conf.scan->ns, 0,
					backup_args.shared_fd, &fd_buf, conf.compress_mode,
					conf.encrypt_mode, conf.pkey)) {
			err("Error while opening shared backup file");
			goto cleanup7;
		}
	}

	bool first = true;

	// Create a single backup task
	memcpy(&backup_args.filter, &conf.p_filter, sizeof(as_partition_filter));
	backup_args.first = first;
	first = false;
	if (cf_queue_push(job_queue, &backup_args) != CF_QUEUE_OK) {
		err("Error while queueing backup job");
		goto cleanup8;
	}

	uint32_t n_threads_ok = 0;

	if (verbose) {
		ver("Creating %u backup thread(s)", n_threads);
	}

	for (uint32_t i = 0; i < n_threads; ++i) {
		if (pthread_create(&backup_threads[i], NULL, backup_thread_func, job_queue) != 0) {
			err_code("Error while creating backup thread");
			goto cleanup9;
		}

		++n_threads_ok;
	}

	res = EXIT_SUCCESS;

cleanup9:
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
				ver("Backup thread failed");
			}

			res = EXIT_FAILURE;
		}
	}

cleanup8:
	if (conf.output_file != NULL && !close_file(backup_args.shared_fd, &fd_buf)) {
		err("Error while closing shared backup file");
		res = EXIT_FAILURE;
	}
	cf_free(backup_args.shared_fd);

cleanup7:
	cf_queue_destroy(job_queue);

cleanup6:
	stop();

	if (verbose) {
		ver("Waiting for counter thread");
	}

	if (safe_join(counter_thread, NULL) != 0) {
		err_code("Error while joining counter thread");
		res = EXIT_FAILURE;
	}

	if (conf.estimate) {
		show_estimate(mach_fd, samples, n_samples, rec_count_estimate);
	}

cleanup5:
	aerospike_close(&as, &ae);

cleanup4:
	aerospike_destroy(&as);

	pthread_mutex_destroy(&g_stop_lock);
	pthread_cond_destroy(&g_stop_cond);

cleanup3:
	if (mach_fd != NULL) {
		fclose(mach_fd);
	}

cleanup1:
	backup_config_destroy(&conf);

	as_scan_destroy(&scan);

	if (verbose) {
		ver("Exiting with status code %d", res);
	}

	return res;
}

void
backup_config_default(backup_config *conf)
{
	conf->host = NULL;
	conf->port = -1;
	conf->use_services_alternate = false;
	conf->user = NULL;
	conf->password = DEFAULTPASSWORD;
	conf->auth_mode = NULL;

	as_vector_init(&conf->set_list, sizeof(as_set), 8);
	conf->bin_list = NULL;
	conf->partition_list = NULL;
	conf->after_digest = NULL;
	conf->mod_after = 0;
	conf->mod_before = 0;
	conf->ttl_zero = false;

	conf->remove_files = false;
	conf->directory = NULL;
	conf->output_file = NULL;
	conf->prefix = NULL;
	conf->compact = false;
	conf->compress_mode = IO_PROXY_COMPRESS_NONE;
	conf->encrypt_mode = IO_PROXY_ENCRYPT_NONE;
	conf->pkey = NULL;
	conf->machine = NULL;
	conf->estimate = false;
	conf->bandwidth = 0;
	conf->no_records = false;
	conf->no_indexes = false;
	conf->no_udfs = false;
	conf->file_limit = DEFAULT_FILE_LIMIT * 1024 * 1024;

	conf->rec_count_estimate = 0;
	conf->rec_count_total = 0;
	conf->byte_count_total = 0;
	conf->byte_count_limit = 0;
	conf->index_count = 0;
	conf->udf_count = 0;

	memset(&conf->tls, 0, sizeof(as_config_tls));
	conf->as = NULL;
	conf->policy = NULL;
	conf->scan = NULL;
	conf->encoder = NULL;
}

void
backup_config_destroy(backup_config *conf)
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

	as_vector_destroy(&conf->set_list);

	if (conf->bin_list != NULL) {
		cf_free(conf->bin_list);
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
 * Waits until the one-time work (secondary indexes and UDF files) is complete.
 */
static void
wait_one_shot(void)
{
	safe_lock();

	while (!one_shot_done) {
		safe_wait(&one_shot_cond);
	}

	safe_unlock();
}

/*
 * Signals that the one-time work (secondary indexes and UDF files) is complete.
 */
static void
signal_one_shot(void)
{
	safe_lock();
	one_shot_done = true;
	safe_signal(&one_shot_cond);
	safe_unlock();
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
 * Closes a backup file and frees the associated I/O buffer.
 *
 * @param fd      The file descriptor of the backup file to be closed.
 * @param fd_buf  The I/O buffer that was allocated for the file descriptor.
 */
static bool
close_file(io_write_proxy_t *fd, void **fd_buf)
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

		int32_t fno = fileno(_f);

		if (fno < 0) {
			err_code("Error while retrieving native file descriptor");
			return false;
		}

		if (fsync(fno) < 0) {
			err_code("Error while flushing kernel buffers");
			return false;
		}

		if (fclose(_f) == EOF) {
			err_code("Error while closing backup file");
			return false;
		}
	}

	cf_free(*fd_buf);
	*fd_buf = NULL;
	return true;
}

/*
 * Initializes a backup file.
 *
 *   - Creates the backup file.
 *   - Allocates an I/O buffer for it.
 *   - Writes the version header and meta data (e.g., the namespace) to the backup file.
 *
 * @param bytes       The number of bytes written to the new backup file (version header, meta
 *                    data).
 * @param file_path   The path of the backup file to be created.
 * @param ns          The namespace that is being backed up.
 * @param disk_space  An estimate of the required disk space for the backup file.
 * @param fd          The file descriptor of the created backup file.
 * @param fd_buf      The I/O buffer allocated for the file descriptor.
 * @param c_opt       The compression mode to be used on the file.
 * @param e_opt       The encryption mode to be used on the file.
 *
 * @result            `true`, if successful.
 */
static bool
open_file(uint64_t *bytes, const char *file_path, const char *ns,
		uint64_t disk_space, io_write_proxy_t *fd, void **fd_buf,
		compression_opt c_opt, encryption_opt e_opt, encryption_key_t* pkey)
{
	FILE* _f;

	if (verbose) {
		ver("Opening backup file %s", file_path);
	}

	if (strcmp(file_path, "-") == 0) {
		if (verbose) {
			ver("Backup file is stdout");
		}

		_f = stdout;
	} else {
		if (verbose) {
			ver("Creating backup file");
		}

		int32_t res = remove(file_path);

		if (res < 0) {
			if (errno != ENOENT) {
				err_code("Error while removing existing backup file %s", file_path);
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
		ver("Initializing backup file");
	}

	io_write_proxy_init(fd, _f);
	io_proxy_init_compression(fd, c_opt);
	io_proxy_init_encryption(fd, pkey, e_opt);

	*fd_buf = safe_malloc(IO_BUF_SIZE);
	setbuffer(fd->fd, *fd_buf, IO_BUF_SIZE);

	if (fprintf_bytes(bytes, fd, "Version " VERSION_3_1 "\n") < 0) {
		err_code("Error while writing header to backup file %s", file_path);
		close_file(fd, fd_buf);
		return false;
	}

	if (fprintf_bytes(bytes, fd, META_PREFIX META_NAMESPACE " %s\n", escape(ns)) < 0) {
		err_code("Error while writing meta data to backup file %s", file_path);
		close_file(fd, fd_buf);
		return false;
	}

	return true;
}

/*
 * Wrapper around close_file(). Used when backing up to a directory.
 *
 * @param pnc  The per-node context of the backup thread that's closing the backup file.
 *
 * @result     `true`, if successful.
 */
static bool
close_dir_file(per_node_context *pnc)
{
	if (!close_file(pnc->fd, &pnc->fd_buf)) {
		return false;
	}

	if (verbose) {
		ver("File size is %" PRIu64, pnc->byte_count_file);
	}

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
 * @param pnc  The per-node context of the backup thread that's creating the backup file.
 *
 * @result     `true`, if successful.
 */
static bool
open_dir_file(per_node_context *pnc)
{
	char file_path[PATH_MAX];

	if ((size_t)snprintf(file_path, sizeof file_path, "%s/%s_%05d.asb", pnc->conf->directory, 
			pnc->conf->prefix == NULL ? pnc->conf->scan->ns : pnc->conf->prefix, pnc->file_count) >= sizeof file_path) {
		err("Backup file path too long");
		return false;
	}

	uint64_t rec_count_estimate = pnc->conf->rec_count_estimate;
	uint64_t rec_count_total = cf_atomic64_get(pnc->conf->rec_count_total);
	uint64_t byte_count_total = cf_atomic64_get(pnc->conf->byte_count_total);
	uint64_t rec_remain = rec_count_total > rec_count_estimate ? 0 :
			rec_count_estimate - rec_count_total;
	uint64_t rec_size = rec_count_total == 0 ? 0 : byte_count_total / rec_count_total;

	if (verbose) {
		ver("%" PRIu64 " remaining record(s), %" PRIu64 " B/rec average size", rec_remain,
				rec_size);
	}

	uint64_t bytes = 0;

	if (!open_file(&bytes, file_path, pnc->conf->scan->ns, rec_remain * rec_size,
			pnc->fd, &pnc->fd_buf, pnc->conf->compress_mode, pnc->conf->encrypt_mode,
			pnc->conf->pkey)) {
		return false;
	}

	pnc->rec_count_file = 0;
	++pnc->file_count;

	pnc->byte_count_file = bytes;
	pnc->byte_count_node += bytes;
	cf_atomic64_add(&pnc->conf->byte_count_total, (int64_t)bytes);
	return true;
}

/*
 * Callback function for the cluster node scan. Passed to `aerospike_scan_node()`.
 *
 * @param val   The record to be processed. `NULL` indicates scan completion.
 * @param cont  The user-specified context passed to `aerospike_scan_node()`.
 *
 * @result      `false` to abort the scan, `true` to keep going.
 */
static bool
scan_callback(const as_val *val, void *cont)
{
	if (val == NULL) {
		if (verbose) {
			ver("Received scan end marker");
		}

		return false;
	}

	if (has_stopped()) {
		if (verbose) {
			ver("Callback detected failure");
		}

		return false;
	}

	as_record *rec = as_record_fromval(val);

	if (rec == NULL) {
		err("Received value of unexpected type %d", (int32_t)as_val_type(val));
		return false;
	}

	if (rec->key.ns[0] == 0) {
		err("Received record without namespace, generation %d, %d bin(s)", rec->gen,
				rec->bins.size);
		return false;
	}

	per_node_context *pnc = cont;

	// backing up to a directory: switch backup files when reaching the file size limit
	if (pnc->conf->directory != NULL && pnc->byte_count_file >= pnc->conf->file_limit) {
		if (verbose) {
			ver("Crossed %" PRIu64 " bytes, switching backup file", pnc->conf->file_limit);
		}

		if (!close_dir_file(pnc)) {
			err("Error while closing old backup file");
			return false;
		}

		if (!open_dir_file(pnc)) {
			err("Error while opening new backup file");
			return false;
		}
	}

	// backing up to a single backup file: allow one thread at a time to write
	if (pnc->conf->output_file != NULL || pnc->conf->estimate) {
		safe_lock();
	}

	if (pnc->conf->estimate && *pnc->n_samples >= NUM_SAMPLES) {
		inf("Backed up enough samples for estimate");
		safe_unlock();
		return false;
	}

	uint64_t bytes = 0;
	bool ok = pnc->conf->encoder->put_record(&bytes, pnc->fd, pnc->conf->compact, rec);

	if (pnc->conf->estimate) {
		pnc->samples[*pnc->n_samples] = bytes;
		++(*pnc->n_samples);
	}

	if (pnc->conf->output_file != NULL || pnc->conf->estimate) {
		safe_unlock();
	}

	if (!ok) {
		err("Error while storing record in backup file");
		return false;
	}

	++pnc->rec_count_file;
	++pnc->rec_count_node;
	cf_atomic64_incr(&pnc->conf->rec_count_total);

	pnc->byte_count_file += bytes;
	pnc->byte_count_node += bytes;
	cf_atomic64_add(&pnc->conf->byte_count_total, (int64_t)bytes);

	if (pnc->conf->bandwidth > 0) {
		safe_lock();

		while (cf_atomic64_get(pnc->conf->byte_count_total) >= pnc->conf->byte_count_limit &&
				!has_stopped()) {
			safe_wait(&bandwidth_cond);
		}

		safe_unlock();
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
 * @param pnc  The per-node context of the backup thread that's backing up the indexes.
 *
 * @result     `true`, if successful.
 */
static bool
process_secondary_indexes(per_node_context *pnc)
{
	if (verbose) {
		ver("Processing secondary indexes");
	}

	bool res = false;

	size_t value_size = sizeof "sindex-list:ns=" - 1 + strlen(pnc->conf->scan->ns) + 1;
	char value[value_size];
	snprintf(value, value_size, "sindex-list:ns=%s", pnc->conf->scan->ns);

	as_policy_info policy;
	as_policy_info_init(&policy);
	policy.timeout = TIMEOUT;

	char *resp =  NULL;
	as_error ae;

	if (aerospike_info_any(pnc->conf->as, &ae, &policy, value, &resp) != AEROSPIKE_OK) {
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

		if (!parse_index_info(pnc->conf->scan->ns, index_str, &index)) {
			err("Error while parsing secondary index info string %s", clone);
			goto cleanup2;
		}

		if (verbose) {
			ver("Storing index %s", index.name);
		}

		uint32_t n_sets = pnc->conf->set_list.size;
		if (n_sets == 0 || (index.set != NULL &&
					str_vector_contains(&pnc->conf->set_list, index.set))) {

			// backing up to a single backup file: allow one thread at a time to write
			if (pnc->conf->output_file != NULL) {
				safe_lock();
			}

			uint64_t bytes = 0;
			bool ok = pnc->conf->encoder->put_secondary_index(&bytes, pnc->fd, &index);

			if (pnc->conf->output_file != NULL) {
				safe_unlock();
			}

			if (!ok) {
				err("Error while storing secondary index in backup file");
				goto cleanup3;
			}

			pnc->byte_count_file += bytes;
			pnc->byte_count_node += bytes;
			cf_atomic64_add(&pnc->conf->byte_count_total, (int64_t)bytes);
		}
		else {
			++skipped;
		}

		as_vector_destroy(&index.path_vec);
	}

	pnc->conf->index_count = info_vec.size;
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
 * @param pnc  The per-node context of the backup thread that's backing up the UDF files.
 *
 * @result     `true`, if successful.
 */
static bool
process_udfs(per_node_context *pnc)
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

	if (aerospike_udf_list(pnc->conf->as, &ae, &policy, &files) != AEROSPIKE_OK) {
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

		if (aerospike_udf_get(pnc->conf->as, &ae, &policy, files.entries[i].name,
				files.entries[i].type, &file) != AEROSPIKE_OK) {
			err("Error while fetching UDF file %s - code %d: %s at %s:%d", files.entries[i].name,
					ae.code, ae.message, ae.file, ae.line);
			goto cleanup2;
		}

		// backing up to a single backup file: allow one thread at a time to write
		if (pnc->conf->output_file != NULL) {
			safe_lock();
		}

		uint64_t bytes = 0;
		bool ok = pnc->conf->encoder->put_udf_file(&bytes, pnc->fd, &file);

		if (pnc->conf->output_file != NULL) {
			safe_unlock();
		}

		if (!ok) {
			err("Error while storing UDF file in backup file");
			goto cleanup2;
		}

		pnc->byte_count_file += bytes;
		pnc->byte_count_node += bytes;
		cf_atomic64_add(&pnc->conf->byte_count_total, (int64_t)bytes);

		as_udf_file_destroy(&file);
		as_udf_file_init(&file);
	}

	pnc->conf->udf_count = files.size;
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
 *   - Initializes a per_node_context for that cluster node.
 *   - If backing up to a single file: uses the provided shared file descriptor,
 *       backup_thread_args.shared_fd.
 *   - If backing up to a directory: creates a new backup file by invoking
 *       open_dir_file().
 *   - If handling the first job from the queue: stores secondary index
 *       information and UDF file by invoking process_secondary_indexes() and
 *       process_udfs().
 *   - Initiates a node or partition scan with scan_callback() as the callback
 *       and the initialized per_node_context as user-specified context.
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

		backup_thread_args args;
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
			break;
		}

		per_node_context pnc;
		pnc.conf = args.conf;
		pnc.shared_fd = args.shared_fd;
		pnc.fd = NULL;
		pnc.fd_buf = NULL;
		pnc.rec_count_file = pnc.byte_count_file = 0;
		pnc.file_count = 0;
		pnc.rec_count_node = pnc.byte_count_node = 0;
		pnc.samples = args.samples;
		pnc.n_samples = args.n_samples;

		if (args.filter.digest.init) {
			uint32_t id = as_partition_getid(args.filter.digest.value, pnc.conf->as->cluster->n_partitions);
			uint32_t len = cf_b64_encoded_len(sizeof(args.filter.digest.value));
			char* str = cf_malloc(len + 1);
	
			cf_b64_encode(args.filter.digest.value, sizeof(args.filter.digest.value), str);
			str[len] = 0;
			sprintf(pnc.desc, "partition %u after %s", id, str);
			cf_free(str);
		}
		else if (args.filter.count > 0) {
			sprintf(pnc.desc, "partition range %u:%u", args.filter.begin, args.filter.count);
		}
		else {
			sprintf(pnc.desc, "whole namespace");
		}

		inf("Starting backup for %s", pnc.desc);

		// backing up to a single backup file: use the provided shared file descriptor for
		// the current job
		if (pnc.conf->output_file != NULL) {
			if (verbose) {
				ver("Using shared file descriptor");
			}

			pnc.fd = pnc.shared_fd;
		}
		// backing up to a directory: create the first backup file for the current job
		else if (pnc.conf->directory != NULL) {
			pnc.fd = (io_write_proxy_t*) cf_malloc(sizeof(io_write_proxy_t));
			if (!open_dir_file(&pnc)) {
				err("Error while opening first backup file");
				break;
			}
		}

		// if we got the first job in the queue, take care of secondary indexes and UDF files
		if (args.first) {
			if (verbose) {
				ver("Picked up first job, doing one shot work");
			}

			if (fprintf_bytes(&args.bytes, pnc.fd, META_PREFIX META_FIRST_FILE "\n") < 0) {
				err_code("Error while writing meta data to backup file");
				stop();
				goto close_file;
			}

			pnc.byte_count_file = pnc.byte_count_node += args.bytes;
			cf_atomic64_add(&pnc.conf->byte_count_total, (int64_t)args.bytes);

			if (pnc.conf->no_indexes) {
				if (verbose) {
					ver("Skipping index backup");
				}
			} else if (!process_secondary_indexes(&pnc)) {
				err("Error while processing secondary indexes");
				stop();
				goto close_file;
			}

			if (pnc.conf->no_udfs) {
				if (verbose) {
					ver("Skipping UDF backup");
				}
			} else if (!process_udfs(&pnc)) {
				err("Error while processing UDFs");
				stop();
				goto close_file;
			}

			if (verbose) {
				ver("Signaling one shot work completion");
			}

			signal_one_shot();
		// all other jobs wait until the first job is done with the secondary indexes and UDF files
		} else {
			if (verbose) {
				ver("Ensuring one shot work completion");
			}

			wait_one_shot();
		}

		as_error ae;
		as_status status;

		if (pnc.conf->no_records) {
			if (verbose) {
				ver("Skipping record backup");
			}
			status = AEROSPIKE_OK;
		}
		else if (args.filter.digest.init || args.filter.count > 0) {
			status = aerospike_scan_partitions(pnc.conf->as, &ae, pnc.conf->policy, pnc.conf->scan,
				&args.filter, scan_callback, &pnc);
		}
		else {
			status = aerospike_scan_foreach(pnc.conf->as, &ae, pnc.conf->policy, pnc.conf->scan,
				scan_callback, &pnc);
		}

		if (status != AEROSPIKE_OK) {
			if (ae.code == AEROSPIKE_OK) {
				inf("Abort scan for %s", pnc.desc);
			} else {
				err("Error while running scan for %s - code %d: %s at %s:%d", pnc.desc,
						ae.code, ae.message, ae.file, ae.line);
			}

			stop();
			goto close_file;
		}

		inf("Completed backup for %s, records: %" PRIu64 ", size: %" PRIu64 " "
				"(~%" PRIu64 " B/rec)", pnc.desc, pnc.rec_count_node,
				pnc.byte_count_node,
				pnc.rec_count_node == 0 ? 0 : pnc.byte_count_node / pnc.rec_count_node);

	close_file:
		// backing up to a single backup file: do nothing
		if (pnc.conf->output_file != NULL) {
			if (verbose) {
				ver("Not closing shared file descriptor");
			}

			pnc.fd = NULL;
		}
		// backing up to a directory: close the last backup file for the current job
		else if (pnc.conf->directory != NULL) {
			if (!close_dir_file(&pnc)) {
				err("Error while closing backup file");
				cf_free(pnc.fd);
				pnc.fd = NULL;
				break;
			}
			cf_free(pnc.fd);
			pnc.fd = NULL;
		}
	}

	if (res != (void *)EXIT_SUCCESS) {
		if (verbose) {
			ver("Indicating failure to other threads");
		}

		stop();
	}

	// in case we got the first job and failed before we were done with the secondary indexes
	// and UDF files
	signal_one_shot();

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
	backup_config *conf = args->conf;
	uint32_t iter = 0;
	cf_clock prev_ms = cf_getms();
	uint64_t prev_bytes = cf_atomic64_get(conf->byte_count_total);
	uint64_t prev_recs = cf_atomic64_get(conf->rec_count_total);

	while (true) {
		sleep_for(1);

		cf_clock now_ms = cf_getms();
		uint32_t ms = (uint32_t)(now_ms - prev_ms);
		prev_ms = now_ms;

		if (conf->rec_count_estimate > 0) {
			uint64_t now_bytes = cf_atomic64_get(conf->byte_count_total);
			uint64_t now_recs = cf_atomic64_get(conf->rec_count_total);

			int32_t percent = (int32_t)(now_recs * 100 / conf->rec_count_estimate);
			uint64_t bytes = now_bytes - prev_bytes;
			uint64_t recs = now_recs - prev_recs;

			int32_t eta = recs == 0 ? -1 :
					(int32_t)(((uint64_t)conf->rec_count_estimate - now_recs) * ms / recs / 1000);
			char eta_buff[ETA_BUF_SIZE];
			format_eta(eta, eta_buff, sizeof eta_buff);

			prev_bytes = now_bytes;
			prev_recs = now_recs;

			// rec_count_estimate may be a little off, make sure that we only print up to 99%
			if (percent < 100) {
				if (iter++ % 10 == 0) {
					inf("%d%% complete (~%" PRIu64 " KiB/s, ~%" PRIu64 " rec/s, ~%" PRIu64 " B/rec)",
							percent, ms == 0 ? 0 : bytes * 1000 / 1024 / ms,
							ms == 0 ? 0 : recs * 1000 / ms, recs == 0 ? 0 : bytes / recs);

					if (eta >= 0) {
						inf("~%s remaining", eta_buff);
					}
				}

				if (args->mach_fd != NULL) {
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

		safe_lock();

		if (conf->bandwidth > 0) {
			if (ms > 0) {
				conf->byte_count_limit += conf->bandwidth * 1000 / ms;
			}

			safe_signal(&bandwidth_cond);
		}

		bool tmp_stop = has_stopped();
		safe_unlock();

		if (tmp_stop) {
			break;
		}
	}

	uint64_t records = cf_atomic64_get(conf->rec_count_total);
	uint64_t bytes = cf_atomic64_get(conf->byte_count_total);
	inf("Backed up %" PRIu64 " record(s), %u secondary index(es), %u UDF file(s), "
			"%" PRIu64 " byte(s) in total (~%" PRIu64 " B/rec)", records, conf->index_count,
			conf->udf_count, bytes, records == 0 ? 0 : bytes / records);

	if (args->mach_fd != NULL && (fprintf(args->mach_fd,
			"SUMMARY:%" PRIu64 ":%u:%u:%" PRIu64 ":%" PRIu64 "\n", records, conf->index_count,
			conf->udf_count, bytes, records == 0 ? 0 : bytes / records) < 0 ||
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
 *
 * @result           `true`, if successful.
 */
static bool
clean_output_file(const char *file_path, bool clear)
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
 *   - If the directory already contains backup files, removes them or reports
 *       an error.
 *
 * @param dir_path  The path of the directory.
 * @param clear     What to do, if the directory already contains backup files.
 *                  'true' to remove them, `false` to report back an error.
 *
 * @result          'true', if successful.
 */
static bool
clean_directory(const char *dir_path, bool clear)
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

		dir = opendir(dir_path);

		if (dir == NULL) {
			err_code("Error while opening directory %s", dir_path);
			return false;
		}
	}

	struct dirent *entry;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name + strlen(entry->d_name) - 4, ".asb") == 0) {
			if (!clear) {
				err("Directory %s seems to contain an existing backup; "
						"use -r to clear directory", dir_path);
				closedir(dir);
				return false;
			}

			char file_path[PATH_MAX];

			if ((size_t)snprintf(file_path, sizeof file_path, "%s/%s", dir_path,
					entry->d_name) >= sizeof file_path) {
				err("File path too long (%s, %s)", dir_path, entry->d_name);
				closedir(dir);
				return false;
			}

			if (remove(file_path) < 0) {
				err_code("Error while removing existing backup file %s", file_path);
				closedir(dir);
				return false;
			}
		}
	}

	if (closedir(dir) < 0) {
		err_code("Error while closing directory handle for %s", dir_path);
		return false;
	}

	inf("Directory %s prepared for backup", dir_path);
	return true;
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
parse_digest(const char *str, as_digest *digest)
{
	uint32_t len = (uint32_t)strlen(str);
	uint8_t* bytes = (uint8_t*)alloca(cf_b64_decoded_buf_size(len));
	uint32_t size;
	
	if (! cf_b64_validate_and_decode(str, len, bytes, &size)) {
		return false;
	}

	if (size != sizeof(digest->value)) {
		return false;
	}

	memcpy(digest->value, bytes, size);
    digest->init = true;
    return true;
}

/*
 * Parse digest string filter in base64 format.
 * Append results to digest and partition ranges.
 *
 * Example: EjRWeJq83vEjRRI0VniavN7xI0U=
 */
static bool
parse_after_digest(char *str, as_partition_filter* filter)
{
	as_digest digest;

	if (! parse_digest(str, &digest)) {
		return false;
	}

	as_partition_filter_set_after(filter, &digest);
	return true;
}

/*
 * Parses a list of set names to either a single-set scan or a multi-set
 * expression filter.
 */
static bool
parse_sets(as_vector* set_list, as_scan* scan, as_policy_scan* policy)
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
		strcpy(scan->set, (char*) as_vector_get(set_list, 0));
	}
	else {
		// build a filter expression on the set names
		as_vector entries;
		as_vector_init(&entries, sizeof(as_exp_entry), 8);

		as_exp_entry* or_decl = (as_exp_entry*) as_vector_reserve(&entries);
		*or_decl = (as_exp_entry) { .op = _AS_EXP_CODE_OR };

		for (i = 0; i < set_list->size; i++) {
			char* set_name = (char*) as_vector_get(set_list, (uint32_t) i);
			as_exp_entry eq_entry[] = { as_exp_cmp_eq(as_exp_set_name() ,
					as_exp_str(set_name)) };
			for (uint64_t j = 0; j < (sizeof(eq_entry) / sizeof(as_exp_entry));
					j++) {
				as_vector_append(&entries, &eq_entry[j]);
			}
		}

		as_exp_entry* end_decl = (as_exp_entry*) as_vector_reserve(&entries);
		*end_decl = (as_exp_entry) { .op = _AS_EXP_CODE_END_OF_VA_ARGS };

		policy->base.filter_exp = as_exp_compile((as_exp_entry*) entries.list,
				entries.size);

		as_vector_destroy(&entries);
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
 */
static void
show_estimate(FILE *mach_fd, uint64_t *samples, uint32_t n_samples, uint64_t rec_count_estimate)
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
		upper = (uint64_t)ceil(exp_value + 4.7 * stand_dev / sqrt(n_samples));
	}

	inf("Estimated overall record size is %" PRIu64 " byte(s)", upper);

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
	fprintf(stdout, "Copyright 2015-2020 Aerospike. All rights reserved.\n");
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


	fprintf(stderr, "[asbackup]\n");
	fprintf(stderr, "  -n, --namespace <namespace>\n");
	fprintf(stderr, "                      The namespace to be backed up. Required.\n");
	fprintf(stderr, "  -s, --set <set>[,<set2>[,...]]\n");
	fprintf(stderr, "                      The set(s) to be backed up. Default: all sets.\n");
	fprintf(stderr, "  -d, --directory <directory>\n");
	fprintf(stderr, "                      The directory that holds the backup files. Required, \n");
	fprintf(stderr, "                      unless -o or -e is used.\n");
	fprintf(stderr, "  -o, --output-file <file>\n");
	fprintf(stderr, "                      Backup to a single backup file. Use - for stdout.\n");
	fprintf(stderr, "                      Required, unless -d or -e is used.\n");
	fprintf(stderr, "  -q, --output-file-prefix <prefix>\n");
	fprintf(stderr, "                      When using directory parameter, prepend a prefix to the names of the generated files.\n");
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
	fprintf(stderr, "  -w, --parallel <# nodes>\n");
	fprintf(stderr, "                      Maximal number of nodes backed up in parallel. Default: 10.\n");
	fprintf(stderr, "  -X, --partition-filter <list>\n");
	fprintf(stderr, "                      Partition filter to back up. Partition filters can be an individual partition or a range.\n");
	fprintf(stderr, "                      This argument is mutually exclusive to after-digest.\n");
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
	fprintf(stderr, "                      This argument is mutually exclusive to partition-filter.\n");
	fprintf(stderr, "                      Format: base64 encoded string\n");
	fprintf(stderr, "                      Example: EjRWeJq83vEjRRI0VniavN7xI0U=\n");
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
	fprintf(stderr, "                      Only include records that have no ttl set (persistent records).\n\n");

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

