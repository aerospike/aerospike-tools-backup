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

#include <restore_config.h>

#include <getopt.h>

#include <conf.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#define OPTIONS_SHORT "-h:Sp:A:U:P::n:d:i:t:vm:B:s:urgN:RILFwVZT:y:z:"

// The C client's version string.
extern char *aerospike_client_version;


//==========================================================
// Forward Declarations.
//

static void print_version(void);
static void usage(const char *name);


//==========================================================
// Public API.
//

int
restore_config_init(int argc, char* argv[], restore_config_t* conf)
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
		{ "retry-scale-factor", required_argument, NULL, COMMAND_OPT_RETRY_SCALE_FACTOR },
		// support the `--sleep-between-retries` option until a major version bump.
		{ "sleep-between-retries", required_argument, NULL, COMMAND_OPT_RETRY_DELAY },
		// support the `--retry-delay` option until a major version bump.
		{ "retry-delay", required_argument, NULL, COMMAND_OPT_RETRY_DELAY },
		{ "disable-batch-writes", no_argument, NULL, COMMAND_OPT_DISABLE_BATCH_WRITES },
		{ "max-async-batches", required_argument, NULL, COMMAND_OPT_MAX_ASYNC_BATCHES },
		{ "batch-size", required_argument, NULL, COMMAND_OPT_BATCH_SIZE },
		{ "event-loops", required_argument, NULL, COMMAND_OPT_EVENT_LOOPS },

		{ "s3-region", required_argument, NULL, COMMAND_OPT_S3_REGION },
		{ "s3-profile", required_argument, NULL, COMMAND_OPT_S3_PROFILE },
		{ "s3-endpoint-override", required_argument, NULL, COMMAND_OPT_S3_ENDPOINT_OVERRIDE },
		{ "s3-max-async-downloads", required_argument, NULL, COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS },
		{ "s3-log-level", required_argument, NULL, COMMAND_OPT_S3_LOG_LEVEL },
		{ NULL, 0, NULL, 0 }
	};

	restore_config_default(conf);

	int32_t optcase;
	int64_t tmp;
	s3_log_level_t s3_log_level;

	// Don't print error messages for the first two argument parsers
	opterr = 0;

	// option string should start with '-' to avoid argv permutation
	// we need same argv sequence in third check to support space separated optional argument value
	while ((optcase = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {
		switch (optcase) {
			case 'V':
				print_version();
				return RESTORE_CONFIG_INIT_EXIT;

			case 'Z':
				usage(argv[0]);
				return RESTORE_CONFIG_INIT_EXIT;
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
			if (!config_from_file(&conf, instance, config_fname, 0, false)) {
				return RESTORE_CONFIG_INIT_FAILURE;
			}
		} else {
			if (!config_from_files(&conf, instance, config_fname, false)) {
				return RESTORE_CONFIG_INIT_FAILURE;
			}
		}
	} else {
		if (read_only_conf_file) {
			fprintf(stderr, "--no-config-file and --only-config-file are "
					"mutually exclusive option. Please enable only one.\n");
			return RESTORE_CONFIG_INIT_FAILURE;
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
			cf_free(conf->host);
			conf->host = safe_strdup(optarg);
			break;

		case 'p':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > 65535) {
				err("Invalid port value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}

			conf->port = (int32_t) tmp;
			break;

		case 'U':
			conf->user = safe_strdup(optarg);
			break;

		case 'P':
			cf_free(conf->password);
			if (optarg) {
				conf->password = safe_strdup(optarg);
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					conf->password = safe_strdup(argv[optind++]);
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf->password = safe_strdup(DEFAULTPASSWORD);
				}
			}
			break;

		case 'A':
			conf->auth_mode = safe_strdup(optarg);
			break;

		case 'n':
			conf->ns_list = safe_strdup(optarg);
			break;

		case 'd':
			conf->directory = safe_strdup(optarg);
			break;

		case 'i':
			conf->input_file = safe_strdup(optarg);
			break;

		case 'z':
			if (parse_compression_type(optarg, &conf->compress_mode) != 0) {
				err("Invalid compression type \"%s\"\n", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			break;

		case 'y':
			if (parse_encryption_type(optarg, &conf->encrypt_mode) != 0) {
				err("Invalid encryption type \"%s\"\n", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			break;

		case '1':
			// encryption key file
			if (conf->pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env\n");
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
			if (io_proxy_read_private_key_file(optarg, conf->pkey) != 0) {
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			break;

		case '2':
			// encryption key environment variable
			if (conf->pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env\n");
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->pkey = parse_encryption_key_env(optarg);
			if (conf->pkey == NULL) {
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			break;

		case '_':
			err("WARNING: '--threads' option is deprecated, use `--parallel` instead");
		case 't':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > MAX_THREADS) {
				err("Invalid threads value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}

			conf->parallel = (uint32_t) tmp;
			break;

		case 'v':
			if (as_load_bool(&g_verbose)) {
				enable_client_log();
			} else {
				as_store_bool(&g_verbose, true);
			}

			break;

		case 'm':
			conf->machine = optarg;
			break;

		case 'B':
			conf->bin_list = safe_strdup(optarg);
			break;

		case 's':
			conf->set_list = safe_strdup(optarg);
			break;

		case 'K':
			conf->ignore_rec_error = true;
			break;

		case 'u':
			conf->unique = true;
			break;

		case 'r':
			conf->replace = true;
			break;

		case 'g':
			conf->no_generation = true;
			break;

		case 'l':
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > INT32_MAX) {
				err("Invalid extra-ttl value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}

			conf->extra_ttl = (int32_t) tmp;
			break;

		case 'N':
			conf->nice_list = safe_strdup(optarg);
			break;

		case 'R':
			conf->no_records = true;
			break;

		case 'I':
			conf->no_indexes = true;
			break;

		case 'L':
			conf->indexes_last = true;
			break;

		case 'F':
			conf->no_udfs = true;
			break;

		case 'w':
			conf->wait = true;
			break;

		case 'S':
			conf->use_services_alternate = true;
			break;

		case TLS_OPT_ENABLE:
			conf->tls.enable = true;
			break;

		case TLS_OPT_NAME:
			conf->tls_name = safe_strdup(optarg);
			break;

		case TLS_OPT_CA_FILE:
			conf->tls.cafile = safe_strdup(optarg);
			break;

		case TLS_OPT_CA_PATH:
			conf->tls.capath = safe_strdup(optarg);
			break;

		case TLS_OPT_PROTOCOLS:
			conf->tls.protocols = safe_strdup(optarg);
			break;

		case TLS_OPT_CIPHER_SUITE:
			conf->tls.cipher_suite = safe_strdup(optarg);
			break;

		case TLS_OPT_CRL_CHECK:
			conf->tls.crl_check = true;
			break;

		case TLS_OPT_CRL_CHECK_ALL:
			conf->tls.crl_check_all = true;
			break;

		case TLS_OPT_CERT_BLACK_LIST:
			conf->tls.cert_blacklist = safe_strdup(optarg);
			break;

		case TLS_OPT_LOG_SESSION_INFO:
			conf->tls.log_session_info = true;
			break;

		case TLS_OPT_KEY_FILE:
			conf->tls.keyfile = safe_strdup(optarg);
			break;

		case TLS_OPT_KEY_FILE_PASSWORD:
			if (optarg) {
				conf->tls.keyfile_pw = safe_strdup(optarg);
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					conf->tls.keyfile_pw = safe_strdup(argv[optind++]);
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf->tls.keyfile_pw = safe_strdup(DEFAULTPASSWORD);
				}
			}
			break;

		case TLS_OPT_CERT_FILE:
			conf->tls.certfile = safe_strdup(optarg);
			break;

		case 'T':
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid timeout value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}

			conf->timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_SOCKET_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid socket timeout value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->socket_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_TOTAL_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid total timeout value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->total_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_MAX_RETRIES:
			if (!better_atoi(optarg, &tmp) || tmp < 0) {
				err("Invalid max retries value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->max_retries = (uint64_t) tmp;
			break;

		case COMMAND_OPT_RETRY_DELAY:
			inf("Warning: `--sleep-between-retries` is deprecated and has no "
					"effect, use `--retry-scale-factor` to configure the amount "
					"to back off when retrying transactions.");
			break;

		case COMMAND_OPT_RETRY_SCALE_FACTOR:
			if (!better_atoi(optarg, &tmp) || tmp < 0) {
				err("Invalid retry delay value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->retry_scale_factor = (uint64_t) tmp;
			break;

		case COMMAND_OPT_DISABLE_BATCH_WRITES:
			conf->disable_batch_writes = true;
			break;

		case COMMAND_OPT_MAX_ASYNC_BATCHES:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid max-async-batches value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->max_async_batches = (uint32_t) tmp;
			break;

		case COMMAND_OPT_BATCH_SIZE:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid batch-size value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->batch_size = (uint32_t) tmp;
			break;

		case COMMAND_OPT_EVENT_LOOPS:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT32_MAX) {
				err("Invalid event-loops value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->event_loops = (uint32_t) tmp;
			break;

		case COMMAND_OPT_S3_REGION:
			conf->s3_region = strdup(optarg);
			break;

		case COMMAND_OPT_S3_PROFILE:
			conf->s3_profile = strdup(optarg);
			break;

		case COMMAND_OPT_S3_ENDPOINT_OVERRIDE:
			conf->s3_endpoint_override = strdup(optarg);
			break;

		case COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS:
			if (!better_atoi(optarg, &tmp) || tmp <= 0 || tmp > UINT32_MAX) {
				err("Invalid S3 max async downloads value %s", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->s3_max_async_downloads = (uint32_t) tmp;
			break;

		case COMMAND_OPT_S3_LOG_LEVEL:
			if (!s3_parse_log_level(optarg, &s3_log_level)) {
				err("Invalid S3 log level \"%s\"", optarg);
				return RESTORE_CONFIG_INIT_FAILURE;
			}
			conf->s3_log_level = s3_log_level;
			break;

		case CONFIG_FILE_OPT_FILE:
		case CONFIG_FILE_OPT_INSTANCE:
		case CONFIG_FILE_OPT_NO_CONFIG_FILE:
		case CONFIG_FILE_OPT_ONLY_CONFIG_FILE:
			break;

		default:
			fprintf(stderr, "Run with --help for usage information and flag options\n");
			return RESTORE_CONFIG_INIT_FAILURE;
		}
	}

	if (optind < argc) {
		err("Unexpected trailing argument %s", argv[optind]);
		return RESTORE_CONFIG_INIT_FAILURE;
	}

	if (conf->directory != NULL && conf->input_file != NULL) {
		err("Invalid options: --directory and --input-file are mutually exclusive.");
		return RESTORE_CONFIG_INIT_FAILURE;
	}

	if (conf->directory == NULL && conf->input_file == NULL) {
		err("Please specify a directory (-d option) or an input file (-i option)");
		return RESTORE_CONFIG_INIT_FAILURE;
	}

	if (conf->unique && (conf->replace || conf->no_generation)) {
		err("Invalid options: --unique is mutually exclusive with --replace and --no-generation.");
		return RESTORE_CONFIG_INIT_FAILURE;
	}

	if ((conf->pkey != NULL) ^ (conf->encrypt_mode != IO_PROXY_ENCRYPT_NONE)) {
		err("Must specify both encryption mode and a private key "
				"file/environment variable\n");
		return RESTORE_CONFIG_INIT_FAILURE;
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
	s3_set_log_level(conf->s3_log_level);

	if (conf->nice_list != NULL) {
		as_vector nice_vec;
		as_vector_inita(&nice_vec, sizeof(void*), 2);

		if (!restore_config_parse_list("nice", 10, conf->nice_list, &nice_vec)) {
			err("Error while parsing nice list");
			as_vector_destroy(&nice_vec);
			return RESTORE_CONFIG_INIT_FAILURE;
		}

		if (nice_vec.size != 2) {
			err("Invalid nice option");
			as_vector_destroy(&nice_vec);
			return RESTORE_CONFIG_INIT_FAILURE;
		}

		char *item0 = as_vector_get_ptr(&nice_vec, 0);
		char *item1 = as_vector_get_ptr(&nice_vec ,1);

		if (!better_atoi(item0, &tmp) || tmp < 1 ||
					((uint64_t) tmp) > ULONG_MAX / (1024 * 1024)) {
			err("Invalid bandwidth value %s", item0);
			as_vector_destroy(&nice_vec);
			return RESTORE_CONFIG_INIT_FAILURE;
		}

		conf->bandwidth = ((uint64_t) tmp) * 1024 * 1024;

		if (!better_atoi(item1, &tmp) || tmp < 1 || tmp > UINT32_MAX) {
			err("Invalid TPS value %s", item1);
			as_vector_destroy(&nice_vec);
			return RESTORE_CONFIG_INIT_FAILURE;
		}

		conf->tps = (uint32_t) tmp;
	}

	return 0;
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
	conf->s3_log_level = S3_DEFAULT_LOG_LEVEL;

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
	conf->max_retries = 5;
	conf->retry_scale_factor = 150000;

	conf->socket_timeout = 10 * 1000;
	conf->total_timeout = 0;

	conf->disable_batch_writes = false;
	conf->max_async_batches = DEFAULT_MAX_ASYNC_BATCHES;
	conf->batch_size = BATCH_SIZE_UNDEFINED;
	conf->event_loops = DEFAULT_EVENT_LOOPS;

	memset(&conf->tls, 0, sizeof(as_config_tls));
	conf->tls_name = NULL;
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

bool
restore_config_parse_list(const char *which, size_t size, char *list, as_vector *vec)
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

bool
restore_config_from_cloud(const restore_config_t* conf)
{
	return conf->s3_region != NULL || conf->s3_endpoint_override != NULL;
}


//==========================================================
// Local helpers.
//

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
	fprintf(stderr, "                      The default is 5.\n");
	fprintf(stderr, "      --retry-scale-factor <us>\n");
	fprintf(stderr, "                      The scale factor to use in the exponential backoff retry\n");
	fprintf(stderr, "                      strategy, in microseconds.\n");
	fprintf(stderr, "                      Default is 150000 us (150 ms).\n");
	fprintf(stderr, "      --disable-batch-writes\n");
	fprintf(stderr, "                      Disables the use of batch writes when restoring records to the\n");
	fprintf(stderr, "                      Aerospike cluster. By default, the cluster is checked for batch\n");
	fprintf(stderr, "                      write support, so only set this flag if you explicitly don't want\n");
	fprintf(stderr, "                      batch writes to be used or asrestore is failing to recognize that\n");
	fprintf(stderr, "                      batch writes are disabled and is failing to work because of it.\n");
	fprintf(stderr, "      --max-async-batches <n>\n");
	fprintf(stderr, "                      The max number of outstanding async record batch write calls at a time.\n");
	fprintf(stderr, "                      For pre-6.0 servers, \"batches\" are only a logical grouping of\n");
	fprintf(stderr, "                      records, and each record is uploaded individually. The true max\n");
	fprintf(stderr, "                      number of async aerospike calls would then be\n");
	fprintf(stderr, "                      <max-async-batches> * <batch-size>\n");
	fprintf(stderr, "                      Default is 32.\n");
	fprintf(stderr, "      --batch-size <n>\n");
	fprintf(stderr, "                      The max allowed number of outstanding async batch write calls\n");
	fprintf(stderr, "                      to make to aerospike at a time.\n");
	fprintf(stderr, "                      Default is 128 with batch writes enabled, or 16 without batch writes.\n");
	fprintf(stderr, "      --event-loops <n>\n");
	fprintf(stderr, "                      The number of c-client event loops to initialize for\n");
	fprintf(stderr, "                      processing of asynchronous Aerospike transactions.\n");
	fprintf(stderr, "                      Default is 1.\n");
	fprintf(stderr, "      --s3-region <region>\n");
	fprintf(stderr, "                      The S3 region that the bucket(s) exist in.\n");
	fprintf(stderr, "      --s3-profile <profile_name>\n");
	fprintf(stderr, "                      The S3 profile to use for credentials (the default is \"default\").\n");
	fprintf(stderr, "      --s3-endpoint-override <url>\n");
	fprintf(stderr, "                      An alternate url endpoint to send S3 API calls to.\n");
	fprintf(stderr, "      --s3-max-async-downloads <n>\n");
	fprintf(stderr, "                      The maximum number of simultaneous download requests from S3.\n");
	fprintf(stderr, "      --s3-log-level <n>\n");
	fprintf(stderr, "                      The log level of the AWS S3 C++ SDK. The possible levels are,\n");
	fprintf(stderr, "                      from least to most granular:\n");
	fprintf(stderr, "                       - Off\n");
	fprintf(stderr, "                       - Fatal\n");
	fprintf(stderr, "                       - Error\n");
	fprintf(stderr, "                       - Warn\n");
	fprintf(stderr, "                       - Info\n");
	fprintf(stderr, "                       - Debug\n");
	fprintf(stderr, "                       - Trace\n");
	fprintf(stderr, "                      The default is Fatal.\n\n");

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

