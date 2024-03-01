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

#include <backup_config.h>

#include <getopt.h>

#include <conf.h>
#include <utils.h>


//==========================================================
// Typedefs & constants.
//

#define OPTIONS_SHORT "h:Sp:A:U:P::n:s:d:o:c:F:rvxCB:l:X:D:M:m:eN:RIuVZa:b:L:q:w:z:y:f:"

// The C client's version string
extern char *aerospike_client_version;


//==========================================================
// Forward Declarations.
//

static void print_version();
static void usage(const char *name);

//==========================================================
// Public API.
//

int
backup_config_set(int argc, char* argv[], backup_config_t* conf)
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
		// tlsCertBlackList is deprecated
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
		// tls-cert-blacklist is deprecated
		{ "tls-cert-blacklist", required_argument, NULL, TLS_OPT_CERT_BLACK_LIST },
		{ "tls-log-session-info", no_argument, NULL, TLS_OPT_LOG_SESSION_INFO },
		{ "tls-keyfile", required_argument, NULL, TLS_OPT_KEY_FILE },
		{ "tls-keyfile-password", optional_argument, NULL, TLS_OPT_KEY_FILE_PASSWORD },
		{ "tls-certfile", required_argument, NULL, TLS_OPT_CERT_FILE },

		// asbackup section in config file
		{ "compact", no_argument, NULL, 'C' },
		{ "parallel", required_argument, NULL, 'w' },
		{ "compress", required_argument, NULL, 'z' },
		{ "compression-level", required_argument, NULL, COMMAND_OPT_COMPRESSION_LEVEL },
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
		{ "remove-artifacts", no_argument, NULL, COMMAND_OPT_REMOVE_ARTIFACTS },
		{ "estimate-samples", required_argument, NULL, COMMAND_OPT_ESTIMATE_SAMPLES },
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
		{ "prefer-racks", required_argument, NULL, COMMAND_OPT_PREFER_RACKS },

		{ "s3-region", required_argument, NULL, COMMAND_OPT_S3_REGION },
		{ "s3-profile", required_argument, NULL, COMMAND_OPT_S3_PROFILE },
		{ "s3-endpoint-override", required_argument, NULL, COMMAND_OPT_S3_ENDPOINT_OVERRIDE },
		{ "s3-min-part-size", required_argument, NULL, COMMAND_OPT_S3_MIN_PART_SIZE },
		{ "s3-max-async-downloads", required_argument, NULL, COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS },
		{ "s3-max-async-uploads", required_argument, NULL, COMMAND_OPT_S3_MAX_ASYNC_UPLOADS },
		{ "s3-log-level", required_argument, NULL, COMMAND_OPT_S3_LOG_LEVEL },
		{ "s3-connect-timeout", required_argument, NULL, COMMAND_OPT_S3_CONNECT_TIMEOUT },

		{ "sa-address", required_argument, NULL, COMMAND_SA_ADDRESS },
		{ "sa-port", required_argument, NULL, COMMAND_SA_PORT },
		{ "sa-timeout", required_argument, NULL, COMMAND_SA_TIMEOUT },
		{ "sa-cafile", required_argument, NULL, COMMAND_SA_CAFILE },
		{ NULL, 0, NULL, 0 }
	};

	backup_config_init(conf);
	backup_config_set_heap_defaults(conf);

	int32_t opt;
	int64_t tmp;
	s3_log_level_t s3_log_level;

	// Don't print error messages for the first two argument parsers
	opterr = 0;

	// Reset optind (internal variable)
	// to parse all options again in case this was called before
	// by the shared library
	optind = 1;

	// Option string should start with '-' to avoid argv permutation.
	// We need same argv sequence in third check to support space separated
	// optional argument value.
	while ((opt = getopt_long(argc, argv, "-" OPTIONS_SHORT, options, 0)) != -1) {

		switch (opt) {
			case 'V':
				print_version();
				backup_config_destroy(conf);
				return BACKUP_CONFIG_INIT_EXIT;

			case 'Z':
				usage(argv[0]);
				return BACKUP_CONFIG_INIT_EXIT;
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
			if (!config_from_file(conf, instance, config_fname, 0, true)) {
				return BACKUP_CONFIG_INIT_FAILURE;
			}
		} else {
			if (!config_from_files(conf, instance, config_fname, true)) {
				return BACKUP_CONFIG_INIT_FAILURE;
			}
		}
	} else { 
		if (read_only_conf_file) {
			err("--no-config-file and only-config-file are mutually exclusive "
					"option. Please enable only one.");
			return BACKUP_CONFIG_INIT_FAILURE;
		}
	}

	// Reset optind (internal variable) to parse all options again
	optind = 1;

	// Now print error messages
	opterr = 1;

	bool used_sa_port_arg = false;
	// parse secret agent arguments
	while ((opt = getopt_long(argc, argv, "-" OPTIONS_SHORT, options, 0)) != -1) {

		switch (opt) {
		case COMMAND_SA_ADDRESS:
			// if the default was set, free it
			if (conf->secret_cfg.addr != NULL) {
				cf_free(conf->secret_cfg.addr);
			}

			conf->secret_cfg.addr = safe_strdup(optarg);
			break;

		case COMMAND_SA_PORT:
			used_sa_port_arg = true;
			
			// if the default was set, free it
			if (conf->secret_cfg.port != NULL) {
				cf_free(conf->secret_cfg.port);
			}
			
			conf->secret_cfg.port = safe_strdup(optarg);
			break;
		
		case COMMAND_SA_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > INT_MAX) {
				err("Invalid secret agent timeout value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->secret_cfg.timeout = (int) tmp;
			break;
		
		case COMMAND_SA_CAFILE:
			// if this was already set during config file parsing,
			// free the config version
			if (conf->secret_cfg.tls.ca_string != NULL) {
				cf_free(conf->secret_cfg.tls.ca_string);
				conf->secret_cfg.tls.ca_string = NULL;
			}

			conf->secret_cfg.tls.ca_string = read_file_as_string(optarg);
			if (conf->secret_cfg.tls.ca_string == NULL) {
				err("Invalid secret agent cafile %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->secret_cfg.tls.enabled = true;
			break;
		}
	}

	// if the user supplied the secret_agent address
	// with an attached port, ex 127.0.0.1:3005
	// then parse and use the addr and port only
	// if the user did not also provide an explicit port
	char* sa_addr = NULL;
	char* sa_port = NULL;
	char *sa_addr_p = conf->secret_cfg.addr;
	bool is_addr_and_port = parse_host(&conf->secret_cfg.addr, &sa_addr, &sa_port);
	if (is_addr_and_port && !used_sa_port_arg) {
		cf_free(conf->secret_cfg.port);
		conf->secret_cfg.addr = safe_strdup(sa_addr);
		conf->secret_cfg.port = safe_strdup(sa_port);
		cf_free(sa_addr_p);
	}

	sa_client sac;
	sa_client_init(&sac, &conf->secret_cfg);
    
	sa_set_log_function(&sa_log_err);

	// Reset optind (internal variable) to parse all options again
	optind = 1;
	// Used to reset optarg if an arg is a secret
	char* old_optarg = NULL;
	while ((opt = getopt_long(argc, argv, OPTIONS_SHORT, options, 0)) != -1) {

		bool arg_is_secret = false;
		old_optarg = optarg;

		if (get_secret_arg(&sac, optarg, &optarg, &arg_is_secret) != 0) {
			return BACKUP_CONFIG_INIT_FAILURE;
		}
		
		if (!arg_is_secret) {
			optarg = old_optarg;
		}

		switch (opt) {
		case 'h':
			conf->host = safe_strdup(optarg);
			break;

		case 'p':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > 65535) {
				err("Invalid port value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->port = (int32_t)tmp;
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
					char* pwd_val = argv[optind++];

					if (get_secret_arg(&sac, pwd_val, &pwd_val, &arg_is_secret) != 0) {
						return BACKUP_CONFIG_INIT_FAILURE;
					}
					
					if (pwd_val != NULL && arg_is_secret) {
						old_optarg = optarg;
						optarg = pwd_val;
					}

					conf->password = safe_strdup(pwd_val);
				} else {
					// No password specified should
					// force it to default password
					// to trigger prompt.
					conf->password = safe_strdup(DEFAULT_PASSWORD);
				}
			}
			break;

		case 'A':
			conf->auth_mode = safe_strdup(optarg);
			break;

		case 'n':
			as_strncpy(conf->ns, optarg, AS_NAMESPACE_MAX_SIZE);
			break;

		case 's':
			if (!parse_set_list(&conf->set_list, optarg)) {
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			break;

		case 'd':
			conf->directory = safe_strdup(optarg);
			break;

		case 'q':
			conf->prefix = safe_strdup(optarg);
			break;

		case 'c':
			conf->state_file = safe_strdup(optarg);
			break;

		case '3':
			conf->state_file_dst = safe_strdup(optarg);
			break;

		case 'o':
			conf->output_file = safe_strdup(optarg);
			break;

		case 'F':
			if (!better_atoi(optarg, &tmp) || tmp < 1) {
				err("Invalid file limit value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->file_limit = ((uint64_t) tmp) * 1024 * 1024;
			break;

		case 'r':
			conf->remove_files = true;
			break;

		case COMMAND_OPT_REMOVE_ARTIFACTS:
			conf->remove_artifacts = true;
			break;

		case COMMAND_OPT_ESTIMATE_SAMPLES:
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > UINT_MAX) {
				err("Invalid estimate-samples value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->n_estimate_samples = (uint32_t) tmp;
			break;

		case 'L':
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid records-per-second value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->records_per_second = (uint32_t) tmp;
			break;

		case 'v':
			as_log_set_level(AS_LOG_LEVEL_TRACE);
			g_verbose = true;
			break;

		case 'x':
			conf->no_bins = true;
			break;

		case 'C':
			conf->compact = true;
			break;

		case 'w':
			if (!better_atoi(optarg, &tmp) || tmp < 1 || tmp > MAX_PARALLEL) {
				err("Invalid parallelism value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->parallel = (int32_t) tmp;
			break;

		case 'z':
			if (parse_compression_type(optarg, &conf->compress_mode) != 0) {
				err("Invalid compression type \"%s\"", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			break;

		case COMMAND_OPT_COMPRESSION_LEVEL:
			if (!better_atoi(optarg, &tmp) || tmp < INT32_MIN || tmp > INT32_MAX) {
				err("Invalid compression-level value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->compression_level = (int32_t) tmp;
			break;

		case 'y':
			if (parse_encryption_type(optarg, &conf->encrypt_mode) != 0) {
				err("Invalid encryption type \"%s\"", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			break;

		case '1':
			// encryption key file
			if (conf->pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env");
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->pkey = (encryption_key_t*) cf_malloc(sizeof(encryption_key_t));
			if (arg_is_secret) {
				if(read_private_key(optarg, conf->pkey) != 0) {
					return BACKUP_CONFIG_INIT_FAILURE;
				}
			}
			else {
				if (read_private_key_file(optarg, conf->pkey) != 0) {
					return BACKUP_CONFIG_INIT_FAILURE;
				}
			}

			break;

		case '2':
			// encryption key environment variable
			if (conf->pkey != NULL) {
				err("Cannot specify both encryption-key-file and encryption-key-env");
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->pkey = parse_encryption_key_env(optarg);
			if (conf->pkey == NULL) {
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			break;

		case 'B':
			conf->bin_list = safe_strdup(optarg);
			break;

		case 'l':
			conf->node_list = safe_strdup(optarg);
			break;

		case 'X':
			conf->partition_list = safe_strdup(optarg);
			break;

		case 'D':
			conf->after_digest = safe_strdup(optarg);
			break;

		case 'f':
			conf->filter_exp = safe_strdup(optarg);
			break;

		case 'M':
			if (!better_atoi(optarg, &tmp) || tmp < 0) {
				err("Invalid max-records value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->max_records = (uint64_t) tmp;
			break;

		case 'm':
			conf->machine = safe_strdup(optarg);
			break;

		case 'e':
			conf->estimate = true;
			break;

		case 'N':
			if (!better_atoi(optarg, &tmp) || tmp < 1 ||
					((uint64_t) tmp) > ULONG_MAX / (1024 * 1024)) {
				err("Invalid bandwidth value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			conf->bandwidth = ((uint64_t) tmp) * 1024 * 1024;
			break;

		case 'R':
			conf->no_records = true;
			break;

		case 'I':
			conf->no_indexes = true;
			break;

		case 'u':
			conf->no_udfs = true;
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
			if (arg_is_secret) {
				conf->tls.castring = safe_strdup(optarg);
			}
			else {
				conf->tls.cafile = safe_strdup(optarg);
			}
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
			inf("Warning: --tls-cert-blacklist is deprecated and will be removed in the next release. Use a crl instead");
			break;

		case TLS_OPT_LOG_SESSION_INFO:
			conf->tls.log_session_info = true;
			break;

		case TLS_OPT_KEY_FILE:
			if (arg_is_secret) {
				conf->tls.keystring = safe_strdup(optarg);
			}
			else {
				conf->tls.keyfile = safe_strdup(optarg);
			}
			break;

		case TLS_OPT_KEY_FILE_PASSWORD:
			if (optarg) {
				conf->tls.keyfile_pw = safe_strdup(optarg);
			} else {
				if (optind < argc && NULL != argv[optind] && '-' != argv[optind][0] ) {
					// space separated argument value
					char* pwd_val = argv[optind++];

					if (get_secret_arg(&sac, pwd_val, &pwd_val, &arg_is_secret) != 0) {
						return BACKUP_CONFIG_INIT_FAILURE;
					}
					
					if (pwd_val != NULL && arg_is_secret) {
						old_optarg = optarg;
						optarg = pwd_val;
					}

					conf->tls.keyfile_pw = safe_strdup(pwd_val);
				} else {
					// No password specified should force it to default password
					// to trigger prompt.
					conf->tls.keyfile_pw = safe_strdup(DEFAULT_PASSWORD);
				}
			}
			break;

		case TLS_OPT_CERT_FILE:
			if (arg_is_secret) {
				conf->tls.certstring = safe_strdup(optarg);
			}
			else {
				conf->tls.certfile = safe_strdup(optarg);
			}
			break;

		case 'a':
			if (!parse_date_time(optarg, &conf->mod_after)) {
				err("Invalid date and time string %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			break;

		case 'b':
			if (!parse_date_time(optarg, &conf->mod_before)) {
				err("Invalid date and time string %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}

			break;

		case COMMAND_OPT_NO_TTL_ONLY:
			conf->ttl_zero = true;
			break;

		case COMMAND_OPT_SOCKET_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid socket timeout value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->socket_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_TOTAL_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid total timeout value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->total_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_MAX_RETRIES:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid max retries value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->max_retries = (uint32_t) tmp;
			break;

		case COMMAND_OPT_RETRY_DELAY:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid retry delay value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->retry_delay = (uint32_t) tmp;
			break;

		case COMMAND_OPT_PREFER_RACKS:
			conf->prefer_racks = strdup(optarg);
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

		case COMMAND_OPT_S3_MIN_PART_SIZE:
			if (!better_atoi(optarg, &tmp) || tmp <= 0 ||
					((uint64_t) tmp) > ULONG_MAX / (1024 * 1024)) {
				err("Invalid S3 min part size value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->s3_min_part_size = ((uint64_t) tmp) * 1024 * 1024;
			break;

		case COMMAND_OPT_S3_MAX_ASYNC_DOWNLOADS:
			if (!better_atoi(optarg, &tmp) || tmp <= 0 || tmp > UINT_MAX) {
				err("Invalid S3 max async downloads value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->s3_max_async_downloads = (uint32_t) tmp;
			break;

		case COMMAND_OPT_S3_MAX_ASYNC_UPLOADS:
			if (!better_atoi(optarg, &tmp) || tmp <= 0 || tmp > UINT_MAX) {
				err("Invalid S3 max async uploads value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->s3_max_async_uploads = (uint32_t) tmp;
			break;

		case COMMAND_OPT_S3_CONNECT_TIMEOUT:
			if (!better_atoi(optarg, &tmp) || tmp < 0 || tmp > UINT_MAX) {
				err("Invalid S3 connect timeout value %s", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->s3_connect_timeout = (uint32_t) tmp;
			break;

		case COMMAND_OPT_S3_LOG_LEVEL:
			if (!s3_parse_log_level(optarg, &s3_log_level)) {
				err("Invalid S3 log level \"%s\"", optarg);
				return BACKUP_CONFIG_INIT_FAILURE;
			}
			conf->s3_log_level = s3_log_level;
			break;

		case CONFIG_FILE_OPT_FILE:
		case CONFIG_FILE_OPT_INSTANCE:
		case CONFIG_FILE_OPT_NO_CONFIG_FILE:
		case CONFIG_FILE_OPT_ONLY_CONFIG_FILE:
		case COMMAND_SA_ADDRESS:
		case COMMAND_SA_PORT:
		case COMMAND_SA_TIMEOUT:
		case COMMAND_SA_CAFILE:
			break;

		default:
			fprintf(stderr, "Run with --help for usage information and flag options\n");
			return BACKUP_CONFIG_INIT_FAILURE;
		}

		if (arg_is_secret) {
			cf_free(optarg);
			optarg = old_optarg;
		}
	}

	if (optind < argc) {
		err("Unexpected trailing argument %s", argv[optind]);
		return BACKUP_CONFIG_INIT_FAILURE;
	}

	return 0;
}

int
backup_config_validate(backup_config_t* conf)
{
	if (conf->port < 0) {
		conf->port = DEFAULT_PORT;
	}

	if (conf->ns[0] == 0 && !conf->remove_artifacts) {
		err("Please specify a namespace (-n option)");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->set_list.size > 1 && conf->filter_exp != NULL) {
		err("Multi-set backup and filter-exp are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->compress_mode == IO_PROXY_COMPRESS_NONE &&
			conf->compression_level != 0) {
		err("Cannot set compression level without compression enabled");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if ((conf->pkey != NULL) ^ (conf->encrypt_mode != IO_PROXY_ENCRYPT_NONE)) {
		err("Must specify both encryption mode and a private key "
				"file/environment variable");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	int32_t out_count = 0;
	out_count += conf->directory != NULL ? 1 : 0;
	out_count += conf->output_file != NULL ? 1 : 0;
	out_count += conf->estimate ? 1 : 0;

	if (out_count > 1) {
		err("Invalid options: --directory, --output-file, and --estimate are mutually exclusive.");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (out_count == 0) {
		err("Please specify a directory (-d), an output file (-o), or make an estimate (-e).");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->estimate && conf->no_records) {
		err("Invalid options: -e and -R are mutually exclusive.");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->estimate && conf->parallel != 0) {
		err("Estimate cannot be parallelized, don't set --parallel.");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->partition_list != NULL && conf->after_digest != NULL) {
		err("after-digest and partition-list arguments are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}
	if (conf->node_list != NULL &&
			(conf->partition_list != NULL || conf->after_digest != NULL)) {
		err("node-list is mutually exclusive with after-digest and partition-list");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->state_file != NULL && conf->estimate) {
		err("--continue and --estimate arguments are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}
	if (conf->state_file != NULL && conf->remove_files) {
		err("--continue and --remove-files arguments are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->state_file != NULL && conf->remove_artifacts) {
		err("--continue and --remove-artifacts arguments are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}
	if (conf->estimate && conf->remove_artifacts) {
		err("--estimate and --remove-artifacts arguments are mutually exclusive");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->s3_min_part_size != 0 && (conf->s3_min_part_size < S3_MIN_PART_SIZE ||
			conf->s3_min_part_size > S3_MAX_PART_SIZE)) {
		err("S3 minimum part size must be between 5 MB and 5 GB (5120 MB)");
		return BACKUP_CONFIG_VALIDATE_FAILURE;
	}

	if (conf->estimate) {
		if (conf->filter_exp != NULL || conf->node_list != NULL ||
				conf->mod_after > 0 || conf->mod_before > 0 || conf->ttl_zero ||
				conf->after_digest != NULL || conf->partition_list != NULL) {
			inf("Warning: using estimate with any of the following will ignore their effects when calculating estimated time/storage: filter-exp, node-list, modified-after, modified-before, no-ttl-only, after-digest, partition-list");
		}

		if (conf->max_records > 0) {
			inf("Warning: max-records is ignored with --estimate, use "
					"--estimate-samples to limit the number of backup samples "
					"taken (default is 10,000)");
		}
	}

	return 0;
}

void
backup_config_set_heap_defaults(backup_config_t* conf) {
	if (conf->host == NULL) {
		conf->host = safe_strdup(DEFAULT_HOST);
	}
	
	if (conf->password == NULL) {
		conf->password = safe_strdup(DEFAULT_PASSWORD);
	}

	if (conf->secret_cfg.addr == NULL) {
		conf->secret_cfg.addr = safe_strdup(DEFAULT_SECRET_AGENT_HOST);
	}

	if (conf->secret_cfg.port == NULL) {
		conf->secret_cfg.port = safe_strdup(DEFAULT_SECRET_AGENT_PORT);
	}
}

void
backup_config_init(backup_config_t* conf)
{
	conf->host = NULL;
	conf->port = -1;
	conf->use_services_alternate = false;
	conf->user = NULL;
	conf->password = NULL;
	conf->auth_mode = NULL;

	conf->s3_region = NULL;
	conf->s3_profile = NULL;
	conf->s3_endpoint_override = NULL;
	conf->s3_min_part_size = 0;
	conf->s3_max_async_downloads = S3_DEFAULT_MAX_ASYNC_DOWNLOADS;
	conf->s3_max_async_uploads = S3_DEFAULT_MAX_ASYNC_UPLOADS;
	conf->s3_connect_timeout = S3_DEFAULT_CONNECT_TIMEOUT_MS;
	conf->s3_log_level = S3_DEFAULT_LOG_LEVEL;

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
	conf->remove_artifacts = false;
	conf->n_estimate_samples = DEFAULT_ESTIMATE_SAMPLES;
	conf->directory = NULL;
	conf->output_file = NULL;
	conf->prefix = NULL;
	conf->compact = false;
	conf->parallel = 0;
	conf->compress_mode = IO_PROXY_COMPRESS_NONE;
	conf->compression_level = 0;
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

	conf->prefer_racks = NULL;

	sa_cfg_init(&conf->secret_cfg);
}

void
backup_config_destroy(backup_config_t* conf)
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

	if (conf->pkey != NULL) {
		encryption_key_free(conf->pkey);
		cf_free(conf->pkey);
	}

	if (conf->bin_list != NULL) {
		cf_free(conf->bin_list);
	}

	if (conf->node_list != NULL) {
		cf_free(conf->node_list);
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

	if (conf->directory != NULL) {
		cf_free(conf->directory);
	}

	if (conf->output_file != NULL) {
		cf_free(conf->output_file);
	}

	if (conf->prefix != NULL) {
		cf_free(conf->prefix);
	}

	if (conf->machine != NULL) {
		cf_free(conf->machine);
	}

	if (conf->tls_name != NULL) {
		cf_free(conf->tls_name);
	}

	if (conf->prefer_racks != NULL) {
		cf_free(conf->prefer_racks);
	}

	tls_config_destroy(&conf->tls);

	sa_config_destroy(&conf->secret_cfg);
}

backup_config_t*
backup_config_clone(backup_config_t* conf)
{
	backup_config_t* clone = cf_malloc(sizeof(backup_config_t));
	if (clone == NULL) {
		err("Failed to allocate %zu bytes for backup_config struct",
				sizeof(backup_config_t));
		return NULL;
	}

	clone->host = safe_strdup(conf->host);
	clone->port = conf->port;
	clone->use_services_alternate = conf->use_services_alternate;
	clone->user = safe_strdup(conf->user);
	clone->password = safe_strdup(conf->password);
	clone->s3_region = safe_strdup(conf->s3_region);
	clone->s3_profile = safe_strdup(conf->s3_profile);
	clone->s3_endpoint_override = safe_strdup(conf->s3_endpoint_override);
	clone->s3_min_part_size = conf->s3_min_part_size;
	clone->s3_max_async_downloads = conf->s3_max_async_downloads;
	clone->s3_max_async_uploads = conf->s3_max_async_uploads;
	clone->s3_log_level = conf->s3_log_level;
	memcpy(clone->ns, conf->ns, sizeof(as_namespace));
	clone->no_bins = conf->no_bins;
	clone->state_file = safe_strdup(conf->state_file);
	clone->state_file_dst = safe_strdup(conf->state_file_dst);
	str_vector_clone(&clone->set_list, &conf->set_list);
	clone->bin_list = safe_strdup(conf->bin_list);
	clone->node_list = safe_strdup(conf->node_list);
	clone->mod_after = conf->mod_after;
	clone->mod_before = conf->mod_before;
	clone->ttl_zero = conf->ttl_zero;
	clone->socket_timeout = conf->socket_timeout;
	clone->total_timeout = conf->total_timeout;
	clone->max_retries = conf->max_retries;
	clone->retry_delay = conf->retry_delay;

	clone->tls_name = safe_strdup(conf->tls_name);
	tls_config_clone(&clone->tls, &conf->tls);

	clone->remove_files = conf->remove_files;
	clone->remove_artifacts = conf->remove_artifacts;
	clone->n_estimate_samples = conf->n_estimate_samples;
	clone->directory = safe_strdup(conf->directory);
	clone->output_file = safe_strdup(conf->output_file);
	clone->prefix = safe_strdup(conf->prefix);
	clone->compact = conf->compact;
	clone->parallel = conf->parallel;
	clone->compress_mode = conf->compress_mode;
	clone->compression_level = conf->compression_level;
	clone->encrypt_mode = conf->encrypt_mode;
	if (conf->pkey != NULL) {
		clone->pkey = cf_malloc(sizeof(encryption_key_t));
		encryption_key_clone(clone->pkey, conf->pkey);
	}
	else {
		clone->pkey = NULL;
	}
	clone->machine = safe_strdup(conf->machine);
	clone->estimate = conf->estimate;
	clone->bandwidth = conf->bandwidth;
	clone->max_records = conf->max_records;
	clone->records_per_second = conf->records_per_second;
	clone->no_records = conf->no_records;
	clone->no_indexes = conf->no_indexes;
	clone->no_udfs = conf->no_udfs;
	clone->file_limit = conf->file_limit;
	clone->auth_mode = safe_strdup(conf->auth_mode);
	clone->partition_list = safe_strdup(conf->partition_list);
	clone->after_digest = safe_strdup(conf->after_digest);
	clone->filter_exp = safe_strdup(conf->filter_exp);
	clone->prefer_racks = safe_strdup(conf->prefer_racks);

	sa_config_clone(&clone->secret_cfg, &conf->secret_cfg);

	return clone;
}

bool
backup_config_log_start(const backup_config_t* conf)
{
	const char *before;
	const char *after;
	const char *ttl_zero_msg;
	char before_buff[100];
	char after_buff[100];

	if (!format_date_time(conf->mod_before, before_buff, sizeof(before_buff))) {
		err("Error while formatting modified-since time");
		return false;
	}
	if (!format_date_time(conf->mod_after, after_buff, sizeof(after_buff))) {
		err("Error while formatting modified-since time");
		return false;
	}

	before = before_buff;
	after = after_buff;
	ttl_zero_msg = conf->ttl_zero ? "true" : "false";

	inf("Starting backup of %s (namespace: %s, set: [%s], bins: %s, "
			"after: %s, before: %s, no ttl only: %s, limit: %" PRId64
			") to %s",
			conf->node_list ? conf->node_list : conf->host, conf->ns,
			conf->set_list.size == 0 ? "all" : str_vector_tostring(&conf->set_list),
			conf->bin_list == NULL ? "[all]" : conf->bin_list,
			after, before, ttl_zero_msg, conf->max_records,
			conf->output_file != NULL ?
			strcmp(conf->output_file, "-") == 0 ? "[stdout]" : conf->output_file :
			conf->directory != NULL ? conf->directory : "[none]");

	return true;
}

bool
backup_config_can_resume(const backup_config_t* conf)
{
	return !conf->estimate;
}

bool
backup_config_allow_uncovered_partitions(const backup_config_t* conf)
{
	return conf->node_list != NULL;
}


//==========================================================
// Local helpers.
//

/*
 * Print the tool's version information.
 */
static void
print_version()
{
	char* build = NULL;
	char* version_cpy = strdup(TOOL_VERSION);
	char* token = strtok(version_cpy, "-");
	char* version = token;

	token = strtok(NULL, "-");

	while (token != NULL) {
		token = strtok(NULL, "-");

		if (token != NULL) {
			build = token;
		}
	}
	
	fprintf(stdout, "Aerospike Backup\n");
	fprintf(stdout, "Version %s\n", version);

	if (build != NULL) {
		fprintf(stdout, "Build %s\n", build);
	}

	free(version_cpy);
}

/*
 * Displays usage information.
 *
 * @param name  The actual name of the `asbackup` binary.
 */
static void
usage(const char *name)
{
	fprintf(stdout, "Usage: %s [OPTIONS]\n", name);
	fprintf(stdout, "------------------------------------------------------------------------------");
	fprintf(stdout, "\n");
	fprintf(stdout, " -V, --version        Print ASBACKUP version information.\n");
	fprintf(stdout, " -O, --options        Print command-line options message.\n");
	fprintf(stdout, " -Z, --usage          Display this message.\n\n");

	fprintf(stdout, "\n");
	fprintf(stdout, "Configuration File Allowed Options\n");
	fprintf(stdout, "----------------------------------\n\n");

	fprintf(stdout, "[cluster]\n");
	fprintf(stdout, " -h HOST, --host=HOST\n");
	fprintf(stdout, "                      HOST is \"<host1>[:<tlsname1>][:<port1>],...\" \n");
	fprintf(stdout, "                      Server seed hostnames or IP addresses. The tlsname is \n");
	fprintf(stdout, "                      only used when connecting with a secure TLS enabled \n");
	fprintf(stdout, "                      server. Default: localhost:3000\n");
	fprintf(stdout, "                      Examples:\n");
	fprintf(stdout, "                        host1\n");
	fprintf(stdout, "                        host1:3000,host2:3000\n");
	fprintf(stdout, "                        192.168.1.10:cert1:3000,192.168.1.20:cert2:3000\n");
	fprintf(stdout, " -S, --services-alternate\n");
	fprintf(stdout, "                      Use to connect to alternate access address when the \n");
	fprintf(stdout, "                      cluster's nodes publish IP addresses through access-address \n");
	fprintf(stdout, "                      which are not accessible over WAN and alternate IP addresses \n");
	fprintf(stdout, "                      accessible over WAN through alternate-access-address. Default: false.\n");
	fprintf(stdout, " -p PORT, --port=PORT Server default port. Default: 3000\n");
	fprintf(stdout, " -U USER, --user=USER User name used to authenticate with cluster. Default: none\n");
	fprintf(stdout, " -P, --password\n");
	fprintf(stdout, "                      Password used to authenticate with cluster. Default: none\n");
	fprintf(stdout, "                      User will be prompted on command line if -P specified and no\n");
	fprintf(stdout, "      	               password is given.\n");
	fprintf(stdout, " -A, --auth\n");
	fprintf(stdout, "                      Set authentication mode when user/password is defined. Modes are\n");
	fprintf(stdout, "                      (INTERNAL, EXTERNAL, EXTERNAL_INSECURE, PKI) and the default is INTERNAL.\n");
	fprintf(stdout, "                      This mode must be set EXTERNAL when using LDAP\n");
	fprintf(stdout, " --tls-enable         Enable TLS on connections. By default TLS is disabled.\n");
	// Deprecated
	fprintf(stdout, " --tls-name           The default tls-name to use to authenticate each TLS socket connection.\n");
	fprintf(stdout, " --tls-cafile=TLS_CAFILE\n");
	fprintf(stdout, "                      Path to a trusted CA certificate file.\n");
	fprintf(stdout, " --tls-capath=TLS_CAPATH.\n");
	fprintf(stdout, "                      Path to a directory of trusted CA certificates.\n");
	fprintf(stdout, " --tls-protocols=TLS_PROTOCOLS\n");
	fprintf(stdout, "                      Set the TLS protocol selection criteria. This format\n"
					"                      is the same as Apache's SSLProtocol documented at http\n"
					"                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
					"                      protocol . If not specified the asbackup will use '-all\n"
					"                      +TLSv1.2' if has support for TLSv1.2,otherwise it will\n"
					"                      be '-all +TLSv1'.\n");
	fprintf(stdout, " --tls-cipher-suite=TLS_CIPHER_SUITE\n");
	fprintf(stdout, "                     Set the TLS cipher selection criteria. The format is\n"
					"                     the same as Open_sSL's Cipher List Format documented\n"
					"                     at https://www.openssl.org/docs/man3.0/man1/openssl-ciphers.html.\n"
					"                     html\n");
	fprintf(stdout, " --tls-keyfile=TLS_KEYFILE\n");
	fprintf(stdout, "                      Path to the key for mutual authentication (if\n"
					"                      Aerospike Cluster is supporting it).\n");
	fprintf(stdout, " --tls-keyfile-password=TLS_KEYFILE_PASSWORD\n");
	fprintf(stdout, "                      Password to load protected tls-keyfile.\n"
					"                      It can be one of the following:\n"
					"                      1) Environment varaible: 'env:<VAR>'\n"
					"                      2) File: 'file:<PATH>'\n"
					"                      3) String: 'PASSWORD'\n"
					"                      Default: none\n"
					"                      User will be prompted on command line if --tls-keyfile-password\n"
					"                      specified and no password is given.\n");
	fprintf(stdout, " --tls-certfile=TLS_CERTFILE <path>\n");
	fprintf(stdout, "                      Path to the chain file for mutual authentication (if\n"
					"                      Aerospike Cluster is supporting it).\n");
	fprintf(stdout, " --tls-cert-blacklist <path> (DEPRECATED)\n");
	fprintf(stdout, "                      Path to a certificate blacklist file. The file should\n"
					"                      contain one line for each blacklisted certificate.\n"
					"                      Each line starts with the certificate serial number\n"
					"                      expressed in hex. Each entry may optionally specify\n"
					"                      the issuer name of the certificate (serial numbers are\n"
					"                      only required to be unique per issuer).Example:\n"
					"                      867EC87482B2\n"
					"                      /C=US/ST=CA/O=Acme/OU=Engineering/CN=TestChainCA\n");

	fprintf(stdout, " --tls-crl-check      Enable CRL checking for leaf certificate. An error\n"
					"                      occurs if a valid CRL files cannot be found in\n"
					"                      tls_capath.\n");
	fprintf(stdout, " --tls-crl-checkall   Enable CRL checking for entire certificate chain. An\n"
					"                      error occurs if a valid CRL files cannot be found in\n"
					"                      tls_capath.\n");
	fprintf(stdout, " --tls-log-session-info\n");
	fprintf(stdout, "                      Enable logging session information for each TLS connection.\n");


	fprintf(stdout, "[asbackup]\n");
	fprintf(stdout, "  -n, --namespace <namespace>\n");
	fprintf(stdout, "                      The namespace to be backed up. Required.\n");
	fprintf(stdout, "  -s, --set <set>[,<set2>[,...]]\n");
	fprintf(stdout, "                      The set(s) to be backed up. Default: all sets.\n");
	fprintf(stdout, "                      If multiple sets are being backed up, filter-exp cannot be used\n");
	fprintf(stdout, "  -d, --directory <directory>\n");
	fprintf(stdout, "                      The directory that holds the backup files. Required, \n");
	fprintf(stdout, "                      unless -o or -e is used.\n");
	fprintf(stdout, "  -o, --output-file <file>\n");
	fprintf(stdout, "                      Backup to a single backup file. Use - for stdout.\n");
	fprintf(stdout, "                      Required, unless -d or -e is used.\n");
	fprintf(stdout, "  -q, --output-file-prefix <prefix>\n");
	fprintf(stdout, "                      When using directory parameter, prepend a prefix to the names of the generated files.\n");
	fprintf(stdout, "  -v, --verbose       Enable verbose output. Default: disabled\n");
	fprintf(stdout, "  -r, --remove-files\n");
	fprintf(stdout, "                      Remove existing backup file (-o) or files (-d).\n");
	fprintf(stdout, "      --remove-artifacts\n");
	fprintf(stdout, "                      Remove existing backup file (-o) or files (-d) without performing a backup.\n");
	fprintf(stdout, "                      This option is mutually exclusive to --continue and --estimate.\n");
	fprintf(stdout, "  -c, --continue <state_file>\n");
	fprintf(stdout, "                      Resumes an interrupted/failed backup from where it was left off, given the .state file\n");
	fprintf(stdout, "                      that was generated from the interrupted/failed run.\n");
	fprintf(stdout, "  --state-file-dst <path>\n");
	fprintf(stdout, "                      Either a path with a file name or a directory in which the backup state file will be\n");
	fprintf(stdout, "                      placed if the backup is interrupted/fails. If a path with a file name is used, that\n");
	fprintf(stdout, "                      exact path is where the backup file will be placed. If a directory is given, the backup\n");
	fprintf(stdout, "                      state will be placed in the directory with name `<namespace>.asb.state`, or\n");
	fprintf(stdout, "                      `<prefix>.asb.state` if `--output-file-prefix` is given.\n");
	fprintf(stdout, "  -F, --file-limit\n");
	fprintf(stdout, "                      Rotate backup files, when their size crosses the given\n");
	fprintf(stdout, "                      value (in MiB) Only used when backing up to a directory.\n");
	fprintf(stdout, "                      Default: 250.\n");
	fprintf(stdout, "  -L, --records-per-second <rps>\n");
	fprintf(stdout, "                      Limit total returned records per second (rps).\n");
	fprintf(stdout, "                      Do not apply rps limit if records-per-second is zero.\n");
	fprintf(stdout, "                      Default: 0.\n");
	fprintf(stdout, "  -v, --verbose\n");
	fprintf(stdout, "                      Enable more detailed logging.\n");
	fprintf(stdout, "  -x, --no-bins\n");
	fprintf(stdout, "                      Do not include bin data in the backup.\n");
	fprintf(stdout, "  -C, --compact\n");
	fprintf(stdout, "                      Do not apply base-64 encoding to BLOBs; results in smaller\n");
	fprintf(stdout, "                      backup files.\n");
	fprintf(stdout, "  -z, --compress <compression_algorithm>\n");
	fprintf(stdout, "                      Enables compressing of backup files using the specified compression algorithm.\n");
	fprintf(stdout, "                      Supported compression algorithms are: zstd\n");
	fprintf(stdout, "                      Set the zstd compression level via the --compression-level option. Default level is 3.\n");
	fprintf(stdout, "  -y, --encrypt <encryption_algorithm>\n");
	fprintf(stdout, "                      Enables encryption of backup files using the specified encryption algorithm.\n");
	fprintf(stdout, "                      A private key must be given, either via the --encryption-key-file option or\n");
	fprintf(stdout, "                      the --encryption-key-env option.\n");
	fprintf(stdout, "                      Supported encryption algorithms are: aes128, aes256\n");
	fprintf(stdout, "      --encryption-key-file <path>\n");
	fprintf(stdout, "                      Grabs the encryption key from the given file, which must be in PEM format.\n");
	fprintf(stdout, "      --encryption-key-env <env_var_name>\n");
	fprintf(stdout, "                      Grabs the encryption key from the given environment variable, which must be base-64 encoded.\n");
	fprintf(stdout, "  -B, --bin-list <bin 1>[,<bin 2>[,...]]\n");
	fprintf(stdout, "                      Only include the given bins in the backup.\n");
	fprintf(stdout, "                      Default: include all bins.\n");
	fprintf(stdout, "  -l, --node-list <IP addr 1>:<port 1>[,<IP addr 2>:<port 2>[,...]]\n");
	fprintf(stdout, "                      <IP addr 1>:<TLS_NAME 1>:<port 1>[,<IP addr 2>:<TLS_NAME 2>:<port 2>[,...]]\n");
	fprintf(stdout, "                      Backup the given cluster nodes only.\n");
	fprintf(stdout, "                      The job is parallelized over 16 scans unless --parallel is set to another value.\n");
	fprintf(stdout, "                      This argument is mutually exclusive to partition-list/after-digest arguments.\n");
	fprintf(stdout, "                      Default: backup all nodes in the cluster\n");
	fprintf(stdout, "  -w, --parallel <n>\n");
	fprintf(stdout, "                      Maximum number of scan calls to run in parallel. Default: 1\n");
	fprintf(stdout, "                      If only one partition range is given, or the entire namespace is being backed up, the range\n");
	fprintf(stdout, "                      of partitions will be evenly divided by this number to be processed in parallel. Otherwise, each\n");
	fprintf(stdout, "                      filter cannot be parallelized individually, so you may only achieve as much parallelism as there are\n");
	fprintf(stdout, "                      partition filters.\n");
	fprintf(stdout, "  -X, --partition-list <filter[,<filter>[...]]>\n");
	fprintf(stdout, "                      List of partitions to back up. Partition filters can be ranges, individual partitions, or \n");
	fprintf(stdout, "                      records after a specific digest within a single partition.\n");
	fprintf(stdout, "                      This argument is mutually exclusive to after-digest.\n");
	fprintf(stdout, "                      Note: each partition filter is an individual task which cannot be parallelized, so you can only\n");
	fprintf(stdout, "                      achieve as much parallelism as there are partition filters. You may increase parallelism by dividing up\n");
	fprintf(stdout, "                      partition ranges manually.\n");
	fprintf(stdout, "                      Filter: <begin partition>[-<partition count>]|<digest>\n");
	fprintf(stdout, "                      begin partition: 0-4095\n");
	fprintf(stdout, "                      partition count: 1-4096 Default: 1\n");
	fprintf(stdout, "                      digest: base64 encoded string\n");
	fprintf(stdout, "                      Examples: 0-1000, 1000-1000, 2222, EjRWeJq83vEjRRI0VniavN7xI0U=\n");
	fprintf(stdout, "                      Default: 0-4096 (all partitions)\n");
	fprintf(stdout, "  -D, --after-digest <digest>\n");
	fprintf(stdout, "                      Backup records after record digest in record's partition plus all succeeding\n");
	fprintf(stdout, "                      partitions. Used to resume backup with last record received from previous\n");
	fprintf(stdout, "                      incomplete backup.\n");
	fprintf(stdout, "                      This argument is mutually exclusive to partition-list.\n");
	fprintf(stdout, "                      Format: base64 encoded string\n");
	fprintf(stdout, "                      Example: EjRWeJq83vEjRRI0VniavN7xI0U=\n");
	fprintf(stdout, "  -f, --filter-exp <b64 encoded expression>\n");
	fprintf(stdout, "                      Use the encoded filter expression in each scan call,\n");
	fprintf(stdout, "                      which can be used to do a partial backup.\n");
	fprintf(stdout, "                      The expression to be used can be base64 encoded through any client.\n");
	fprintf(stdout, "                      This argument is mutually exclusive with multi-set backup\n");
	fprintf(stdout, "  -M, --max-records <number of records>\n");
	fprintf(stdout, "                      The number of records approximately to back up. Default: all records\n");
	fprintf(stdout, "  -m, --machine <path>\n");
	fprintf(stdout, "                      Output machine-readable status updates to the given path, \n");
	fprintf(stdout,"                       typically a FIFO.\n");
	fprintf(stdout, "  -e, --estimate\n");
	fprintf(stdout, "                      Estimate the backed-up record size from a random sample of \n");
	fprintf(stdout, "                      10,000 (default) records at 99.9999%% confidence.\n");
	fprintf(stdout, "      --estimate-samples <n>\n");
	fprintf(stdout, "                      The number of samples to take when running a backup estimate.\n");
	fprintf(stdout, "  -N, --nice <bandwidth>\n");
	fprintf(stdout, "                      The limit for write storage bandwidth in MiB/s.\n");
	fprintf(stdout, "  -R, --no-records\n");
	fprintf(stdout, "                      Don't backup any records.\n");
	fprintf(stdout, "  -I, --no-indexes\n");
	fprintf(stdout, "                      Don't backup any indexes.\n");
	fprintf(stdout, "  -u, --no-udfs\n");
	fprintf(stdout, "                      Don't backup any UDFs.\n");
	fprintf(stdout, "  -a, --modified-after <YYYY-MM-DD_HH:MM:SS>\n");
	fprintf(stdout, "                      Perform an incremental backup; only include records \n");
	fprintf(stdout, "                      that changed after the given date and time. The system's \n");
	fprintf(stdout, "                      local timezone applies. If only HH:MM:SS is specified, then\n");
	fprintf(stdout, "                      today's date is assumed as the date. If only YYYY-MM-DD is \n");
	fprintf(stdout, "                      specified, then 00:00:00 (midnight) is assumed as the time.\n");
	fprintf(stdout, "  -b, --modified-before <YYYY-MM-DD_HH:MM:SS>\n");
	fprintf(stdout, "                      Only include records that last changed before the given\n");
	fprintf(stdout, "                      date and time. May combined with --modified-after to specify\n");
	fprintf(stdout, "                      a range.\n");
	fprintf(stdout, "      --no-ttl-only\n");
	fprintf(stdout, "                      Only include records that have no ttl set (persistent records).\n");
	fprintf(stdout, "      --socket-timeout <ms>\n");
	fprintf(stdout, "                      Socket timeout in milliseconds. Default is 10 seconds.\n");
	fprintf(stdout, "                      If this value is 0, its set to total-timeout. If both are 0,\n");
	fprintf(stdout, "                      there is no socket idle time limit\n");
	fprintf(stdout, "      --total-timeout <ms>\n");
	fprintf(stdout, "                      Total socket timeout in milliseconds. Default is 0, i.e. no timeout.\n");
	fprintf(stdout, "      --max-retries <n>\n");
	fprintf(stdout, "                      Maximum number of retries before aborting the current transaction.\n");
	fprintf(stdout, "                      The default is 5.\n");
	fprintf(stdout, "      --sleep-between-retries <ms>\n");
	fprintf(stdout, "                      The amount of time to sleep between retries. Default is 0.\n");
	fprintf(stdout, "      --prefer-racks <rack id 1>[,<rack id 2>[,...]]\n");
	fprintf(stdout, "                      A list of Aerospike Server rack IDs to prefer when reading records for a backup.\n");
	fprintf(stdout, "      --s3-region <region>\n");
	fprintf(stdout, "                      The S3 region that the bucket(s) exist in.\n");
	fprintf(stdout, "      --s3-profile <profile_name>\n");
	fprintf(stdout, "                      The S3 profile to use for credentials (the default is \"default\").\n");
	fprintf(stdout, "      --s3-endpoint-override <url>\n");
	fprintf(stdout, "                      An alternate url endpoint to send S3 API calls to.\n");
	fprintf(stdout, "      --s3-min-part-size <megabytes>\n");
	fprintf(stdout, "                      The minimum size in megabytes of individual S3 UploadParts.\n");
	fprintf(stdout, "      --s3-max-async-downloads <n>\n");
	fprintf(stdout, "                      The maximum number of simultaneous download requests from S3.\n");
	fprintf(stdout, "                      The default is 32.\n");
	fprintf(stdout, "      --s3-max-async-uploads <n>\n");
	fprintf(stdout, "                      The maximum number of simultaneous upload requests from S3.\n");
	fprintf(stdout, "                      The default is 16.\n");
	fprintf(stdout, "      --s3-log-level <n>\n");
	fprintf(stdout, "                      The log level of the AWS S3 C++ SDK. The possible levels are,\n");
	fprintf(stdout, "                      from least to most granular:\n");
	fprintf(stdout, "                       - Off\n");
	fprintf(stdout, "                       - Fatal\n");
	fprintf(stdout, "                       - Error\n");
	fprintf(stdout, "                       - Warn\n");
	fprintf(stdout, "                       - Info\n");
	fprintf(stdout, "                       - Debug\n");
	fprintf(stdout, "                       - Trace\n");
	fprintf(stdout, "                      The default is Fatal.\n");
	fprintf(stdout, "      --s3-connect-timeout <ms>\n");
	fprintf(stdout, "                      The AWS S3 client's connection timeout in milliseconds.\n");
	fprintf(stdout, "                      This is equivalent to cli-connect-timeout in the AWS CLI,\n");
	fprintf(stdout, "                      or connectTimeoutMS in the aws-sdk-cpp client configuration.\n\n");

	fprintf(stdout, "\n\n");
	fprintf(stdout, "Default configuration files are read from the following files in the given order:\n");
	fprintf(stdout, "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n");
	fprintf(stdout, "The following sections are read: (cluster asbackup include)\n");
	fprintf(stdout, "The following options effect configuration file behavior\n");
	fprintf(stdout, " --no-config-file \n");
	fprintf(stdout, "                      Do not read any config file. Default: disabled\n");
	fprintf(stdout, " --instance <name>\n");
	fprintf(stdout, "                      Section with these instance is read. e.g in case instance `a` is specified\n");
	fprintf(stdout, "                      sections cluster_a, asbackup_a is read.\n");
	fprintf(stdout, " --config-file <path>\n");
	fprintf(stdout, "                      Read this file after default configuration file.\n");
	fprintf(stdout, " --only-config-file <path>\n");
	fprintf(stdout, "                      Read only this configuration file.\n\n");

	fprintf(stdout, "[secret-agent]\n");
	fprintf(stdout, " Options pertaining to the Aerospike secret agent https://docs.aerospike.com/tools/secret-agent.\n");
	fprintf(stdout, " Asbackup and asrestore support getting most config file and command line options\n");
	fprintf(stdout, " from the Aerospike secret agent. \n");
	fprintf(stdout, " To use a secret as an option, use this format \"secrets:<resource_name>:<secret_name>\" \n");
	fprintf(stdout, "    Examples:\n");
	fprintf(stdout, "    asrestore -n secrets:resource1:namespace -d testout -h secrets:pass:pass --sa-address 0.0.0.0:3005\n");
	fprintf(stdout, "    asbackup -n test -d testout --ca-file secrets:resource2:cacert\n");
	fprintf(stdout, " --sa-address=<host_name>\n");
	fprintf(stdout, "                      <host_name> is \"<host>[:<port>]\" \n");
	fprintf(stdout, "                      Aerospike Secret agent hostname or IP address.\n");
	fprintf(stdout, "                      Default: localhost:3005\n");
	fprintf(stdout, "                      Examples:\n");
	fprintf(stdout, "                        host1\n");
	fprintf(stdout, "                        host1:3005\n");
	fprintf(stdout, "                        192.168.1.10:3005\n");
	fprintf(stdout, "                        [::]:3005\n");
	fprintf(stdout, " --sa-port=<port>\n");
	fprintf(stdout, "                      The port number used to connect to the Aerospike secret agent \n");
	fprintf(stdout, "                      Default: 3005 \n");
	fprintf(stdout, " --sa-timeout=<ms>\n");
	fprintf(stdout, "                      Timeout in milliseconds applied when connecting\n");
	fprintf(stdout, "                      to the Aerospike Secret agent and when requesting secrets.\n");
	fprintf(stdout, "                      The default timeout is 1000ms.\n");
	fprintf(stdout, " --sa-cafile=<tls_cafile>\n");
	fprintf(stdout, "                      Path to a trusted CA certificate file.\n");
	fprintf(stdout, "                      Used when authenticating with the Aerospike secret agent.\n");
}

