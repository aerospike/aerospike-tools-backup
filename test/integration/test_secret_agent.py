# coding=UTF-8

"""
Tests that config file and command line option secrets work.
"""

import aerospike
import ctypes

import lib
from run_backup import backup_and_restore

path = "/Users/dwelch/Desktop/everything/projects/tools/aerospike-tools-backup/bin/asrestore.dylib"
restore_so = ctypes.CDLL(path)
backup_so = ctypes.CDLL(path)

class ComparableCtStructure(ctypes.Structure):

	def __eq__(self, other):
		for fld in self._fields_:
			#todo verify the pkey field
			if fld[0] == "pkey":
				continue

			lattr = getattr(self, fld[0])
			rattr = getattr(other, fld[0])

			if lattr != rattr:
				print("eq. %s unequal v1: %s v2: %s" % (fld, getattr(self, fld[0]), getattr(other, fld[0])))
				return False
		return True

	def __ne__(self, other):
		for fld in self._fields_:
			# todo verify the pkey field
			if fld[0] == "pkey":
				continue

			if getattr(self, fld[0]) != getattr(other, fld[0]):
				print("ne. %s unequal v1: %s v2: %s" % (fld, getattr(self, fld[0]), getattr(other, fld[0])))
				return True
		return False

# Define the encryption_key_t structure
class EncryptionKeyT(ComparableCtStructure):
	_fields_ = [
		("data", ctypes.POINTER(ctypes.c_uint8)),
		("len", ctypes.c_uint64)
	]

# Define the as_config_tls structure
class AsConfigTls(ComparableCtStructure):
	_fields_ = [
		("enable", ctypes.c_bool),
		("cafile", ctypes.c_char_p),
		("castring", ctypes.c_char_p),
		("capath", ctypes.c_char_p),
		("protocols", ctypes.c_char_p),
		("cipher_suite", ctypes.c_char_p),
		("cert_blacklist", ctypes.c_char_p),
		("keyfile", ctypes.c_char_p),
		("keyfile_pw", ctypes.c_char_p),
		("keystring", ctypes.c_char_p),
		("certfile", ctypes.c_char_p),
		("certstring", ctypes.c_char_p),
		("crl_check", ctypes.c_bool),
		("crl_check_all", ctypes.c_bool),
		("log_session_info", ctypes.c_bool),
		("for_login_only", ctypes.c_bool)
	]

# Define the restore_config_t structure using the above structures
class RestoreConfigT(ComparableCtStructure):
	_fields_ = [
		("host", ctypes.c_char_p),
		("port", ctypes.c_int32),
		("use_services_alternate", ctypes.c_bool),
		("user", ctypes.c_char_p),
		("password", ctypes.c_char_p),
		("parallel", ctypes.c_uint32),
		("nice_list", ctypes.c_char_p),
		("no_records", ctypes.c_bool),
		("no_indexes", ctypes.c_bool),
		("indexes_last", ctypes.c_bool),
		("no_udfs", ctypes.c_bool),
		("wait", ctypes.c_bool),
		("validate", ctypes.c_bool),
		("timeout", ctypes.c_uint32),
		("max_retries", ctypes.c_uint64),
		("retry_scale_factor", ctypes.c_uint64),
		("socket_timeout", ctypes.c_uint32),
		("total_timeout", ctypes.c_uint32),
		("retry_delay", ctypes.c_uint32),
		("disable_batch_writes", ctypes.c_bool),
		("max_async_batches", ctypes.c_uint32),
		("batch_size", ctypes.c_uint32),
		("event_loops", ctypes.c_uint32),
		("s3_region", ctypes.c_char_p),
		("s3_profile", ctypes.c_char_p),
		("s3_endpoint_override", ctypes.c_char_p),
		("s3_max_async_downloads", ctypes.c_uint32),
		("s3_connect_timeout", ctypes.c_uint32),
		("s3_log_level", ctypes.c_int),  # Assuming s3_log_level is an enum, use int
		("tls", AsConfigTls),
		("tls_name", ctypes.c_char_p),
		("ns_list", ctypes.c_char_p),
		("directory", ctypes.c_char_p),
		("directory_list", ctypes.c_char_p),
		("parent_directory", ctypes.c_char_p),
		("input_file", ctypes.c_char_p),
		("machine", ctypes.c_char_p),
		("bin_list", ctypes.c_char_p),
		("set_list", ctypes.c_char_p),
		("pkey", ctypes.POINTER(EncryptionKeyT)),
		("compress_mode", ctypes.c_int),  # Assuming compression_opt is an enum, use int
		("encrypt_mode", ctypes.c_int),  # Assuming encryption_opt is an enum, use int
		("unique", ctypes.c_bool),
		("replace", ctypes.c_bool),
		("ignore_rec_error", ctypes.c_bool),
		("no_generation", ctypes.c_bool),
		("extra_ttl", ctypes.c_int32),
		("bandwidth", ctypes.c_uint64),
		("tps", ctypes.c_uint32),
		("auth_mode", ctypes.c_char_p)
	]

string_val = "str"
int_val = 1234
bool_val = True
compress_val = "zstd"
encryption_val = "aes256"
s3_log_level_val = "debug"
parallel_val = 16

# anytime an option is added to restore that can be
# a secret it should be added here
RESTORE_SECRET_OPTIONS = [
	{"name": "host", "value": string_val},
	{"name": "port", "value": int_val},
	{"name": "user", "value": string_val},
	{"name": "password", "value": string_val},
	{"name": "auth", "value": string_val},
	{"name": "tls-name", "value": string_val},
	{"name": "tls-cafile", "value": string_val},
	{"name": "tls-capath", "value": string_val},
	{"name": "tls-protocols", "value": string_val},
	{"name": "tls-cipher-suite", "value": string_val},
	{"name": "tls-keyfile", "value": string_val},
	{"name": "tls-keyfile-password", "value": string_val},
	{"name": "tls-certfile", "value": string_val},
	{"name": "namespace", "value": string_val},
	{"name": "directory", "value": string_val},
	{"name": "directory-list", "value": string_val},
	{"name": "parent-directory", "value": string_val},
	{"name": "input-file", "value": string_val},
	{"name": "compress", "value": compress_val},
	{"name": "encrypt", "value": encryption_val},
	{"name": "encryption-key-file", "value": string_val},
	{"name": "parallel", "value": int_val},
	{"name": "threads", "value": int_val},
	{"name": "machine", "value": string_val},
	{"name": "bin-list", "value": string_val},
	{"name": "set-list", "value": string_val},
	{"name": "extra-ttl", "value": int_val},
	{"name": "nice", "value": int_val},
	{"name": "timeout", "value": int_val},
	{"name": "socket-timeout", "value": int_val},
	{"name": "total-timeout", "value": int_val},
	{"name": "max-retries", "value": int_val},
	{"name": "retry-scale-factor", "value": int_val},
	{"name": "sleep-between-retries", "value": int_val},
	{"name": "retry-delay", "value": int_val},
	{"name": "max-async-batches", "value": int_val},
	{"name": "batch-size", "value": int_val},
	{"name": "event-loops", "value": int_val},
	{"name": "s3-region", "value": string_val},
	{"name": "s3-profile", "value": string_val},
	{"name": "s3-endpoint-override", "value": string_val},
	{"name": "s3-max-async-downloads", "value": int_val},
	{"name": "s3-log-level", "value": s3_log_level_val},
	{"name": "s3-connect-timeout", "value": int_val},
]

class AsVector(ComparableCtStructure):

	def __eq__(self, other):
		for fld in self._fields_:
			# TODO verify the list field
			if fld[0] == "list":
				continue

			lattr = getattr(self, fld[0])
			rattr = getattr(other, fld[0])

			if lattr != rattr:
				print("eq. %s unequal v1: %s v2: %s" % (fld, getattr(self, fld[0]), getattr(other, fld[0])))
				return False
		return True

	def __ne__(self, other):
		for fld in self._fields_:
			# TODO verify the list field
			if fld[0] == "list":
				continue

			if getattr(self, fld[0]) != getattr(other, fld[0]):
				print("ne. %s unequal v1: %s v2: %s" % (fld, getattr(self, fld[0]), getattr(other, fld[0])))
				return True
		return False

	_fields_ = [
		("list", ctypes.c_void_p),
		("capacity", ctypes.c_uint32),
		("size", ctypes.c_uint32),
		("item_size", ctypes.c_uint32),
		("flags", ctypes.c_uint32)
	]

# Define the backup_config_t structure
class BackupConfigT(ComparableCtStructure):
    _fields_ = [
        ("host", ctypes.c_char_p),
        ("port", ctypes.c_int32),
        ("use_services_alternate", ctypes.c_bool),
        ("user", ctypes.c_char_p),
        ("password", ctypes.c_char_p),
        ("s3_region", ctypes.c_char_p),
        ("s3_profile", ctypes.c_char_p),
        ("s3_endpoint_override", ctypes.c_char_p),
        ("s3_min_part_size", ctypes.c_uint64),
        ("s3_max_async_downloads", ctypes.c_uint32),
        ("s3_max_async_uploads", ctypes.c_uint32),
        ("s3_connect_timeout", ctypes.c_uint32),
        ("s3_log_level", ctypes.c_int),
        ("ns", ctypes.c_char * 32),  # Use simplified as_namespace structure
        ("no_bins", ctypes.c_bool),
        ("state_file", ctypes.c_char_p),
        ("state_file_dst", ctypes.c_char_p),
        ("set_list", AsVector),  # Use simplified as_vector structure
        ("bin_list", ctypes.c_char_p),
        ("node_list", ctypes.c_char_p),
        ("mod_after", ctypes.c_int64),
        ("mod_before", ctypes.c_int64),
        ("ttl_zero", ctypes.c_bool),
        ("socket_timeout", ctypes.c_uint32),
        ("total_timeout", ctypes.c_uint32),
        ("max_retries", ctypes.c_uint32),
        ("retry_delay", ctypes.c_uint32),
        ("tls_name", ctypes.c_char_p),
        ("tls", AsConfigTls),  # Use simplified as_config_tls structure
        ("remove_files", ctypes.c_bool),
        ("remove_artifacts", ctypes.c_bool),
        ("n_estimate_samples", ctypes.c_uint32),
        ("directory", ctypes.c_char_p),
        ("output_file", ctypes.c_char_p),
        ("prefix", ctypes.c_char_p),
        ("compact", ctypes.c_bool),
        ("parallel", ctypes.c_int32),
        ("compress_mode", ctypes.c_int32),  # Use appropriate type
        ("compression_level", ctypes.c_int32),
        ("encrypt_mode", ctypes.c_int32),  # Use appropriate type
        ("pkey", ctypes.POINTER(EncryptionKeyT)),
        ("machine", ctypes.c_char_p),
        ("estimate", ctypes.c_bool),
        ("bandwidth", ctypes.c_uint64),
        ("max_records", ctypes.c_uint64),
        ("records_per_second", ctypes.c_uint32),
        ("no_records", ctypes.c_bool),
        ("no_indexes", ctypes.c_bool),
        ("no_udfs", ctypes.c_bool),
        ("file_limit", ctypes.c_uint64),
        ("auth_mode", ctypes.c_char_p),
        ("partition_list", ctypes.c_char_p),
        ("after_digest", ctypes.c_char_p),
        ("filter_exp", ctypes.c_char_p)
    ]

BACKUP_SECRET_OPTIONS = [
	{"name": "host", "value": string_val},
	{"name": "port", "value": int_val},
	{"name": "user", "value": string_val},
	{"name": "password", "value": string_val},
	{"name": "auth", "value": string_val},
	{"name": "tls-name", "value": string_val},
	{"name": "tls-cafile", "value": string_val},
	{"name": "tls-capath", "value": string_val},
	{"name": "tls-protocols", "value": string_val},
	{"name": "tls-cipher-suite", "value": string_val},
	{"name": "tls-keyfile", "value": string_val},
	{"name": "tls-keyfile-password", "value": string_val},
	{"name": "tls-certfile", "value": string_val},
	{"name": "compact", "value": string_val},
	{"name": "parallel", "value": parallel_val},
	{"name": "compress", "value": compress_val},
	{"name": "compression-level", "value": int_val},
	{"name": "encrypt", "value": encryption_val},
	{"name": "encryption-key-file", "value": string_val},
	{"name": "bin-list", "value": string_val},
	{"name": "node-list", "value": string_val},
	{"name": "namespace", "value": string_val},
	{"name": "set", "value": string_val},
	{"name": "directory", "value": string_val},
	{"name": "output-file", "value": string_val},
	{"name": "output-file-prefix", "value": string_val},
	{"name": "continue", "value": string_val},
	{"name": "state-file-dst", "value": string_val}, # TODO this expects a file path, maybe it should support reading state file from mem
	{"name": "file-limit", "value": int_val},
	{"name": "estimate-samples", "value": int_val},
	{"name": "partition-list", "value": string_val},
	{"name": "after-digest", "value": string_val},
	{"name": "filter-exp", "value": string_val},
	{"name": "modified-after", "value": string_val},
	{"name": "modified-before", "value": string_val},
	{"name": "records-per-second", "value": int_val},
	{"name": "max-records", "value": int_val},
	{"name": "machine", "value": string_val},
	{"name": "nice", "value": int_val},
	{"name": "socket-timeout", "value": int_val},
	{"name": "total-timeout", "value": int_val},
	{"name": "max-retries", "value": int_val},
	{"name": "sleep-between-retries", "value": int_val},
	{"name": "retry-delay", "value": int_val},
	{"name": "s3-region", "value": string_val},
	{"name": "s3-profile", "value": string_val},
	{"name": "s3-endpoint-override", "value": string_val},
	{"name": "s3-min-part-size", "value": int_val},
	{"name": "s3-max-async-downloads", "value": int_val},
	{"name": "s3-max-async-uploads", "value": int_val},
	{"name": "s3-log-level", "value": s3_log_level_val},
	{"name": "s3-connect-timeout", "value": int_val}
]

def gen_secret_args(input_list, prgm_name):
	args = [prgm_name]
	for elem in input_list:
		arg = "--" + elem["name"]
		args.append(bytes(arg, "utf-8"))

		val = "secrets:r1:"
		val_type = elem["value"]
		if val_type == string_val:
			val = val + "string_val"
		elif val_type == int_val:
			val = val + "int_val"
		elif val_type == compress_val:
			val = val + "compress_val"
		elif val_type == encryption_val:
			val = val + "encryption_val"
		elif val_type == s3_log_level_val:
			val = val + "s3_log_level_val"
		elif val_type == parallel_val:
			val = val + "parallel_val"
		# val = val + elem["name"]

		args.append(bytes(val, "utf-8"))
	
	args.append(b"--sa-address")
	args.append(b"127.0.0.1")
	args.append(b"--sa-port")
	args.append(b"3005")

	count = len(args)
	return count, args

def gen_args(input_list, prgm_name):
	args = [prgm_name]
	for elem in input_list:
		arg = "--" + elem["name"]
		args.append(bytes(arg, "utf-8"))
		args.append(bytes(str(elem["value"]), "utf-8"))
	
	args.append(b"--sa-address")
	args.append(b"127.0.0.1")
	args.append(b"--sa-port")
	args.append(b"3005")

	count = len(args)
	return count, args

def test_restore_config_init():
	exp_argc, exp_argv = gen_args(RESTORE_SECRET_OPTIONS, b"asrestore")
	
	expected_conf = RestoreConfigT()
	p_exp_conf = ctypes.POINTER(RestoreConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	restore_so.restore_config_init(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will file
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	argc, argv = gen_secret_args(RESTORE_SECRET_OPTIONS, b"asrestore")
	conf = RestoreConfigT()
	c_argv = (ctypes.c_char_p * argc)(*argv)
	p_argv = ctypes.POINTER(ctypes.c_char_p)(c_argv)
	p_conf = ctypes.POINTER(RestoreConfigT)(conf)
	restore_so.restore_config_init(argc, p_argv, p_conf)

	assert expected_conf == conf

def test_backup_config_init():
	exp_argc, exp_argv = gen_args(BACKUP_SECRET_OPTIONS, b"asbackup")

	expected_conf = BackupConfigT()
	p_exp_conf = ctypes.POINTER(BackupConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	backup_so.backup_config_init(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will file
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	argc, argv = gen_secret_args(BACKUP_SECRET_OPTIONS, b"asbackup")
	conf = BackupConfigT()
	c_argv = (ctypes.c_char_p * argc)(*argv)
	p_argv = ctypes.POINTER(ctypes.c_char_p)(c_argv)
	p_conf = ctypes.POINTER(BackupConfigT)(conf)
	backup_so.backup_config_init(argc, p_argv, p_conf)

	assert expected_conf == conf
