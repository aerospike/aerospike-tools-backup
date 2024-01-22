# coding=UTF-8

"""
Tests that config file and command line option secrets are parsed correctly.
"""

import ctypes
import os
import platform
import sys
import time

import lib
from aerospike_servers import init_work_dir
import secret_agent_servers as sa

shared_extension = "so"
if platform.system() == "Darwin":
	shared_extension = "dylib"

cwd = os.getcwd()
restore_so = ctypes.CDLL(cwd + "/bin/asrestore." + shared_extension)
backup_so = ctypes.CDLL(cwd + "/bin/asbackup." + shared_extension)
# restore_so = ctypes.CDLL("/tmp/testing/bin/asrestore.so")
# backup_so = ctypes.CDLL("/tmp/testing/bin/asbackup.so")

class ComparableCtStructure(ctypes.Structure):

	def __eq__(self, other):
		for fld in self._fields_:
			lattr = getattr(self, fld[0])
			rattr = getattr(other, fld[0])

			if lattr and rattr and isinstance(lattr, ctypes._Pointer):
				lattr = lattr.contents
				rattr = rattr.contents

			are_eq = lattr.__eq__(rattr)

			if are_eq == NotImplemented:
				print(
					"WARNING: eq %s unimplemented, skipping v1: %s, v2: %s" % (fld, lattr, rattr),
		  			file=sys.stderr
				)
				continue

			if not are_eq:
				print("eq. %s unequal v1: %s v2: %s" % (fld, lattr, rattr))
				return False
		return True

	def __ne__(self, other):
		for fld in self._fields_:
			lattr = getattr(self, fld[0])
			rattr = getattr(other, fld[0])

			if lattr and rattr and isinstance(lattr, ctypes._Pointer):
				lattr = lattr.contents
				rattr = rattr.contents
				breakpoint()

			are_ne = lattr.__ne__(rattr)

			if are_ne == NotImplemented:
				print(
					"WARNING: ne %s unimplemented, skipping v1: %s, v2: %s" % (fld, lattr, rattr),
		  			file=sys.stderr
				)
				continue

			if are_ne:
				print("ne. %s unequal v1: %s v2: %s" % (fld, lattr, rattr))
				return True
		return False

# Define the encryption_key_t structure
class SCTLSCFG(ComparableCtStructure):
	_fields_ = [
		("ca_string", ctypes.c_char_p),
		("enabled", ctypes.c_bool),
	]

# Define the encryption_key_t structure
class SCCFG(ComparableCtStructure):
	_fields_ = [
		("addr", ctypes.c_char_p),
		("port", ctypes.c_char_p),
		("timeout", ctypes.c_int),
		("tls", SCTLSCFG)
	]

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
		("s3_log_level", ctypes.c_int),
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
		("compress_mode", ctypes.c_int),
		("encrypt_mode", ctypes.c_int),
		("unique", ctypes.c_bool),
		("replace", ctypes.c_bool),
		("ignore_rec_error", ctypes.c_bool),
		("no_generation", ctypes.c_bool),
		("extra_ttl", ctypes.c_int32),
		("bandwidth", ctypes.c_uint64),
		("tps", ctypes.c_uint32),
		("auth_mode", ctypes.c_char_p),
		("secret_cfg", SCCFG)
	]

encryption_key_val = ""
with open("./test/test_key.pem", 'r') as key_file:
	encryption_key_val = key_file.read()

string_val = "str"
int_val = 1234
bool_val = True
compress_val = "zstd"
encryption_val = "aes256"
s3_log_level_val = "debug"
parallel_val = 16
modified_by_val = "2016-05-12_08:10:30"

# anytime an option is added to restore that can be
# a secret it should be added here
RESTORE_SECRET_OPTIONS = [
	{"name": "host", "value": string_val, "config_section": "cluster"},
	{"name": "port", "value": int_val, "config_section": "cluster"},
	{"name": "user", "value": string_val, "config_section": "cluster"},
	{"name": "password", "value": string_val, "config_section": "cluster"},
	{"name": "auth", "value": string_val, "config_section": "cluster"},
	{"name": "tls-name", "value": string_val, "config_section": "cluster"},
	{"name": "tls-cafile", "value": string_val, "config_section": "cluster"},
	{"name": "tls-capath", "value": string_val, "config_section": "cluster"},
	{"name": "tls-protocols", "value": string_val, "config_section": "cluster"},
	{"name": "tls-cipher-suite", "value": string_val, "config_section": "cluster"},
	{"name": "tls-keyfile", "value": string_val, "config_section": "cluster"},
	{"name": "tls-keyfile-password", "value": string_val, "config_section": "cluster"},
	{"name": "tls-certfile", "value": string_val, "config_section": "cluster"},
	{"name": "namespace", "value": string_val, "config_section": "asrestore"},
	{"name": "directory", "value": string_val, "config_section": "asrestore"},
	{"name": "directory-list", "value": string_val, "config_section": "asrestore"},
	{"name": "parent-directory", "value": string_val, "config_section": "asrestore"},
	{"name": "input-file", "value": string_val, "config_section": "asrestore"},
	{"name": "compress", "value": compress_val, "config_section": "asrestore"},
	{"name": "encrypt", "value": encryption_val, "config_section": "asrestore"},
	{"name": "encryption-key-file", "value": encryption_key_val, "config_section": "asrestore"},
	{"name": "parallel", "value": parallel_val, "config_section": "asrestore"},
	{"name": "machine", "value": string_val, "config_section": "asrestore"},
	{"name": "bin-list", "value": string_val, "config_section": "asrestore"},
	{"name": "set-list", "value": string_val, "config_section": "asrestore"},
	{"name": "extra-ttl", "value": int_val, "config_section": "asrestore"},
	{"name": "nice", "value": int_val, "config_section": "asrestore"},
	{"name": "timeout", "value": int_val, "config_section": "asrestore"},
	{"name": "socket-timeout", "value": int_val, "config_section": "asrestore"},
	{"name": "total-timeout", "value": int_val, "config_section": "asrestore"},
	{"name": "max-retries", "value": int_val, "config_section": "asrestore"},
	{"name": "retry-scale-factor", "value": int_val, "config_section": "asrestore"},
	{"name": "max-async-batches", "value": int_val, "config_section": "asrestore"},
	{"name": "batch-size", "value": int_val, "config_section": "asrestore"},
	{"name": "event-loops", "value": int_val, "config_section": "asrestore"},
	{"name": "s3-region", "value": string_val, "config_section": "asrestore"},
	{"name": "s3-profile", "value": string_val, "config_section": "asrestore"},
	{"name": "s3-endpoint-override", "value": string_val, "config_section": "asrestore"},
	{"name": "s3-max-async-downloads", "value": int_val, "config_section": "asrestore"},
	{"name": "s3-log-level", "value": s3_log_level_val, "config_section": "asrestore"},
	{"name": "s3-connect-timeout", "value": int_val, "config_section": "asrestore"},
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
        ("ns", ctypes.c_char * 32),
        ("no_bins", ctypes.c_bool),
        ("state_file", ctypes.c_char_p),
        ("state_file_dst", ctypes.c_char_p),
        ("set_list", AsVector),
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
        ("tls", AsConfigTls),
        ("remove_files", ctypes.c_bool),
        ("remove_artifacts", ctypes.c_bool),
        ("n_estimate_samples", ctypes.c_uint32),
        ("directory", ctypes.c_char_p),
        ("output_file", ctypes.c_char_p),
        ("prefix", ctypes.c_char_p),
        ("compact", ctypes.c_bool),
        ("parallel", ctypes.c_int32),
        ("compress_mode", ctypes.c_int32),
        ("compression_level", ctypes.c_int32),
        ("encrypt_mode", ctypes.c_int32),
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
        ("filter_exp", ctypes.c_char_p),
		("prefer_racks", ctypes.c_char_p),
		("secret_cfg", SCCFG)
    ]

BACKUP_SECRET_OPTIONS = [
	{"name": "host", "value": string_val, "config_section": "cluster"},
	{"name": "port", "value": int_val, "config_section": "cluster"},
	{"name": "user", "value": string_val, "config_section": "cluster"},
	{"name": "password", "value": string_val, "config_section": "cluster"},
	{"name": "auth", "value": string_val, "config_section": "cluster"},
	{"name": "tls-name", "value": string_val, "config_section": "cluster"},
	{"name": "tls-cafile", "value": string_val, "config_section": "cluster"},
	{"name": "tls-capath", "value": string_val, "config_section": "cluster"},
	{"name": "tls-protocols", "value": string_val, "config_section": "cluster"},
	{"name": "tls-cipher-suite", "value": string_val, "config_section": "cluster"},
	{"name": "tls-keyfile", "value": string_val, "config_section": "cluster"},
	{"name": "tls-keyfile-password", "value": string_val, "config_section": "cluster"},
	{"name": "tls-certfile", "value": string_val, "config_section": "cluster"},
	{"name": "parallel", "value": parallel_val, "config_section": "asbackup"},
	{"name": "compress", "value": compress_val, "config_section": "asbackup"},
	{"name": "compression-level", "value": int_val, "config_section": "asbackup"},
	{"name": "encrypt", "value": encryption_val, "config_section": "asbackup"},
	{"name": "encryption-key-file", "value": encryption_key_val, "config_section": "asbackup"},
	{"name": "bin-list", "value": string_val, "config_section": "asbackup"},
	{"name": "node-list", "value": string_val, "config_section": "asbackup"},
	{"name": "namespace", "value": string_val, "config_section": "asbackup"},
	{"name": "set", "value": string_val, "config_section": "asbackup"},
	{"name": "directory", "value": string_val, "config_section": "asbackup"},
	{"name": "output-file", "value": string_val, "config_section": "asbackup"},
	{"name": "output-file-prefix", "value": string_val, "config_section": "asbackup"},
	{"name": "continue", "value": string_val, "config_section": "asbackup"},
	{"name": "state-file-dst", "value": string_val, "config_section": "asbackup"},
	{"name": "file-limit", "value": int_val, "config_section": "asbackup"},
	{"name": "estimate-samples", "value": int_val, "config_section": "asbackup"},
	{"name": "partition-list", "value": string_val, "config_section": "asbackup"},
	{"name": "after-digest", "value": string_val, "config_section": "asbackup"},
	{"name": "filter-exp", "value": string_val, "config_section": "asbackup"},
	{"name": "prefer-racks", "value": string_val, "config_section": "asbackup"},
	{"name": "modified-after", "value": modified_by_val, "config_section": "asbackup"},
	{"name": "modified-before", "value": modified_by_val, "config_section": "asbackup"},
	{"name": "records-per-second", "value": int_val, "config_section": "asbackup"},
	{"name": "max-records", "value": int_val, "config_section": "asbackup"},
	{"name": "machine", "value": string_val, "config_section": "asbackup"},
	{"name": "nice", "value": int_val, "config_section": "asbackup"},
	{"name": "socket-timeout", "value": int_val, "config_section": "asbackup"},
	{"name": "total-timeout", "value": int_val, "config_section": "asbackup"},
	{"name": "max-retries", "value": int_val, "config_section": "asbackup"},
	{"name": "sleep-between-retries", "value": int_val, "config_section": "asbackup"},
	{"name": "retry-delay", "value": int_val, "config_section": "asbackup"},
	{"name": "s3-region", "value": string_val, "config_section": "asbackup"},
	{"name": "s3-profile", "value": string_val, "config_section": "asbackup"},
	{"name": "s3-endpoint-override", "value": string_val, "config_section": "asbackup"},
	{"name": "s3-min-part-size", "value": int_val, "config_section": "asbackup"},
	{"name": "s3-max-async-downloads", "value": int_val, "config_section": "asbackup"},
	{"name": "s3-max-async-uploads", "value": int_val, "config_section": "asbackup"},
	{"name": "s3-log-level", "value": s3_log_level_val, "config_section": "asbackup"},
	{"name": "s3-connect-timeout", "value": int_val, "config_section": "asbackup"}
]

def gen_secret_args(input_list, prgm_name, sa_args, resource_name):
	args = [prgm_name]

	args += sa.gen_secret_args(
		args={x["name"]: x["value"] for x in input_list},
		resource=resource_name
	)
	
	args += sa_args

	args = [bytes(x, "utf-8") for x in args]

	count = len(args)
	return count, args

def gen_args(input_list, prgm_name):
	args = [bytes(prgm_name, "utf-8")]
	for elem in input_list:
		arg = "--" + elem["name"]
		args.append(bytes(arg, "utf-8"))

		val = str(elem["value"])
		if elem["name"] == "encryption-key-file":
			val = "./test/test_key.pem"

		args.append(bytes(val, "utf-8"))
	
	args.append(b"--sa-address")
	args.append(b"127.0.0.1")
	args.append(b"--sa-port")
	args.append(b"3005")

	x = ctypes.POINTER("hi").contents

	count = len(args)
	return count, args

def gen_secret_toml(input_list, resource_name, sa_data='sa-address = "127.0.0.1"\nsa-port = "3005"\n'):
	data = ""
	cluster_data = "[cluster]\n"
	secret_data = '[secret-agent]\n%s' % sa_data
	asbackup_data = "[asbackup]\n"
	asrestore_data = "[asrestore]\n"

	for elem in input_list:
		val = "secrets:%s:%s" % (resource_name, elem["name"])
		arg = elem["name"] + " = " +  '"%s"' % val
		if elem["config_section"] == "cluster":
			cluster_data += arg + "\n"
		elif elem["config_section"] == "asbackup":
			asbackup_data += arg + "\n"
		elif elem["config_section"] == "asrestore":
			asrestore_data += arg + "\n"
	
	data = cluster_data + secret_data + asbackup_data + asrestore_data

	
	path = lib.temporary_path("toml")
	with open(path, "x") as conf:
		conf.write(data)
	
	return path

def setup_module(module):
	init_work_dir()
	sa.setup_secret_agent()

def teardown_module(module):
	sa.teardown_secret_agent()

SA_RSRC_PATH = os.path.join(sa.WORK_DIRECTORY, "resources")

SA_BACKUP_FILE_PATH = os.path.join(SA_RSRC_PATH, "b_secrets.json")
SA_BACKUP_RESOURCE = "backup"

SA_RESTORE_FILE_PATH = os.path.join(SA_RSRC_PATH, "r_secrets.json")
SA_RESTORE_RESOURCE = "restore"

SA_CONF_PATH = os.path.join(SA_RSRC_PATH, "conf.yaml")

def gen_secret_agent_files(backup_args:{str:any}=None, restore_args:{str:any}=None):
    resources = {}

    if backup_args:
        backup_secrets_json = sa.gen_secret_agent_secrets(backup_args)

        # if "encryption-key-file" in backup_args:
        #     backup_args["encryption-key-file"]

        with open(SA_BACKUP_FILE_PATH, "w+") as f:
                f.write(backup_secrets_json)
        resources[SA_BACKUP_RESOURCE] = SA_BACKUP_FILE_PATH

    if restore_args:
        restore_secrets_json = sa.gen_secret_agent_secrets(restore_args)
        with open(SA_RESTORE_FILE_PATH, "w+") as f:
                f.write(restore_secrets_json)
        resources[SA_RESTORE_RESOURCE] = SA_RESTORE_FILE_PATH

    secrets_conf = sa.gen_secret_agent_conf(resources=resources, tls_cfg="")

    with open(SA_CONF_PATH, "w+") as f:
        f.write(secrets_conf)

def setup_function(function):
    os.system("rm -rf " + SA_RSRC_PATH)
    os.system("mkdir " + SA_RSRC_PATH)

def test_restore_config_set():
	exp_argc, exp_argv = gen_args(RESTORE_SECRET_OPTIONS, "asrestore")
	
	expected_conf = RestoreConfigT()
	p_exp_conf = ctypes.POINTER(RestoreConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	restore_so.restore_config_set(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will fill
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	gen_secret_agent_files(
		restore_args={x["name"]: x["value"] for x in RESTORE_SECRET_OPTIONS}
	)

	sa_args = ["--sa-address", "%s:%s" % ("127.0.0.1", sa.SA_PORT)]
	argc, argv = gen_secret_args(
		input_list=RESTORE_SECRET_OPTIONS,
		prgm_name="asrestore",
		sa_args=sa_args,
		resource_name=SA_RESTORE_RESOURCE
	)

	conf = RestoreConfigT()
	p_conf = ctypes.POINTER(RestoreConfigT)(conf)
	c_argv = (ctypes.c_char_p * argc)(*argv)
	p_argv = ctypes.POINTER(ctypes.c_char_p)(c_argv)

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		restore_so.restore_config_set(argc, p_argv, p_conf)
	except Exception as e:
		raise e
	finally:
		agent.stop()
		print("*** Secret Agent Output ***")
		print(agent.output())
		print("*** End Secret Agent Output ***")
		agent.cleanup()

	assert expected_conf == conf

def test_backup_config_set():
	exp_argc, exp_argv = gen_args(BACKUP_SECRET_OPTIONS, "asbackup")

	expected_conf = BackupConfigT()
	p_exp_conf = ctypes.POINTER(BackupConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	backup_so.backup_config_set(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will file
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	gen_secret_agent_files(
		backup_args={x["name"]: x["value"] for x in BACKUP_SECRET_OPTIONS}
	)

	sa_args = ["--sa-address", "127.0.0.1", "--sa-port", sa.SA_PORT]
	argc, argv = gen_secret_args(
		input_list=BACKUP_SECRET_OPTIONS,
		prgm_name="asbackup",
		sa_args=sa_args,
		resource_name=SA_BACKUP_RESOURCE
	)

	conf = BackupConfigT()
	c_argv = (ctypes.c_char_p * argc)(*argv)
	p_argv = ctypes.POINTER(ctypes.c_char_p)(c_argv)
	p_conf = ctypes.POINTER(BackupConfigT)(conf)

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		backup_so.backup_config_set(argc, p_argv, p_conf)
	except Exception as e:
		raise e
	finally:
		agent.stop()
		print("*** Secret Agent Output ***")
		print(agent.output())
		print("*** End Secret Agent Output ***")
		agent.cleanup()

	assert expected_conf == conf

def test_backup_conf_file():
	exp_argc, exp_argv = gen_args(BACKUP_SECRET_OPTIONS, "asbackup")

	expected_conf = BackupConfigT()
	p_exp_conf = ctypes.POINTER(BackupConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	backup_so.backup_config_set(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will fill
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	gen_secret_agent_files(
		backup_args={x["name"]: x["value"] for x in BACKUP_SECRET_OPTIONS}
	)

	sa_args = 'sa-address = "127.0.0.1"\nsa-port = "%s"\n' % sa.SA_PORT
	conf_path = gen_secret_toml(
		BACKUP_SECRET_OPTIONS,
		SA_BACKUP_RESOURCE,
		sa_args
	)

	conf = BackupConfigT()
	p_conf = ctypes.POINTER(BackupConfigT)(conf)
	backup_so.backup_config_init(p_conf)

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		backup_so.config_from_file(p_conf, None, bytes(conf_path, "utf-8"), 0, True)
	except Exception as e:
		raise e
	finally:
		agent.stop()
		print("*** Secret Agent Output ***")
		print(agent.output())
		print("*** End Secret Agent Output ***")
		agent.cleanup()

	assert expected_conf == conf

def test_asrestore_conf_file():
	exp_argc, exp_argv = gen_args(RESTORE_SECRET_OPTIONS, "asrestore")

	expected_conf = RestoreConfigT()
	p_exp_conf = ctypes.POINTER(RestoreConfigT)(expected_conf)
	c_exp_argv = (ctypes.c_char_p * exp_argc)(*exp_argv)
	p_exp_argv = ctypes.POINTER(ctypes.c_char_p)(c_exp_argv)
	restore_so.restore_config_set(exp_argc, p_exp_argv, p_exp_conf)

	# configs that don't use secrets for these fields will fill
	# the ~file fields instead of the ~string fields
	# adjust the expected data to match configs that use secrets
	expected_conf.tls.castring = expected_conf.tls.cafile
	expected_conf.tls.cafile = None
	expected_conf.tls.keystring = expected_conf.tls.keyfile
	expected_conf.tls.keyfile = None
	expected_conf.tls.certstring = expected_conf.tls.certfile
	expected_conf.tls.certfile = None

	gen_secret_agent_files(
		restore_args={x["name"]: x["value"] for x in RESTORE_SECRET_OPTIONS}
	)

	sa_args = 'sa-address = "%s:%s"\n' % ("127.0.0.1", sa.SA_PORT)
	conf_path = gen_secret_toml(
		RESTORE_SECRET_OPTIONS,
		SA_RESTORE_RESOURCE,
		sa_args
	)

	conf = RestoreConfigT()
	p_conf = ctypes.POINTER(RestoreConfigT)(conf)
	restore_so.restore_config_init(p_conf)

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		restore_so.config_from_file(p_conf, None, bytes(conf_path, "utf-8"), 0, False)
	except Exception as e:
		raise e
	finally:
		agent.stop()
		print("*** Secret Agent Output ***")
		print(agent.output())
		print("*** End Secret Agent Output ***")
		agent.cleanup()

	assert expected_conf == conf