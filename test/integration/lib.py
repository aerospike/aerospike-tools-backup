# coding=UTF-8

"""
Utility functions for automated tests.
"""

import sys
import os
import os.path
import subprocess
import time
import codecs
import random
import string
import math
import signal

import docker

import aerospike
from aerospike import predexp as predexp

PORT = 3000
NAMESPACE = "test"
SET = "test"
CLIENT_ATTEMPTS = 20
WORK_DIRECTORY = "work"
STATE_DIRECTORIES = ["state-1", "state-2"]
UDF_DIRECTORIES = ["udf-1", "udf-2"]
FAKE_TIME_FILE = "clock_gettime.txt"
SHOW_ASD_OUTPUT = False

if sys.platform == "linux":
	USE_VALGRIND = True
else:
	USE_VALGRIND = False
DOCKER_CLIENT = docker.from_env()

NO_TTL = [0, -1, 4294967295] # these all mean "no TTL" in the test setup
GLOBALS = {"file_count": 0, "dir_mode": False}

random.seed(0)

def graceful_exit(sig, frame):
	signal.signal(signal.SIGINT, g_orig_int_handler)
	stop()
	os.kill(os.getpid(), signal.SIGINT)

g_orig_int_handler = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, graceful_exit)

def safe_sleep(secs):
	"""
	Sleeps, even in the presence of signals.
	"""
	start = time.time()
	end = start + secs

	while start < end:
		time.sleep(end - start)
		start = time.time()

def enable_dir_mode():
	"""
	Enables directory mode.
	"""
	GLOBALS["dir_mode"] = True

def disable_dir_mode():
	"""
	Disables directory mode.
	"""
	GLOBALS["dir_mode"] = False

def is_dir_mode():
	"""
	Tests for directory mode.
	"""
	return GLOBALS["dir_mode"]

def eq(value1, value2):
	"""
	Compares two values. Converts Unicode values to UTF-8 first.
	"""
	if isinstance(value1, str):
		value1 = value1.encode("UTF-8")

	if isinstance(value2, str):
		value2 = value2.encode("UTF-8")

	if isinstance(value1, float) and isinstance(value2, float) and math.isnan(value1):
		return math.isnan(value2)

	# XXX - geo objects don't support equality
	if isinstance(value1, aerospike.GeoJSON) and isinstance(value2, aerospike.GeoJSON):
		return str(value1) == str(value2)

	return value1 == value2

def force_unicode(value, message):
	"""
	Make sure that the given string is a Unicode string.
	"""
	assert not isinstance(value, str) or isinstance(value, str), message

def absolute_path(*path):
	"""
	Turns the given path into an absolute path.
	"""
	if len(path) == 1 and os.path.isabs(path[0]):
		return path[0]

	return os.path.abspath(os.path.join(os.path.dirname(__file__), *path))

def remove_dir(path):
	"""
	Removes a directory.
	"""
	print("Removing directory", path)

	for root, dirs, files in os.walk(path, False):
		for name in dirs:
			os.rmdir(os.path.join(root, name))

		for name in files:
			os.remove(os.path.join(root, name))

	os.rmdir(path)

def remove_work_dir():
	"""
	Removes the work directory.
	"""
	print("Removing work directory")
	work = absolute_path(WORK_DIRECTORY)

	if os.path.exists(work):
		remove_dir(work)

def remove_state_dirs():
	"""
	Removes the runtime state directories.
	"""
	print("Removing state directories")

	for walker in STATE_DIRECTORIES:
		state = absolute_path(WORK_DIRECTORY, walker)

		if os.path.exists(state):
			remove_dir(state)

	for walker in UDF_DIRECTORIES:
		udf = absolute_path(WORK_DIRECTORY, walker)

		if os.path.exists(udf):
			remove_dir(udf)

def init_work_dir():
	"""
	Creates an empty work directory.
	"""
	remove_work_dir()
	print("Creating work directory")
	work = absolute_path(WORK_DIRECTORY)
	os.mkdir(work, 0o755)

def init_state_dirs():
	"""
	Creates empty state directories.
	"""
	remove_state_dirs()
	print("Creating state directories")

	for walker in STATE_DIRECTORIES:
		state = absolute_path(os.path.join(WORK_DIRECTORY, walker))
		os.mkdir(state, 0o755)
		smd = absolute_path(os.path.join(WORK_DIRECTORY, walker, "smd"))
		os.mkdir(smd, 0o755)

	for walker in UDF_DIRECTORIES:
		udf = absolute_path(os.path.join(WORK_DIRECTORY, walker))
		os.mkdir(udf, 0o755)

def write_file(path, content):
	"""
	Creates a file with the given path and content.
	"""
	force_unicode(content, "Please use Unicode strings")

	with codecs.open(path, "w", "UTF-8") as file_obj:
		file_obj.write(content)

def temporary_path(extension):
	"""
	Generates a path to a temporary file in the work directory using the
	given extension.
	"""
	file_name = "tmp-" + ("%05d" % GLOBALS["file_count"]) + "." + extension
	GLOBALS["file_count"] += 1
	return absolute_path(os.path.join(WORK_DIRECTORY, file_name))

def run(command, *options):
	"""
	Runs the given command with the given options.
	"""
	print("Running", command, "with options", options)
	directory = absolute_path("../..")
	command = [os.path.join("bin", command)] + list(options)

	if USE_VALGRIND:
		command = ["./val.sh"] + command

	print("Executing", command, "in", directory)
	subprocess.check_call(command, cwd=directory)

def backup(*options):
	"""
	Runs asbackup with the given options.
	"""
	print("Running asbackup")
	run("asbackup", *options)

def restore(*options):
	"""
	Runs asrestore with the given options.
	"""
	print("Running asrestore")
	run("asrestore", *options)

def set_fake_time(seconds):
	"""
	Writes the given number (seconds since epoch) to the fake time file, from
	where it is picked up by the clock_gettime() interceptor.
	"""
	with codecs.open(absolute_path(WORK_DIRECTORY, FAKE_TIME_FILE), "w", "UTF-8") as file_obj:
		file_obj.write(str(seconds) + "\n")

def unset_fake_time():
	"""
	Removes the fake time file, which deactivates the clock_gettime()
	interceptor.
	"""
	fake_time_file = absolute_path(WORK_DIRECTORY, FAKE_TIME_FILE)

	if os.path.exists(fake_time_file):
		os.remove(fake_time_file)

def init_interceptor():
	"""
	Compiles the clock_gettime() interceptor that's injected into asd using
	LD_PRELOAD. Used for controlling asd's idea of the current time when
	testing TTLs.
	"""
	interceptor = absolute_path(WORK_DIRECTORY, "clock_gettime.so")
	subprocess.check_call(["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-std=c99", \
			"-D_GNU_SOURCE", "-fpic", "-shared", \
			"-o", interceptor, absolute_path("clock_gettime.c")])

	unset_fake_time()
	return interceptor

def create_conf_file(temp_file, base, peer_addr, index):
	"""
	Create an Aerospike configuration file from the given template.
	"""
	with codecs.open(temp_file, "r", "UTF-8") as file_obj:
		temp_content = file_obj.read()

	params = {
		"state_directory": "/opt/aerospike/work/state-" + str(index),
		"udf_directory": "/opt/aerospike/work/udf-" + str(index),
		"service_port": str(base),
		"fabric_port": str(base + 1),
		"heartbeat_port": str(base + 2),
		"info_port": str(base + 3),
		"peer_connection": "# no peer connection" if not peer_addr \
				else "mesh-seed-address-port " + peer_addr[0] + " " + str(peer_addr[1] + 2)
	}

	temp = string.Template(temp_content)
	conf_content = temp.substitute(params)
	conf_file = temporary_path("conf")

	with codecs.open(conf_file, "w", "UTF-8") as file_obj:
		file_obj.write(conf_content)

	return conf_file

def get_file(path, base=None):
	if base is None:
		return os.path.basename(os.path.realpath(path))
	elif path.startswith(base):
		if path[len(base)] == '/':
			return path[len(base) + 1:]
		else:
			return path[len(base):]
	else:
		raise Exception('path %s is not in the directory %s' % (path, base))

def get_dir(path):
	return os.path.dirname(os.path.realpath(path))

def start(keep_work_dir=False):
	"""
	Starts an asd process with the local aerospike.conf and connects the client to it.
	"""
	print("Starting asd")

	if not keep_work_dir:
		init_work_dir()

	init_state_dirs()
	interceptor = init_interceptor()

	"""
	search_path = [os.sep + os.path.join("usr", "bin")]

	if "ASREPO" in os.environ:
		repo = absolute_path(os.environ["ASREPO"])
		uname = os.uname()
		search_path = [os.path.join(repo, "target", uname[0] + "-" + uname[4], "bin")] + search_path

	print("asd search path is", search_path)

	for path in search_path:
		asd_path = os.path.join(path, "asd")

		if os.path.exists(asd_path):
			break
	else:
		raise Exception("No asd executable found")

	if not SHOW_ASD_OUTPUT:
		dev_null = open(os.devnull, "w")
		redirect = {"stdout": dev_null, "stderr": subprocess.STDOUT}
	else:
		redirect = {}
	"""

	temp_file = absolute_path("aerospike.conf")
	# TODO
	#os.environ["LD_PRELOAD"] = interceptor
	mount_dir = absolute_path(WORK_DIRECTORY)

	first_base = 3000
	first_ip = None
	for index in range(1, 3):
		base = first_base + 1000 * (index - 1)
		conf_file = create_conf_file(temp_file, base,
				None if index == 1 else (first_ip, first_base),
				index)
		cmd = '/usr/bin/asd --foreground --config-file %s --instance %s' % ('/opt/aerospike/work/' + get_file(conf_file, base=mount_dir), str(index - 1))
		print('running in docker: %s' % cmd)
		container = DOCKER_CLIENT.containers.run("aerospike/aerospike-server",
				command=cmd,
				ports={
					str(base) + '/tcp': str(base),
					str(base + 1) + '/tcp': str(base + 1),
					str(base + 2) + '/tcp': str(base + 2),
					str(base + 3) + '/tcp': str(base + 3)
				},
				volumes={ mount_dir: { 'bind': '/opt/aerospike/work', 'mode': 'rw' } },
				tty=True, detach=True, name='aerospike-%d' % (index))
		GLOBALS["asd-" + str(index)] = container
		if index == 1:
			container.reload()
			first_ip = container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]

	#del os.environ["LD_PRELOAD"]

	print("Connecting client")
	config = {"hosts": [("127.0.0.1", PORT)]}

	for attempt in range(CLIENT_ATTEMPTS):
		try:
			GLOBALS["client"] = aerospike.client(config).connect()
			break
		except Exception:
			if attempt < CLIENT_ATTEMPTS - 1:
				safe_sleep(.2)
			else:
				raise

	# initialize the list of indices, which will contain a list of the names of
	# all indices created
	GLOBALS["indexes"] = []
	GLOBALS["sets"] = []

	print("Client connected")

def stop(keep_work_dir=False):
	"""
	Disconnects the client and stops the running asd process.
	"""
	print("Disconnecting client")

	if "client" not in GLOBALS:
		print("No connected client")
	else:
		GLOBALS["client"].close()
		GLOBALS.pop("client")

	print("Stopping asd")

	for index in range(1, 3):
		asd = "asd-" + str(index)

		if asd not in GLOBALS:
			print("No running", asd, "process")
		else:
			GLOBALS[asd].stop()
			GLOBALS[asd].remove()
			GLOBALS.pop(asd)

	remove_state_dirs()

	if not keep_work_dir:
		remove_work_dir()

def reset():
	"""
	Reset: disconnects the client, stops asd, restarts asd, reconnects the client.
	"""
	print("resetting the database")
	
	# truncate the set
	for set_name in GLOBALS["sets"]:
		if set_name is not None:
			set_name = set_name.strip()
		GLOBALS["client"].truncate(NAMESPACE, None if not set_name else set_name, 0)
	GLOBALS["sets"] = []

	# delete all udfs
	udfs = []
	for udf in GLOBALS["client"].udf_list():
		udfs.append(udf)
	for udf in udfs:
		GLOBALS["client"].udf_remove(udf["name"])

	# delete all indexes
	for index in GLOBALS["indexes"]:
		try:
			GLOBALS["client"].index_remove(NAMESPACE, index)
		except aerospike.exception.IndexNotFound:
			# the index may not actually be there if we are only backing up certain
			# sets, but this is ok, so fail silently
			pass
	GLOBALS["indexes"] = []

def validate_client():
	"""
	Make sure that there is a client.
	"""
	assert "client" in GLOBALS, "No client"

def get_key_digest(set_name, key):
	"""
	Calculate the digest of the given key in the given set.
	"""
	return GLOBALS["client"].get_key_digest(NAMESPACE, set_name, key)

def test_record(set_name, key):
	"""
	Tests the existence of the given record.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	_, meta = GLOBALS["client"].exists((NAMESPACE, set_name, key))
	return meta is not None

def read_record(set_name, key):
	"""
	Reads the given record.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	meta_key, meta, record = GLOBALS["client"].get((NAMESPACE, set_name, key))
	assert meta, "Key %s does not have a record" % key
	meta_ttl = meta["ttl"]

	if meta_ttl in NO_TTL:
		meta_ttl = None

	return (meta_key[2], meta_ttl, record)

def read_all_records(set_name):
	"""
	Reads all records from the given set.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	scan = GLOBALS["client"].scan(NAMESPACE, set_name)
	records = {}

	for (meta_key, meta, record) in scan.results():
		meta_ttl = meta["ttl"]

		if meta_ttl in NO_TTL:
			meta_ttl = None

		records[str(meta_key[3]).encode().hex()] = (meta_key[2], meta_ttl, record)

	return records

def write_record(set_name, key, bin_names, values, send_key=False, ttl=None):
	"""
	Writes the given values to the given bins in the given record.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	assert len(bin_names) == len(values), "Invalid number of bin names or values (%d vs. %d)" % \
			(len(bin_names), len(values))

	meta = {"ttl": 0 if ttl is None else ttl}
	policy = {"key": aerospike.POLICY_KEY_SEND if send_key else aerospike.POLICY_KEY_DIGEST}
	record = {}

	for bin_name, value in zip(bin_names, values):
		force_unicode(bin_name, "Please use Unicode bin names")
		force_unicode(value, "Please use Unicode bin values")
		record[bin_name] = value

	GLOBALS["client"].put((NAMESPACE, set_name, key), record, meta, policy)
	if set_name not in GLOBALS["sets"]:
		GLOBALS["sets"].append(set_name)

def validate_record(key, record, bin_names, values):
	"""
	Ensure that the given record has the given bins with the given values.
	"""
	assert len(bin_names) == len(values), "Invalid number of bin names or values (%d vs. %d)" % \
			(len(bin_names), len(values))
	assert len(bin_names) == len(record), "Key %s has an invalid number of bins (%d vs. %d)" % \
			(key, len(record), len(bin_names))

	for bin_name, value in zip(bin_names, values):
		force_unicode(bin_name, "Please use Unicode bin names")
		force_unicode(value, "Please use Unicode bin values")
		assert str(bin_name) in record, "Key %s does not have a \"%s\" bin" % (key, bin_name)
		assert eq(value, record[str(bin_name)]), "Key %s has an invalid \"%s\" bin (%s vs. %s)" % \
					(key, bin_name, record[str(bin_name)], value)

def validate_meta(key, meta_key, meta_ttl, expect_key=False, expected_ttl=None):
	"""
	Ensure that the metadata does or does not contain a key or TTL and that
	the respective values, if present, are correct.
	"""
	if not expect_key:
		assert meta_key is None, "Key %s unexpectedly has a metadata key (%s)" % \
				(key, meta_key)
	else:
		assert meta_key is not None, "Key %s does not have a metadata key" % key
		assert eq(meta_key, key), "Key %s has an invalid metadata key (%s)" % (key, meta_key)

	if not expected_ttl:
		assert meta_ttl is None, "Key %s unexpectedly has a TTL (%s)" % (key, meta_ttl)
	else:
		assert meta_ttl is not None, "Key %s does not have a TTL" % key
		assert meta_ttl >= expected_ttl[0] and meta_ttl <= expected_ttl[1], \
				"Key %s has an invalid TTL (%s vs. %s)" % (key, meta_ttl, expected_ttl)

# XXX - geo objects don't support equality
def geo_to_string(value):
	"""
	Convert geo objects to strings, because they don't support equality.
	"""
	if isinstance(value, list):
		return [geo_to_string(x) for x in value]

	if isinstance(value, dict):
		result = {}

		for dict_key, dict_value in value.items():
			result[dict_key] = geo_to_string(dict_value)

		return result

	if isinstance(value, aerospike.GeoJSON):
		return str(value)

	return value

def put_udf_file(content):
	"""
	Stores a UDF file with the given name and content on the cluster.
	"""
	path = temporary_path("lua")
	write_file(path, content)
	validate_client()
	assert GLOBALS["client"].udf_put(path, aerospike.UDF_TYPE_LUA) == 0, \
			"Unexpected error while storing UDF file"
	return path

def get_udf_file(file_name):
	"""
	Retrieves the UDF file with the given name from the cluster.
	"""
	validate_client()
	return GLOBALS["client"].udf_get(file_name, aerospike.UDF_TYPE_LUA)

def validate_index_check(set_name, path, value):
	"""
	Validates the string parameters for the index query functions.
	"""
	force_unicode(set_name, "Please use Unicode set names")
	force_unicode(path, "Please use Unicode index paths")
	force_unicode(value, "Please use Unicode query values")

def check_simple_index(set_name, path, value):
	"""
	Tests the presence of a simple secondary index by making an "equals" query.
	"""
	validate_index_check(set_name, path, value)
	query = GLOBALS["client"].query(NAMESPACE, set_name)
	query.where(aerospike.predicates.equals(path, value))
	query.results()

def check_geo_index(set_name, path, value):
	"""
	Tests the presence of a geo index by making a region query.
	"""
	validate_index_check(set_name, path, value)
	query = GLOBALS["client"].query(NAMESPACE, set_name)
	# XXX - geo index requires string bin names
	query.where(aerospike.predicates.geo_within_radius(str(path), value[0], value[1], 10.0))
	query.results()

def check_complex_index(set_name, path, index_type, value):
	"""
	Tests the presence of a complex secondary index by making a "contains" query.
	"""
	validate_index_check(set_name, path, value)
	query = GLOBALS["client"].query(NAMESPACE, set_name)
	query.where(aerospike.predicates.contains(path, index_type, value))
	query.results()

def check_list_index(set_name, path, value):
	"""
	Test presence of a complex list secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, path, aerospike.INDEX_TYPE_LIST, value)

def check_map_key_index(set_name, path, value):
	"""
	Test presence of a complex map key secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, path, aerospike.INDEX_TYPE_MAPKEYS, value)

def check_map_value_index(set_name, path, value):
	"""
	Test presence of a complex map value secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, path, aerospike.INDEX_TYPE_MAPVALUES, value)

def validate_index_creation(set_name, path, index_name):
	"""
	Validates the string parameters for the index creation functions.
	"""
	force_unicode(set_name, "Please use Unicode set names")
	force_unicode(path, "Please use Unicode index paths")
	force_unicode(index_name, "Please use Unicode index names")

def create_integer_index(set_name, path, index_name):
	"""
	Creates an integer index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_integer_create(NAMESPACE, set_name, path, index_name) == 0, \
			"Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_list_index(set_name, path, index_name):
	"""
	Creates an integer list index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_list_create(NAMESPACE, set_name, path, aerospike.INDEX_NUMERIC, \
			index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_map_key_index(set_name, path, index_name):
	"""
	Creates an integer map key index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_map_keys_create(NAMESPACE, set_name, path, \
			aerospike.INDEX_NUMERIC, index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_map_value_index(set_name, path, index_name):
	"""
	Creates an integer map value index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_map_values_create(NAMESPACE, set_name, path, \
			aerospike.INDEX_NUMERIC, index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_index(set_name, path, index_name):
	"""
	Creates a string index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_string_create(NAMESPACE, set_name, path, index_name) == 0, \
			"Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_geo_index(set_name, path, index_name):
	"""
	Creates a geo index.
	"""
	validate_index_creation(set_name, path, index_name)
	# XXX - geo index requires string bin names
	assert GLOBALS["client"].index_geo2dsphere_create(NAMESPACE, set_name, str(path), \
			index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_list_index(set_name, path, index_name):
	"""
	Creates a string list index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_list_create(NAMESPACE, set_name, path, aerospike.INDEX_STRING, \
			index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_map_key_index(set_name, path, index_name):
	"""
	Creates a string map key index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_map_keys_create(NAMESPACE, set_name, path, \
			aerospike.INDEX_STRING, index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_map_value_index(set_name, path, index_name):
	"""
	Creates a string map value index.
	"""
	validate_index_creation(set_name, path, index_name)
	assert GLOBALS["client"].index_map_values_create(NAMESPACE, set_name, path, \
			aerospike.INDEX_STRING, index_name) == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def backup_to_file(path, *options):
	"""
	Backup to the given file using the default options plus the given options.
	"""
	backup("--output-file", path, \
			"--remove-files", \
			"--namespace", NAMESPACE, \
			*options)

def restore_from_file(path, *options):
	"""
	Restore from the given file using the default options plus the given options.
	"""
	restore("--input", path, \
			*options)

def backup_to_directory(path, *options):
	"""
	Backup to the given directory using the default options plus the given options.
	"""
	backup("--directory", path, \
			"--remove-files", \
			"--namespace", NAMESPACE, \
			*options)

def restore_from_directory(path, *options):
	"""
	Restore from the given file using the default options plus the given options.
	"""
	restore("--directory", path, \
			*options)

def backup_and_restore(filler, preparer, checker, backup_opts=None, restore_opts=None, \
		restore_delay=None, cleanup=None):
	"""
	Do one backup-restore cycle.
	"""
	if backup_opts is None:
		backup_opts = []

	if restore_opts is None:
		restore_opts = []


	start()
	for comp_enc_mode in [
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]:
		context = {}
		try:
			filler(context)

			if GLOBALS["dir_mode"]:
				path = temporary_path("dir")
				backup_to_directory(path, *(backup_opts + comp_enc_mode))
			else:
				path = temporary_path("asb")
				backup_to_file(path, *(backup_opts + comp_enc_mode))

			indexes = GLOBALS["indexes"]
			reset()

			# give SMD time to get deleted
			safe_sleep(0.5)

			# restart the server/client
			#stop(True)
			#start(True)

			if restore_delay is not None:
				safe_sleep(restore_delay)

			if preparer is not None:
				preparer(context)

			if GLOBALS["dir_mode"]:
				restore_from_directory(path, *(restore_opts + comp_enc_mode))
			else:
				restore_from_file(path, *(restore_opts + comp_enc_mode))
			# give SMD time to be restored
			safe_sleep(0.5)

			checker(context)

			# restore the indices restored by asrestore before resetting
			GLOBALS["indexes"] = indexes
			reset()
		except Exception:
			if cleanup is not None:
				cleanup(context)
			stop(True)
			raise
		else:
			if cleanup is not None:
				cleanup(context)
	stop()

def random_alphameric():
	"""
	Generates a random alphanumeric character.
	"""
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return alphabet[random.randint(0, len(alphabet) - 1)]

def random_ascii():
	"""
	Generates a random ASCII character.
	"""
	return chr(random.randint(0, 127))

def random_unicode():
	"""
	Generates a random 16-bit Unicode character.
	"""
	return chr(random.randint(0, 0xd7ff))

def random_ascii_no_nul():
	"""
	Generates a random ASCII character, except NUL.
	"""
	return chr(random.randint(1, 127))

def random_unicode_no_nul():
	"""
	Generates a random 16-bit Unicode character, except NUL. 0x0000 is the only
	Unicode character that results in a NUL byte in the UTF-8 encoding. So, it's
	enough to disallow that.
	"""
	res = random.randint(1, 0xd7ff)
	return chr(res)

CHAR_TYPE_ALPHAMERIC = 0
CHAR_TYPE_ASCII = 1
CHAR_TYPE_UNICODE = 2
CHAR_TYPE_ASCII_NO_NUL = 3
CHAR_TYPE_UNICODE_NO_NUL = 4

GENERATOR_FUNCTIONS = {
	CHAR_TYPE_ALPHAMERIC: random_alphameric,
	CHAR_TYPE_ASCII: random_ascii,
	CHAR_TYPE_UNICODE: random_unicode,
	CHAR_TYPE_ASCII_NO_NUL: random_ascii_no_nul,
	CHAR_TYPE_UNICODE_NO_NUL: random_unicode_no_nul
}

def identifier(max_len, char_type=CHAR_TYPE_ALPHAMERIC):
	"""
	Generates a Unicode string composed of characters of the given type. Makes sure that
	the encoded string doesn't exceed the given maximal length.
	"""
	result = ""

	while True:
		char = GENERATOR_FUNCTIONS[char_type]()

		if len((result + char).encode("UTF-8")) > max_len:
			return result

		result += char

def space_framed_identifier(max_len, char_type=CHAR_TYPE_ALPHAMERIC):
	"""
	Generates an identifier that starts and ends with a space character.
	"""
	return " " + identifier(max_len - 2, char_type) + " "

def line_feed_framed_identifier(max_len, char_type=CHAR_TYPE_ALPHAMERIC):
	"""
	Generates an identifier that starts and ends with a new line character.
	"""
	return "\n" + identifier(max_len - 2, char_type) + "\n"

def identifier_with_space(max_len, char_type=CHAR_TYPE_ALPHAMERIC):
	"""
	Generates an identifier that contains a space character.
	"""
	basic = identifier(max_len - 1, char_type)
	return basic[:2] + " " + basic[2:]

def identifier_with_line_feed(max_len, char_type=CHAR_TYPE_ALPHAMERIC):
	"""
	Generates an identifier that contains a new line character.
	"""
	basic = identifier(max_len - 1, char_type)
	return basic[:2] + "\n" + basic[2:]

def identifier_variations(max_len, allow_nul=True):
	"""
	Generates a whole bunch of special-case identifiers.
	"""
	variations = []
	variations.append("")
	variations.append(" ")
	variations.append("  ")
	variations.append("\n")
	variations.append("\n\n")

	char_types = [CHAR_TYPE_ALPHAMERIC]

	if allow_nul:
		char_types += [CHAR_TYPE_ASCII, CHAR_TYPE_UNICODE]
	else:
		char_types += [CHAR_TYPE_ASCII_NO_NUL, CHAR_TYPE_UNICODE_NO_NUL]

	for char_type in char_types:
		tmp = identifier(1, char_type)

		if len(tmp) > 0:
			variations.append(tmp)

		variations.append(identifier(max_len / 2, char_type))
		variations.append(identifier(max_len, char_type))
		variations.append(space_framed_identifier(max_len / 2, char_type))
		variations.append(space_framed_identifier(max_len, char_type))
		variations.append(line_feed_framed_identifier(max_len / 2, char_type))
		variations.append(line_feed_framed_identifier(max_len, char_type))
		variations.append(identifier_with_space(max_len / 2, char_type))
		variations.append(identifier_with_space(max_len, char_type))
		variations.append(identifier_with_line_feed(max_len / 2, char_type))
		variations.append(identifier_with_line_feed(max_len, char_type))

	return variations

def index_variations(max_len):
	"""
	Generates a whole bunch of identifiers that are suitable for index commands.
	"""
	variations = []
	variations.append(" ")
	variations.append("  ")
	variations.append(identifier(1, CHAR_TYPE_ALPHAMERIC))
	variations.append(identifier(max_len / 2, CHAR_TYPE_ALPHAMERIC))
	variations.append(identifier(max_len, CHAR_TYPE_ALPHAMERIC))
	variations.append(space_framed_identifier(max_len / 2, CHAR_TYPE_ALPHAMERIC))
	variations.append(space_framed_identifier(max_len, CHAR_TYPE_ALPHAMERIC))
	variations.append(identifier_with_space(max_len / 2, CHAR_TYPE_ALPHAMERIC))
	variations.append(identifier_with_space(max_len, CHAR_TYPE_ALPHAMERIC))
	return variations

if __name__ == "__main__":
	pass
