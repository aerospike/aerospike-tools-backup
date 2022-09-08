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
import math
import signal
import asyncio
import re
import docker

import aerospike
from aerospike_client import validate_client, get_client

WORK_DIRECTORY = "work"

PORT = 3000
NAMESPACE = "test"
SET = "test"
CLIENT_ATTEMPTS = 20

if sys.platform == "linux":
	USE_VALGRIND = False
else:
	USE_VALGRIND = False
DOCKER_CLIENT = docker.from_env()

# For tests with valgrind, asbackup is built from the source inside a docker image
DOCKER_IMAGE = "" # used for valgrind tests
VAL_SUP_FILE = "val.supp"
TOOLS_VERSION = "aerospike-tools-7.2.0.ubuntu18.04.x86_64.deb"
TOOLS_PACKAGE = "http://build.browser.qe.aerospike.com/citrusleaf/aerospike-tools/7.2.0/build/ubuntu-18.04/default/artifacts/{0}".format(TOOLS_VERSION)
    
NO_TTL = [0, -1, 4294967295] # these all mean "no TTL" in the test setup
GLOBALS = { "file_count": 0, "dir_mode": False }

random.seed(0)

def safe_sleep(secs):
	"""
	Sleeps, even in the presence of signals.
	"""
	start = time.time()
	end = start + secs

	while start < end:
		time.sleep(end - start)
		start = time.time()

def sync_wait(future):
	loop = asyncio.get_event_loop()
	return loop.run_until_complete(future)

async def kill_after(process, dt):
	await asyncio.sleep(dt)
	try:
		os.killpg(os.getpgid(process.pid), signal.SIGINT)
	except Exception:
		pass

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

def run(command, *options, do_async=False, pipe_stdout=None, pipe_stdin=None, env={}, RUN_IN_DOCKER=False):
	"""
	Runs the given command with the given options.
	"""
	print("Running", command, "with options", options)
	directory = absolute_path("../..")
	doc_command = []
	
	if RUN_IN_DOCKER:
		# Run valgrind based tests inside docker
		if DOCKER_IMAGE == "":
			print("NO DOCKER IMAGES FOUND")
			return -1
		doc_command = ("docker exec -t {0} sh -c".format(DOCKER_IMAGE)).split()
		USE_VALGRIND = True
		container_ip = DOCKER_CLIENT.containers.get(DOCKER_IMAGE).attrs["NetworkSettings"]["Gateway"]

		if USE_VALGRIND:
			val_args = "--track-fds=yes --leak-check=full --track-origins=yes --show-reachable=yes --suppressions={0}".\
				format(absolute_path(os.path.join(WORK_DIRECTORY, VAL_SUP_FILE)))
			command = doc_command + ["/usr/bin/valgrind {0} -v {1} -h {2} {3}".format(val_args, os.path.join("exec", command), container_ip, " ".join(options))]
	else:
		# use locally built asbackup for non in-docker mode tests 
		command = [os.path.join("test_target", command)] + list(options)

	print("Executing", command, "in", directory)
	if do_async:
		# preexec_fn is used to place the subprocess in a different process group
		return sync_wait(asyncio.create_subprocess_exec(*command, cwd=directory,
			preexec_fn=os.setpgrp,
			stdout=asyncio.subprocess.PIPE if pipe_stdout is None else pipe_stdout,
			stderr=asyncio.subprocess.PIPE,
			stdin=pipe_stdin,
			env=dict(os.environ, **env)))
	else:
		subprocess.check_call(command, cwd=directory,
				stdin=pipe_stdin,
				stdout=pipe_stdout,
				env=dict(os.environ, **env))
		return 0

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

def get_key_digest(set_name, key):
	"""
	Calculate the digest of the given key in the given set.
	"""
	return get_client().get_key_digest(NAMESPACE, set_name, key)

def test_record(set_name, key):
	"""
	Tests the existence of the given record.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	_, meta = get_client().exists((NAMESPACE, set_name, key))
	return meta is not None

def read_record(set_name, key):
	"""
	Reads the given record.
	"""
	validate_client()
	force_unicode(set_name, "Please use Unicode set names")
	meta_key, meta, record = get_client().get((NAMESPACE, set_name, key))
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
	scan = get_client().scan(NAMESPACE, set_name)
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

	get_client().put((NAMESPACE, set_name, key), record, meta, policy)
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
	assert get_client().udf_put(path, aerospike.UDF_TYPE_LUA) == 0, \
			"Unexpected error while storing UDF file"
	return path

def get_udf_file(file_name):
	"""
	Retrieves the UDF file with the given name from the cluster.
	"""
	validate_client()
	print("getting UDF", file_name)
	return get_client().udf_get(file_name, aerospike.UDF_TYPE_LUA)

def validate_index_check(set_name, bin_name, value):
	"""
	Validates the string parameters for the index query functions.
	"""
	force_unicode(set_name, "Please use Unicode set names")
	force_unicode(bin_name, "Please use Unicode index bin_names")
	force_unicode(value, "Please use Unicode query values")

def check_simple_index(set_name, bin_name, value):
	"""
	Tests the presence of a simple secondary index by making an "equals" query.
	"""
	validate_index_check(set_name, bin_name, value)
	query = get_client().query(NAMESPACE, set_name)
	query.where(aerospike.predicates.equals(bin_name, value))
	query.results()

def check_geo_index(set_name, bin_name, value):
	"""
	Tests the presence of a geo index by making a region query.
	"""
	validate_index_check(set_name, bin_name, value)
	query = get_client().query(NAMESPACE, set_name)
	# XXX - geo index requires string bin names
	query.where(aerospike.predicates.geo_within_radius(str(bin_name), value[0], value[1], 10.0))
	query.results()

def check_complex_index(set_name, bin_name, index_type, value):
	"""
	Tests the presence of a complex secondary index by making a "contains" query.
	"""
	validate_index_check(set_name, bin_name, value)
	query = get_client().query(NAMESPACE, set_name)
	query.where(aerospike.predicates.contains(bin_name, index_type, value))
	query.results()

def check_list_index(set_name, bin_name, value):
	"""
	Test presence of a complex list secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, bin_name, aerospike.INDEX_TYPE_LIST, value)

def check_map_key_index(set_name, bin_name, value):
	"""
	Test presence of a complex map key secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, bin_name, aerospike.INDEX_TYPE_MAPKEYS, value)

def check_map_value_index(set_name, bin_name, value):
	"""
	Test presence of a complex map value secondary index by making a
	"contains" query.
	"""
	check_complex_index(set_name, bin_name, aerospike.INDEX_TYPE_MAPVALUES, value)

def validate_index_creation(set_name, bin_name, index_name):
	"""
	Validates the string parameters for the index creation functions.
	"""
	force_unicode(set_name, "Please use Unicode set names")
	force_unicode(bin_name, "Please use Unicode index bin_names")
	force_unicode(index_name, "Please use Unicode index names")

def create_integer_index(set_name, bin_name, index_name):
	"""
	Creates an integer index.
	"""
	print("create integer index", index_name)
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_integer_create(NAMESPACE, set_name, bin_name, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_list_index(set_name, bin_name, index_name):
	"""
	Creates an integer list index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_list_create(NAMESPACE, set_name, bin_name, aerospike.INDEX_NUMERIC, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_map_key_index(set_name, bin_name, index_name):
	"""
	Creates an integer map key index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_map_keys_create(NAMESPACE, set_name, bin_name, \
					aerospike.INDEX_NUMERIC, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_integer_map_value_index(set_name, bin_name, index_name):
	"""
	Creates an integer map value index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_map_values_create(NAMESPACE, set_name, bin_name, \
					aerospike.INDEX_NUMERIC, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_index(set_name, bin_name, index_name):
	"""
	Creates a string index.
	"""
	print("create string index", index_name)
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_string_create(NAMESPACE, set_name, bin_name, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_geo_index(set_name, bin_name, index_name):
	"""
	Creates a geo index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	# XXX - geo index requires string bin names
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_geo2dsphere_create(NAMESPACE, set_name, str(bin_name), index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_list_index(set_name, bin_name, index_name):
	"""
	Creates a string list index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_list_create(NAMESPACE, set_name, bin_name, aerospike.INDEX_STRING, \
					index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_map_key_index(set_name, bin_name, index_name):
	"""
	Creates a string map key index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_map_keys_create(NAMESPACE, set_name, bin_name, \
					aerospike.INDEX_STRING, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

def create_string_map_value_index(set_name, bin_name, index_name):
	"""
	Creates a string map value index.
	"""
	validate_index_creation(set_name, bin_name, index_name)
	ret = -1
	for _ in range(CLIENT_ATTEMPTS):
		try:
			ret = get_client().index_map_values_create(NAMESPACE, set_name, bin_name, \
					aerospike.INDEX_STRING, index_name)
			break
		except aerospike.exception.IndexFoundError:
			# found the index in the database, meaning it wasn't fully deleted, pause and try again
			safe_sleep(0.5)
	assert ret == 0, "Unexpected error while creating index"
	GLOBALS["indexes"].append(index_name)

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

def install_valgrind():
	docker_images = DOCKER_CLIENT.containers.list()
	if len(docker_images) == 0:
		print("NO DOCKER IMAGE FOUND")
		return -1
	cmd = "docker exec -t {0} sh -c".format(docker_images[0].name).split()
	try:
		cmd_check_install = [" valgrind --version"]
		subprocess.check_call(cmd + cmd_check_install)
	except: # valgrind need to be installed
		cmd_install = "apt update && apt install -y valgrind && mkdir test_dir " # && apt install -y wget && wget {0} && dpkg -i {1} && mkdir test_dir".\
				#format(TOOLS_PACKAGE, TOOLS_VERSION)
		cmd.append(str(cmd_install))
		try:
			subprocess.check_call(cmd)
			# make valgrind supp file accessible to docker image
			subprocess.check_call("cp {0} {1}".format(absolute_path(VAL_SUP_FILE), absolute_path(WORK_DIRECTORY)))
		except:
			print("Exception occured during installing valgrind and other packages.")
	DOCKER_IMAGE = docker_images[0].name

def check_packages_installed():
	if DOCKER_IMAGE == "":
		print("NO DOCKER IMAGE FOUND")
		return -1
	cmd = "docker exec -t {0} sh -c".format(DOCKER_IMAGE).split()
	try:
		cmd_check_install = [" valgrind --version && exec/asbackup --version"]
		subprocess.check_call(cmd + cmd_check_install)
	except: # valgrind need to be installed
		print("Valgrind and asbackup have not installed properly!")
		return False
	return True

def parse_val_logs(log_file):
    res = True
    HEAP_SUMMARY = re.compile("in use at exit: \d+ bytes")
    ERROR_SUMMARY = re.compile("ERROR SUMMARY: \d+ errors")
    heap_sum = []
    error = []
    try:
        with open(log_file, "r") as f:
            for line in f.readlines():
                heap_sum = HEAP_SUMMARY.findall(line)
                if len(heap_sum) >= 1:
                    unfree_heap = re.findall(r'\d+', heap_sum[0])
                    if unfree_heap[0] != "0":
                        print("VALGRIND HEAP SUMMARY: {0} bytes in use at exit".format(unfree_heap[0]))
                        res = False
                
                error = ERROR_SUMMARY.findall(line)
                if len(error) >= 1:
                    tot_errors = re.findall(r'\d+', error[0])
                    if tot_errors[0] != "0":
                        print("VALGRIND ERROR SUMMARY: {0} errors".format(tot_errors[0]))
                        res = False
    except Exception as e:
        print("Unexpected error occured while parsing valgrind logs ", str(e))
        res = False

    os.remove(log_file)
    return res

if __name__ == "__main__":
	pass

