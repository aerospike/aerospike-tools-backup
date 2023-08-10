# coding=UTF-8

"""
Aerospike server management utilities.
"""

import aerospike
import atexit
import codecs
import docker
import os
import signal
import string
import subprocess
import sys

from aerospike_client import get_client, set_client
import lib

# the number of server nodes to use
N_NODES = 2

WORK_DIRECTORY = lib.WORK_DIRECTORY

SERVER_IMAGE = "aerospike/aerospike-server"


STATE_DIRECTORIES = ["state-%d" % i for i in range(1, N_NODES+1)]
UDF_DIRECTORIES = ["udf-%d" % i for i in range(1, N_NODES+1)]

LUA_DIRECTORY = lib.absolute_path(WORK_DIRECTORY, "lua")

FAKE_TIME_FILE = "clock_gettime.txt"

USE_DOCKER_SERVERS = True
if USE_DOCKER_SERVERS:
	DOCKER_CLIENT = docker.from_env()
GLOBALS = { "running": False }

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
	conf_file = lib.temporary_path("conf")

	with codecs.open(conf_file, "w", "UTF-8") as file_obj:
		file_obj.write(conf_content)

	return conf_file

def remove_work_dir():
	"""
	Removes the work directory.
	"""
	print("Removing work directory")
	work = lib.absolute_path(WORK_DIRECTORY)

	if os.path.exists(work):
		lib.remove_dir(work)

def remove_state_dirs():
	"""
	Removes the runtime state directories.
	"""
	print("Removing state directories")

	for walker in STATE_DIRECTORIES:
		state = lib.absolute_path(WORK_DIRECTORY, walker)

		if os.path.exists(state):
			lib.remove_dir(state)

	for walker in UDF_DIRECTORIES:
		udf = lib.absolute_path(WORK_DIRECTORY, walker)

		if os.path.exists(udf):
			lib.remove_dir(udf)

	if os.path.exists(LUA_DIRECTORY):
		lib.remove_dir(LUA_DIRECTORY)

def remove_valgrind_logs():
	"""
	Removes the output log files from valgrind tests
	"""
	print("Removing Valgrind logs")

	if os.path.exists(lib.VAL_LOGS_BACKUP):
		os.remove(lib.VAL_LOGS_BACKUP)
	if os.path.exists(lib.VAL_LOGS_RESTORE):
		os.remove(lib.VAL_LOGS_RESTORE)		

	if os.path.exists(lib.VAL_BACKUP_FILES):
		lib.remove_dir(lib.VAL_BACKUP_FILES)

def init_work_dir():
	"""
	Creates an empty work directory.
	"""
	remove_work_dir()
	print("Creating work directory")
	work = lib.absolute_path(WORK_DIRECTORY)
	os.mkdir(work, 0o755)

def init_state_dirs():
	"""
	Creates empty state directories.
	"""
	remove_state_dirs()
	print("Creating state directories")

	for walker in STATE_DIRECTORIES:
		state = lib.absolute_path(os.path.join(WORK_DIRECTORY, walker))
		os.mkdir(state, 0o755)
		smd = lib.absolute_path(os.path.join(WORK_DIRECTORY, walker, "smd"))
		os.mkdir(smd, 0o755)

	for walker in UDF_DIRECTORIES:
		udf = lib.absolute_path(os.path.join(WORK_DIRECTORY, walker))
		os.mkdir(udf, 0o755)

	os.mkdir(LUA_DIRECTORY, 0o755)

def set_fake_time(seconds):
	"""
	Writes the given number (seconds since epoch) to the fake time file, from
	where it is picked up by the clock_gettime() interceptor.
	"""
	with codecs.open(lib.absolute_path(WORK_DIRECTORY, FAKE_TIME_FILE), "w", "UTF-8") as file_obj:
		file_obj.write(str(seconds) + "\n")

def unset_fake_time():
	"""
	Removes the fake time file, which deactivates the clock_gettime()
	interceptor.
	"""
	fake_time_file = lib.absolute_path(WORK_DIRECTORY, FAKE_TIME_FILE)

	if os.path.exists(fake_time_file):
		os.remove(fake_time_file)

def init_interceptor():
	"""
	Compiles the clock_gettime() interceptor that's injected into asd using
	LD_PRELOAD. Used for controlling asd's idea of the current time when
	testing TTLs.
	"""
	interceptor = lib.absolute_path(WORK_DIRECTORY, "clock_gettime.so")
	subprocess.check_call(["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-std=c99", \
			"-D_GNU_SOURCE", "-fpic", "-shared", \
			"-o", interceptor, lib.absolute_path("clock_gettime.c")])

	unset_fake_time()
	return interceptor

def start_aerospike_servers(keep_work_dir=False):
	"""
	Starts an asd process with the local aerospike.conf and connects the client to it.
	"""

	if not GLOBALS["running"]:
		print("Starting asd")
		GLOBALS["running"] = True

		if not keep_work_dir:
			init_work_dir()

		init_state_dirs()
		interceptor = init_interceptor()

		temp_file = lib.absolute_path("aerospike.conf")
		# TODO
		#os.environ["LD_PRELOAD"] = interceptor
		mount_dir = lib.absolute_path(WORK_DIRECTORY)

		if USE_DOCKER_SERVERS:
			DOCKER_CLIENT.images.pull(SERVER_IMAGE)

			first_base = 3000
			first_ip = None
			for index in range(1, N_NODES+1):
				base = first_base + 10 * (index - 1)
				conf_file = create_conf_file(temp_file, base,
						None if index == 1 else (first_ip, first_base),
						index)
				cmd = '/usr/bin/asd --foreground --config-file %s --instance %s' % ('/opt/aerospike/work/' + lib.get_file(conf_file, base=mount_dir), str(index - 1))
				
				print('running in docker: %s' % cmd)

				container = DOCKER_CLIENT.containers.run(SERVER_IMAGE,
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
		config = {
			"hosts": [("localhost", lib.PORT)],
			"policies": {
				"read": {
					"max_retries": 5
				},
				"write": {
					"max_retries": 5
				}
			},
			"lua": {
				"user_path": LUA_DIRECTORY
			}
		}

		for attempt in range(lib.CLIENT_ATTEMPTS):
			try:
				set_client(aerospike.client(config).connect())
				break
			except Exception:
				if attempt < lib.CLIENT_ATTEMPTS - 1:
					lib.safe_sleep(.2)
				else:
					raise

		# initialize the list of indices, which will contain a list of the names of
		# all indices created
		lib.GLOBALS["indexes"] = []
		lib.GLOBALS["sets"] = []

		print("Client connected")
		lib.safe_sleep(1)

def stop_aerospike_servers(keep_work_dir=False):
	"""
	Disconnects the client and stops the running asd process.
	"""
	print("Disconnecting client")
	GLOBALS["running"] = False

	if get_client() is None:
		print("No connected client")
	else:
		get_client().close()
		set_client(None)

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
	
	# delete log files from valgrind tests
	remove_valgrind_logs()
		
def reset_aerospike_servers(keep_metadata=False):
	"""
	Reset: disconnects the client, stops asd, restarts asd, reconnects the client.
	"""
	print("resetting the database")

	# truncate the set
	for set_name in lib.GLOBALS["sets"]:
		if set_name is not None:
			set_name = set_name.strip()
		print("truncating", set_name)
		get_client().truncate(lib.NAMESPACE, None if not set_name else set_name, 0, {"timeout": 10000})
	if not keep_metadata:
		lib.GLOBALS["sets"] = []

	# delete all udfs
	udfs = []
	for udf in get_client().udf_list():
		udfs.append(udf)
	for udf in udfs:
		print("removing udf", udf["name"])
		get_client().udf_remove(udf["name"])

	# delete all indexes
	for index in lib.GLOBALS["indexes"]:
		try:
			print("removing index", index)
			get_client().index_remove(lib.NAMESPACE, index)
		except aerospike.exception.IndexNotFound:
			# the index may not actually be there if we are only backing up certain
			# sets, but this is ok, so fail silently
			pass
	if not keep_metadata:
		lib.GLOBALS["indexes"] = []

def graceful_exit(sig, frame):
	signal.signal(signal.SIGINT, g_orig_int_handler)
	stop_aerospike_servers()
	os.kill(os.getpid(), signal.SIGINT)

g_orig_int_handler = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, graceful_exit)

def stop_silent():
	# silence stderr and stdout
	stdout_tmp = sys.stdout
	stderr_tmp = sys.stderr
	null = open(os.devnull, 'w')
	sys.stdout = null
	sys.stderr = null
	try:
		stop_aerospike_servers()
		sys.stdout = stdout_tmp
		sys.stderr = stderr_tmp
	except:
		sys.stdout = stdout_tmp
		sys.stderr = stderr_tmp
		raise
# shut down the aerospike cluster when the tests are over
atexit.register(stop_silent)

