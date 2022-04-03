# coding=UTF-8

"""
MinIO S3-compatible server management utilities.
"""

import atexit
import docker
import os
import sys

import lib

DOCKER_CLIENT = docker.from_env()

MINIO_SERVERS = {}

GLOBALS = { "running": False }

def start_minio_server(name, volume, base_port=9000, root_user_key="key",
		root_user_password="secretkey"):
	"""
	Starts a MinIO docker server with given name and "volume" directory
	backing the /data directory within the container.
	"""
	if not GLOBALS["running"]:
		container = DOCKER_CLIENT.containers.run("quay.io/minio/minio",
				command="server /data --console-address=\":9001\"",
				ports={
					'9000/tcp': str(base_port),
					'9001/tcp': str(base_port + 1)
					},
				volumes={ volume: { 'bind': '/data', 'mode': 'rw' } },
				environment=["MINIO_ROOT_USER=key", "MINIO_ROOT_PASSWORD=secretkey",
					"MINIO_HTTP_TRACE=/tmp/minio.log"],
				tty=True, detach=True, name=name, user=str(os.getuid()) + ":" + str(os.getgid()))

		container.reload()
		ip = container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]

		MINIO_SERVERS[name] = {
			"container": container,
			"ip": ip
		}

		# let the server initialize
		lib.safe_sleep(1)

		GLOBALS["running"] = True

def stop_minio_server(name):
	"""
	Shuts down the MinIO server with given name.
	"""
	if name not in MINIO_SERVERS:
		raise Exception("No MinIO server with name " + str(name) + " running")
	container = MINIO_SERVERS[name]["container"]
	container.stop()
	container.remove()
	MINIO_SERVERS.pop(name)

def get_minio_ip(name):
	"""
	Returns the IP address of the minio server hosted in docker image with given
	name.
	"""
	if name not in MINIO_SERVERS:
		raise Exception("No MinIO server with name " + str(name) + " running")
	return MINIO_SERVERS[name]["ip"]

def stop_silent():
	# silence stderr and stdout
	stdout_tmp = sys.stdout
	stderr_tmp = sys.stderr
	null = open(os.devnull, 'w')
	sys.stdout = null
	sys.stderr = null
	try:
		for minio_name in [_ for _ in MINIO_SERVERS]:
			stop_minio_server(minio_name)
		sys.stdout = stdout_tmp
		sys.stderr = stderr_tmp
	except:
		sys.stdout = stdout_tmp
		sys.stderr = stderr_tmp
		raise

# shut down the aerospike cluster when the tests are over
atexit.register(stop_silent)

