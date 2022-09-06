# coding=UTF-8

"""
Tests the representation of asbackup/asrestore output runned with valgrind
"""
from turtle import back
from unittest.mock import NonCallableMagicMock
import docker
import subprocess
import time

import aerospike_servers as as_srv
import lib
from run_backup import run_backup_w_valgrind, run_restore_w_valgrind

DOCKER_CLIENT = docker.from_env()
TOOLS_VERSION = "aerospike-tools-7.2.0.ubuntu20.04.x86_64.deb"
TOOLS_PACKAGE = "http://build.browser.qe.aerospike.com/citrusleaf/aerospike-tools/7.2.0/build/ubuntu-20.04/default/artifacts/{0}".format(TOOLS_VERSION)

def install_valgrind():
    print('Installing Valgrind in docker')
    docker_images = DOCKER_CLIENT.containers.list()
    if len(docker_images) == 0:
        print("NO DOCKER IMAGE FOUND")
        return -1
    cmd = "docker exec -t {0} sh -c".format(docker_images[0].name).split()
    cmd_install = "apt update && apt install -y valgrind && apt install -y wget && wget {0} && dpkg -i {1}".format(TOOLS_PACKAGE, TOOLS_VERSION)
    cmd.append(str(cmd_install))
    try:
        subprocess.check_call(cmd)
    except:
        print("Exception occured during installing valgrind and other packages.")

path = lib.temporary_path("dir")

def get_basic_backup_options():
    backup_options = "--directory", path, \
			#"--namespace", lib.NAMESPACE, \
			#"--verbose"
    return backup_options

def get_basic_restore_options():
    restore_options = "--directory", path, \
			#"--verbose",
    return restore_options

def test_backup_batch_writes_to_dir():
    """
	Tests backup to dir with batch write enabled running by valgrind
	"""
    backup_options = get_basic_backup_options()
    return run_backup_w_valgrind(*backup_options)

def test_backup_to_dir_batch_writes_disabled():
    """
	Tests backup to dir with batch write disabled running by valgrind
	"""
    backup_options = get_basic_backup_options()
    return run_backup_w_valgrind(*backup_options, "--disable-batch-writes")

def test_restore_batch_writes_to_dir():
    """
	Tests restore to dir with batch write enabled running by valgrind
	"""
    restore_options = get_basic_restore_options()
    return lib.run("asrestore",  *restore_options, do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)


def test_restore_to_dir_batch_writes_disabled():
    """
	Tests restore to dir with batch write disabled running by valgrind
	"""
    restore_options = get_basic_restore_options()
    return lib.run("asrestore", *restore_options, "--disable-batch-writes", do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)
