# coding=UTF-8

"""
Tests the representation of asbackup/asrestore output runned with valgrind
"""
from unittest.mock import NonCallableMagicMock
import docker
import subprocess

import lib

DOCKER_CLIENT = docker.from_env()
TOOLS_VERSION = "aerospike-tools-7.2.0.ubuntu20.04.x86_64.deb"
TOOLS_PACKAGE = "http://build.browser.qe.aerospike.com/citrusleaf/aerospike-tools/7.2.0/build/ubuntu-20.04/default/artifacts/{0}".format(TOOLS_VERSION)

def install_prereq():
    print('Installing Valgrind and Tools %s package in docker', TOOLS_VERSION)
    docker_images = DOCKER_CLIENT.containers.list()
    if len(docker_images) == 0:
        print("NO DOCKER IMAGE FOUND")
        return
    print(docker_images)
    cmd = "docker exec -t {0} sh -c".format(docker_images[0].name).split()
    cmd_install = "apt install -y valgrind && apt install -y python3 && wget {0} && dpkg -i {1}".format(TOOLS_PACKAGE, TOOLS_VERSION)
    cmd.append(str(cmd_install))
    try:
        subprocess.check_call(cmd)
    except:
        print("Exception occured during installing pre-req")

path = lib.temporary_path("dir")
backup_options = "--directory", path, \
			"--namespace", lib.NAMESPACE, \
			"--verbose"

restore_options = "--directory", path, \
			"--verbose", \

def test_init():
    install_prereq()

def test_backup_batch_writes_to_dir():
    """
	Tests backup to dir with batch write enabled running by valgrind
	"""
    return lib.run("asbackup", *backup_options, do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)


def test_backup_to_dir_batch_writes_disabled():
    """
	Tests backup to dir with batch write disabled running by valgrind
	"""
    return lib.run("asbackup", "--disable-batch-writes", *backup_options, do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)

def test_restore_batch_writes_to_dir():
    """
	Tests restore to dir with batch write enabled running by valgrind
	"""
    return lib.run("asrestore",  *restore_options, do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)


def test_restore_to_dir_batch_writes_disabled():
    """
	Tests restore to dir with batch write disabled running by valgrind
	"""
    return lib.run("asrestore", "--disable-batch-writes", *restore_options, do_async=False,
			pipe_stdout=None, env={}, RUN_IN_DOCKER=True)
