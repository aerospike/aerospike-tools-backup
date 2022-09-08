# coding=UTF-8

"""
Tests the representation of asbackup/asrestore output runned with valgrind inside a docker container
"""
from turtle import back
from unittest.mock import NonCallableMagicMock
import docker

import aerospike_servers as as_srv
import lib
from run_backup import run_backup_in_docker, run_restore_in_docker
import record_gen

DOCKER_CLIENT = docker.from_env()
path = "test_dir"

def get_basic_backup_options():
    backup_options = "--directory", path, \
			"--namespace", lib.NAMESPACE, \
			"-r"
    return backup_options

def get_basic_restore_options():
    restore_options = "--directory", path,
    return restore_options

def test_backup_to_dir_in_docker():
    """
	Tests backup to dir running by valgrind inside a docker container
	"""
    backup_options = get_basic_backup_options()
    context = {}
    n_records = 5000
    filler = lambda context: record_gen.put_records(n_records, context, lib.SET, do_indexes=True)
    assert run_backup_in_docker(filler, context=context, backup_options=backup_options) == True, "Backup test with valgrind (running in docker) failed, cmd options {0}".format(backup_options)

def test_restore_to_dir_batch_writes_disabled_in_docker():
    """
	Tests restore to dir with batch write disabled running by valgrind inside a docker container
	"""
    restore_options = get_basic_restore_options()
    assert run_restore_in_docker(*restore_options, "--disable-batch-writes") == True, "Restore test with valgrind (running in docker) failed, cmd options {0}".format(restore_options)

def test_restore_batch_writes_to_dir_in_docker():
    """
	Tests restore to dir with batch write enabled running by valgrind inside a docker container
	"""
    restore_options = get_basic_restore_options()
    assert run_restore_in_docker(*restore_options) == True, "Restore test with valgrind (running in docker) failed, cmd options {0}".format(restore_options)

