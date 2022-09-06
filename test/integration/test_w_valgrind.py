# coding=UTF-8

"""
Tests the representation of asbackup/asrestore output runned with valgrind
"""
from turtle import back
from unittest.mock import NonCallableMagicMock
import docker
import subprocess
import time
import re

import aerospike_servers as as_srv
import lib
from run_backup import run_backup_w_valgrind, run_restore_w_valgrind

DOCKER_CLIENT = docker.from_env()
TOOLS_VERSION = "aerospike-tools-7.2.0.ubuntu18.04.x86_64.deb"
TOOLS_PACKAGE = "http://build.browser.qe.aerospike.com/citrusleaf/aerospike-tools/7.2.0/build/ubuntu-18.04/default/artifacts/{0}".format(TOOLS_VERSION)

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
        #print('Installing Valgrind in docker')
        cmd_install = "apt update && apt install -y valgrind && apt install -y wget && wget {0} && dpkg -i {1} && mkdir test".format(TOOLS_PACKAGE, TOOLS_VERSION)
        cmd.append(str(cmd_install))
        try:
            subprocess.check_call(cmd)
        except:
            print("Exception occured during installing valgrind and other packages.")

path = "test/"

def get_basic_backup_options():
    backup_options = "--directory", path, \
			"--namespace", lib.NAMESPACE, \
			"--verbose"
    return backup_options

def get_basic_restore_options():
    restore_options = "--directory", path, \
			"--verbose",
    return restore_options

def parse_val_logs(log_file):
    res = True
    START = re.compile("in loss record")
    STOP = re.compile("^==\d+== $")
    GOOD = re.compile(r"\.c:\d+", re.M)

    HEAP_SUMMARY = re.compile("in use at exit: \d+ bytes")
    ERROR_SUMMARY = re.compile("ERROR SUMMARY: \d+ errors")

    in_line = False
    current = []
    heap_sum = []
    error = []
    try:
        with open(log_file, "r") as f:
            for line in f.lines():
                if in_line:
                    in_line = not STOP.search(line)
                else:
                    in_line = START.search(line)

                if in_line:
                    current.append(line)
                else:
                    match = GOOD.findall("".join(current))
                    if len(match) > 2:
                        print ("".join(current))
                    current = []
                
            heap_sum = HEAP_SUMMARY.findall(f)
            unfree_heap = re.findall(r'\d+', heap_sum[0])
            if unfree_heap[0] != "0":
                print("VALGRIND HEAP SUMMARY: {0} bytes in use at exit".format(unfree_heap[0]))
                res = False
            
            error = ERROR_SUMMARY.findall(f)
            tot_errors = re.findall(r'\d+', error[0])
            if tot_errors[0] != "0":
                print("VALGRIND ERROR SUMMARY: {0} errors".format(tot_errors[0]))
                res = False
    except:
        print("Unexpected error occured while parsing valgrind logs")
        res = False
    return res

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
