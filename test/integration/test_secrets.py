# coding=UTF-8

"""
Tests the representation of bin names in backup files.
"""

import lib
from run_backup import backup_and_restore
import base64
import os
import time
import subprocess
import secret_agent_servers as sa

def put_bins(set_name, key, bin_names, value):
	"""
	Inserts the given key with the given bins with the given value.
	"""
	values = [value] * len(bin_names)
	lib.write_record(set_name, key, bin_names, values)

def check_bins(set_name, key, bin_names, value):
	"""
	Ensures that the given key has the given bins with the given value.
	"""
	meta_key, meta_ttl, record = lib.read_record(set_name, key)
	values = [value] * len(bin_names)
	lib.validate_record(key, record, bin_names, values)
	lib.validate_meta(key, meta_key, meta_ttl)

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
        with open(SA_BACKUP_FILE_PATH, "w+") as f:
                f.write(backup_secrets_json)
        resources[SA_BACKUP_RESOURCE] = SA_BACKUP_FILE_PATH

    if restore_args:
        restore_secrets_json = sa.gen_secret_agent_secrets(restore_args)
        with open(SA_RESTORE_FILE_PATH, "w+") as f:
                f.write(restore_secrets_json)
        resources[SA_RESTORE_RESOURCE] = SA_RESTORE_FILE_PATH

    secrets_conf = sa.gen_secret_agent_conf(resources=resources)

    with open(SA_CONF_PATH, "w+") as f:
        f.write(secrets_conf)

BIN_NAMES = lib.identifier_variations(14, False)
def backup_restore_with_secrets(backup_args:{str:any}, restore_args:{str:any}, sa_args:[str]):
    os.system("rm -rf " + SA_RSRC_PATH)
    os.system("mkdir " + SA_RSRC_PATH)

    gen_secret_agent_files(backup_args=backup_args, restore_args=restore_args)

    agent = sa.get_secret_agent(config=SA_CONF_PATH)

    try:
        agent.start()

        bargs = sa.gen_secret_args(backup_args, SA_BACKUP_RESOURCE)
        bargs += sa_args
        rargs = sa.gen_secret_args(restore_args, SA_RESTORE_RESOURCE)
        rargs += sa_args

        backup_and_restore(
            lambda context: put_bins(lib.SET, "key", BIN_NAMES, "foobar"),
            None,
            lambda context: check_bins(lib.SET, "key", BIN_NAMES, "foobar"),
            backup_opts=bargs,
            restore_opts=rargs,
            do_compress_and_encrypt=False
        )
    except Exception as e:
        raise e
    finally:
        agent.stop()
        print("*** Secret Agent Output ***")
        print(agent.output())
        print("*** End Secret Agent Output ***")
        agent.cleanup()

def setup_module(module):
	sa.setup_secret_agent()

def teardown_module(module):
	sa.teardown_secret_agent()

def test_secrets():
    """
    Test basic secret options.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=["--sa-address", sa.SA_ADDR, "--sa-port", sa.SA_PORT]
    )

def test_secrets_ip_parsing():
    """
    Test sa addr with port.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000, "parallel": 2},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=["--sa-address", "%s:%s" % (sa.SA_ADDR, sa.SA_PORT)]
    )

def test_secrets_ipv6_parsing():
    """
    Test sa addr with port.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000, "parallel": 2},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=["--sa-address", "%s:%s" % ("[::]", sa.SA_PORT)]
    )

def test_secrets_default_sa_args():
    """
    Test default secret options.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=[]
    )