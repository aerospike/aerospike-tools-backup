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

SA_BASE_PATH = lib.absolute_path(lib.SECRET_AGENT_DIRECTORY)
SA_RSRC_PATH = os.path.join(SA_BASE_PATH, "resources")

SA_ADDR = "0.0.0.0"

SA_BACKUP_FILE_PATH = os.path.join(SA_RSRC_PATH, "b_secrets.json")
SA_BACKUP_RESOURCE = "backup"

SA_RESTORE_FILE_PATH = os.path.join(SA_RSRC_PATH, "r_secrets.json")
SA_RESTORE_RESOURCE = "restore"


def gen_secret_agent_conf(resources:{str:str}) -> str:
    sa_addr = SA_ADDR
    sa_port = sa.SA_PORT

    def make_resources(resources:{str:str}={}) -> str:
        res = ""
        for k, v in resources.items():

            if sa.USE_DOCKER_SERVERS:
                v = os.path.relpath(v, SA_BASE_PATH)
                v = os.path.join(sa.CONTAINER_VAL, v)

            nl = '\n'
            res += f'       "{k}": "{v}"{nl}'
        return res

    resource_str = make_resources(resources=resources)

    secret_agent_conf_template = """
service:
  tcp:
    endpoint: %s:%s

secret-manager:
  file:
    resources:
%s

log:
  level: debug
""" % (sa_addr, sa_port, resource_str)
    return secret_agent_conf_template

def gen_secret_agent_secrets(secrets:{str:any}={}) -> str:
    
    def make_secrets(secrets:{str:any}={}) -> str:
        res = ""
        for k, v in secrets.items():
            if v is None or v == "":
                continue

            nl = '\n'
            name = k
            value = base64.b64encode(str(v).encode("utf-8")).decode("utf-8")
            template = f'   "{name}": "{value}",{nl}'

            res += template
        # remove the last "",\n"
        return res[:-2]
			
    secret_str = make_secrets(secrets=secrets)

    secrets_template = """
{
%s
}
""" % secret_str
    return secrets_template

SA_CONF_PATH = os.path.join(SA_RSRC_PATH, "conf.yaml")

def gen_secret_agent_files(backup_args={str:any}, restore_args={str:any}):
    backup_secrets_json = gen_secret_agent_secrets(backup_args)
    with open(SA_BACKUP_FILE_PATH, "w+") as f:
            f.write(backup_secrets_json)

    restore_secrets_json = gen_secret_agent_secrets(restore_args)
    with open(SA_RESTORE_FILE_PATH, "w+") as f:
            f.write(restore_secrets_json)

    resources = {SA_BACKUP_RESOURCE: SA_BACKUP_FILE_PATH,
                 SA_RESTORE_RESOURCE: SA_RESTORE_FILE_PATH}
    secrets_conf = gen_secret_agent_conf(resources=resources)

    with open(SA_CONF_PATH, "w+") as f:
        f.write(secrets_conf)

def gen_secret_args(args:{str:any}, resource:str) -> str:
    res = []
    for k, v in args.items():
        arg = f"--{k}"
        res.append(arg)

        val = f"secrets:{resource}:{k}"
        res.append(val)

    return res

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

BIN_NAMES = lib.identifier_variations(14, False)
def backup_restore_with_secrets(backup_args:{str:any}, restore_args:{str:any}, sa_args:[str]=None):
    os.system("rm -rf " + SA_RSRC_PATH)
    os.system("mkdir " + SA_RSRC_PATH)

    gen_secret_agent_files(backup_args=backup_args, restore_args=restore_args)

    agent = sa.get_secret_agent(config=SA_CONF_PATH)

    try:
        agent.start()

        bargs = gen_secret_args(backup_args, SA_BACKUP_RESOURCE)
        bargs += sa_args
        rargs = gen_secret_args(restore_args, SA_RESTORE_RESOURCE)
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
        sa_args=["--sa-address", SA_ADDR, "--sa-port", sa.SA_PORT]
    )