# coding=UTF-8

"""
Tests backup and restore with the secret agent.
"""

import lib
from run_backup import backup_and_restore
import os
import re
import subprocess
import tempfile
import pytest
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

SA_CA_FILE = os.path.join(SA_RSRC_PATH, "cert.pem")
SA_KEY_FILE = os.path.join(SA_RSRC_PATH, "key.pem")

SA_UNTRUSTED_CA_FILE = os.path.join(sa.WORK_DIRECTORY, "untrusted_cert.pem")
SA_UNTRUSTED_KEY_FILE = os.path.join(sa.WORK_DIRECTORY, "untrusted_key.pem")

SA_TOOLS_CONF_PATH = os.path.join(sa.WORK_DIRECTORY, "astools.conf")

def gen_secret_agent_files(backup_args:{str:any}=None, restore_args:{str:any}=None, sa_tls:bool=False):
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

    sa_tls_cfg = ""
    if sa_tls:
        sa_tls_cfg = sa.tls_cfg(
            cert_file=SA_CA_FILE,
            key_file=SA_KEY_FILE,
        ).get_cfg()

    secrets_conf = sa.gen_secret_agent_conf(
        resources=resources,
        tls_cfg=sa_tls_cfg,
    )

    with open(SA_CONF_PATH, "w+") as f:
        f.write(secrets_conf)


BIN_NAMES = lib.identifier_variations(14, False)
def backup_restore_with_secrets(backup_args:{str:any}, restore_args:{str:any}, sa_args:[str], sa_tls:bool=False,
                                cli_secrets:bool=True):
    os.system("rm -rf " + SA_RSRC_PATH)
    os.system("mkdir " + SA_RSRC_PATH)

    gen_secret_agent_files(
        backup_args=backup_args,
        restore_args=restore_args,
        sa_tls=sa_tls
    )

    agent = sa.get_secret_agent(config=SA_CONF_PATH)

    try:
        agent.start()

        bargs = sa.gen_secret_args(backup_args, SA_BACKUP_RESOURCE) if cli_secrets else []
        bargs += sa_args
        rargs = sa.gen_secret_args(restore_args, SA_RESTORE_RESOURCE) if cli_secrets else []
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

def sa_cli_args(addr:str, ca_file:str, ca_file_key:str) -> [str]:
    return ["--sa-address", addr, "--sa-port", sa.SA_PORT, "--" + ca_file_key, ca_file]

def sa_conf_args(addr:str, ca_file:str, ca_file_key:str) -> [str]:
    with open(SA_TOOLS_CONF_PATH, "w+") as f:
        f.write('[secret-agent]\nsa-address = "%s"\nsa-port = "%s"\n%s = "%s"\n'
                % (addr, sa.SA_PORT, ca_file_key, ca_file))
    return ["--only-config-file", SA_TOOLS_CONF_PATH]

def write_tools_conf(text:str) -> [str]:
    with open(SA_TOOLS_CONF_PATH, "w+") as f:
        f.write(text)
    return ["--only-config-file", SA_TOOLS_CONF_PATH]

SA_ARG_SOURCES = pytest.mark.parametrize("make_sa_args", [sa_cli_args, sa_conf_args],
                                         ids=["cli", "config-file"])
SA_CA_FILE_KEYS = pytest.mark.parametrize("ca_file_key", ["sa-ca-file", "sa-cafile"])

@SA_ARG_SOURCES
@SA_CA_FILE_KEYS
def test_secrets_ca_file(make_sa_args, ca_file_key):
    """
    Test the secret agent TLS options.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=make_sa_args(sa.SA_TLS_ADDR, SA_CA_FILE, ca_file_key),
        sa_tls=True
    )

def expect_sa_cert_verify_failure(sa_args:[str], reason:str):
    os.system("rm -rf " + SA_RSRC_PATH)
    os.system("mkdir " + SA_RSRC_PATH)

    host_args = {"host": "127.0.0.1"}
    gen_secret_agent_files(backup_args=host_args, restore_args=host_args, sa_tls=True)
    agent = sa.get_secret_agent(config=SA_CONF_PATH)

    try:
        agent.start()
        for tool, resource in [("asbackup", SA_BACKUP_RESOURCE),
                               ("asrestore", SA_RESTORE_RESOURCE)]:
            with tempfile.TemporaryFile() as stderr:
                with pytest.raises(subprocess.CalledProcessError):
                    lib.run(tool, "--host", "secrets:%s:host" % resource, *sa_args,
                            pipe_stderr=stderr)
                stderr.seek(0)
                output = stderr.read().decode("utf-8", errors="replace")
                assert re.search("certificate verify failed: " + reason, output), output
    finally:
        agent.stop()
        print("*** Secret Agent Output ***")
        print(agent.output())
        print("*** End Secret Agent Output ***")
        agent.cleanup()

@SA_ARG_SOURCES
@SA_CA_FILE_KEYS
def test_secrets_ca_file_address_mismatch(make_sa_args, ca_file_key):
    """
    Test that the agent certificate is rejected when the secret agent address
    is not one of its subject alternative names.
    """
    expect_sa_cert_verify_failure(make_sa_args(sa.SA_ADDR, SA_CA_FILE, ca_file_key),
                                  "IP address mismatch")

@SA_ARG_SOURCES
@SA_CA_FILE_KEYS
def test_secrets_ca_file_untrusted_ca(make_sa_args, ca_file_key):
    """
    Test that the agent certificate is rejected when it is not signed by the
    secret agent CA file.
    """
    sa.tls_cfg(cert_file=SA_UNTRUSTED_CA_FILE, key_file=SA_UNTRUSTED_KEY_FILE).get_cfg()
    expect_sa_cert_verify_failure(
        make_sa_args(sa.SA_TLS_ADDR, SA_UNTRUSTED_CA_FILE, ca_file_key),
        "self[- ]signed certificate")

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
    Test sa addr with ipv6 port.
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

@pytest.mark.parametrize("make_sa_args", [
    lambda: ["--no-config-file", "--sa-address", "127.0.0.1:9999", "--sa-port", sa.SA_PORT],
    lambda: write_tools_conf('[secret-agent]\nsa-address = "127.0.0.1:9999"\nsa-port = "%s"\n'
                             % sa.SA_PORT),
], ids=["cli", "config-file"])
def test_secrets_sa_port_beats_address_port(make_sa_args):
    """
    Test that sa-port overrides a port given in sa-address.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=make_sa_args()
    )

@pytest.mark.parametrize("make_sa_args", [
    lambda: ["--no-config-file", "--sa-address", "[::1]:%s" % sa.SA_PORT],
    lambda: ["--no-config-file", "--sa-address", "[::1]", "--sa-port", sa.SA_PORT],
    lambda: ["--no-config-file", "--sa-address", "::1"],
    lambda: write_tools_conf('[secret-agent]\nsa-address = "[::1]:%s"\n' % sa.SA_PORT),
    lambda: write_tools_conf('[secret-agent]\nsa-address = "[::1]"\nsa-port = "%s"\n' % sa.SA_PORT),
    lambda: write_tools_conf('[secret-agent]\nsa-address = "::1"\n'),
], ids=["cli-port", "cli-sa-port", "cli-unbracketed",
        "config-file-port", "config-file-sa-port", "config-file-unbracketed"])
def test_secrets_ipv6_address_forms(make_sa_args):
    """
    Test the IPv6 sa-address forms: bracketed with a port, bracketed with
    sa-port and unbracketed with the default port.
    """
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=make_sa_args()
    )

def test_secrets_in_config_file_use_cli_sa_options():
    """
    Test that secrets in the config file are fetched with the secret agent
    options given on the command line.
    """
    conf_args = write_tools_conf('[cluster]\nhost = "secrets:%s:host"\n' % SA_BACKUP_RESOURCE)
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1"},
        restore_args={"host": "127.0.0.1"},
        sa_args=conf_args + sa_cli_args(sa.SA_TLS_ADDR, SA_CA_FILE, "sa-ca-file"),
        sa_tls=True,
        cli_secrets=False
    )

def test_secrets_in_config_file_overridden_on_cli_not_fetched():
    """
    Test that a secret in the config file is not fetched when the command line
    gives the same option.
    """
    conf_args = write_tools_conf('[cluster]\nhost = "secrets:%s:no-such-secret"\n'
                                 % SA_BACKUP_RESOURCE)
    backup_restore_with_secrets(
        backup_args={"port": 3000},
        restore_args={"port": 3000},
        sa_args=conf_args + ["--host", "127.0.0.1"]
    )

def test_secrets_conf_integer_port_and_digit_string_timeout():
    """
    Test a [secret-agent] section with sa-port as an integer and sa-timeout as
    a string of digits.
    """
    conf_args = write_tools_conf('[secret-agent]\nsa-address = "%s"\nsa-port = %s\n'
                                 'sa-timeout = "2000"\nsa-ca-file = "%s"\n'
                                 % (sa.SA_TLS_ADDR, sa.SA_PORT, SA_CA_FILE))
    backup_restore_with_secrets(
        backup_args={"host": "127.0.0.1", "port": 3000},
        restore_args={"host": "127.0.0.1", "port": 3000},
        sa_args=conf_args,
        sa_tls=True
    )