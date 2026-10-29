# coding=UTF-8

"""
Tests that asbackup and asrestore log in to an Enterprise server with security
enabled using credentials fetched from a real Secret Agent.

The module starts its own single Enterprise node, apart from the CE nodes the
other tests use. FEATKEY must hold a base64 encoded feature key file.
"""

import os
import shutil
import subprocess
import tempfile
import time

import aerospike
import docker
import pytest

import lib
import secret_agent_servers as sa

FEATKEY = os.environ.get("FEATKEY", "")

SERVER_IMAGE = "aerospike/aerospike-server-enterprise:8.2.0.0"
CONTAINER_NAME = "asb-sa-sec-%d" % os.getpid()
SERVER_START_TIMEOUT = 60
SET_NAME = "sa-sec"
N_RECORDS = 100
TOOLS = ["asbackup", "asrestore"]
ROLES = ["read-write", "data-admin", "sys-admin"]
SERVER_ERROR = "AEROSPIKE_INVALID_CREDENTIAL"

RESOURCE = "backup"
USER = "sa-backup"
PASSWORD = "sa-backup-pw"
WRONG_PASSWORD = "not-the-sa-backup-pw"
UNSET_ENV = "ASB_SA_UNSET"
MAX_PASSWORD = ("0123456789abcdef" * 4)[:63]

SECRETS = {
	"user": USER,
	"password": PASSWORD,
	"wrong": WRONG_PASSWORD,
	"env-ref": "env:" + UNSET_ENV,
	"max": MAX_PASSWORD,
}

USERS = {
	USER: PASSWORD,
	"sa-literal": "secrets:%s:wrong" % RESOURCE,
	"sa-env": "env:" + UNSET_ENV,
	"sa-max": MAX_PASSWORD,
}

SA_SECRETS_PATH = os.path.join(sa.WORK_DIRECTORY, "secured.json")
SA_CONF_PATH = os.path.join(sa.WORK_DIRECTORY, "secured.yaml")
SA_CA_FILE = os.path.join(sa.WORK_DIRECTORY, "cert.pem")
SA_KEY_FILE = os.path.join(sa.WORK_DIRECTORY, "key.pem")

SERVER_CONF = """service {
	cluster-name asb-sa-sec
	feature-key-file env-b64:FEATURES
	proto-fd-max 1024
}
logging {
	console {
		context any info
	}
}
network {
	service {
		address any
		port 3000
		access-address 127.0.0.1 virtual
	}
	heartbeat {
		mode mesh
		port 3002
	}
	fabric {
		port 3001
	}
}
security {
}
namespace test {
	replication-factor 1
	storage-engine memory {
		data-size 1G
	}
}
"""

STATE = {}


def admin_client():
	return aerospike.client({"hosts": [("127.0.0.1", STATE["port"])], "user": "admin",
		"password": "admin"}).connect()


def start_server():
	STATE["dir"] = tempfile.mkdtemp(prefix=CONTAINER_NAME + "-")
	os.chmod(STATE["dir"], 0o755)
	with open(os.path.join(STATE["dir"], "aerospike.conf"), "w") as f:
		f.write(SERVER_CONF)

	container = sa.DOCKER_CLIENT.containers.run(SERVER_IMAGE,
		command="/usr/bin/asd --foreground --config-file /opt/asb-sa-sec/aerospike.conf",
		ports={"3000/tcp": ("127.0.0.1", None)},
		volumes={STATE["dir"]: {"bind": "/opt/asb-sa-sec", "mode": "ro"}},
		environment={"FEATURES": FEATKEY},
		tty=True, detach=True, name=CONTAINER_NAME)
	container.reload()
	STATE["port"] = int(container.attrs["NetworkSettings"]["Ports"]["3000/tcp"][0]["HostPort"])

	deadline = time.time() + SERVER_START_TIMEOUT
	while True:
		try:
			STATE["client"] = admin_client()
			return
		except aerospike.exception.AerospikeError as error:
			if time.time() > deadline:
				raise Exception("admin/admin never logged in: %s\n%s" % (error,
					container.logs().decode(errors="replace")))
			time.sleep(0.5)


def remove_container():
	try:
		sa.DOCKER_CLIENT.containers.get(CONTAINER_NAME).remove(force=True)
	except docker.errors.NotFound:
		pass


def setup_module(module):
	if not FEATKEY and os.environ.get("CI"):
		pytest.fail("FEATKEY must hold a base64 encoded feature key file when CI is set")
	if not FEATKEY:
		pytest.skip("FEATKEY is not set. Run with FEATKEY=$(base64 < features.conf) to test "
			"against an Enterprise server.")

	try:
		start_server()
		client = STATE["client"]
		client.admin_grant_roles("admin", ROLES)
		for user, password in USERS.items():
			client.admin_create_user(user, password, ROLES)

		STATE.pop("client").close()
		client = STATE["client"] = admin_client()
		for i in range(N_RECORDS):
			client.put(("test", SET_NAME, i), {"v": i})

		STATE["backup"] = backup_path()
		rc, out = run("asbackup", *server_args(), "-U", "admin", "-P", "admin", "-n", "test",
			"-s", SET_NAME, *backup_target(STATE["backup"]))
		assert rc == 0, out

		sa.setup_secret_agent()
	except BaseException:
		teardown_module(module)
		raise


def teardown_module(module):
	client = STATE.pop("client", None)
	if client is not None:
		client.close()
	remove_container()
	if "dir" in STATE:
		shutil.rmtree(STATE.pop("dir"), ignore_errors=True)
	sa.teardown_secret_agent()


def run_agent(tls):
	with open(SA_SECRETS_PATH, "w") as f:
		f.write(sa.gen_secret_agent_secrets(SECRETS))

	tls_cfg = sa.tls_cfg(cert_file=SA_CA_FILE, key_file=SA_KEY_FILE).get_cfg() if tls else ""
	with open(SA_CONF_PATH, "w") as f:
		f.write(sa.gen_secret_agent_conf(resources={RESOURCE: SA_SECRETS_PATH}, tls_cfg=tls_cfg))

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		yield
	finally:
		agent.stop()
		print("*** Secret Agent Output ***")
		print(agent.output())
		print("*** End Secret Agent Output ***")
		agent.cleanup()


@pytest.fixture
def agent():
	yield from run_agent(tls=False)


@pytest.fixture
def tls_agent():
	yield from run_agent(tls=True)


def run(tool, *options, env=None):
	proc = subprocess.run([os.path.join("test_target", tool), *options],
		cwd=lib.absolute_path("../.."), capture_output=True, timeout=120, env=env)
	return proc.returncode, proc.stdout.decode(errors="replace") + \
		proc.stderr.decode(errors="replace")


def fetched(name):
	return "secrets:%s:%s" % (RESOURCE, name)


def server_args():
	return ["--no-config-file", "-h", "127.0.0.1", "-p", str(STATE["port"])]


def agent_args():
	return ["--sa-address", "127.0.0.1", "--sa-port", sa.SA_PORT]


def backup_path():
	return os.path.join(tempfile.mkdtemp(dir=STATE["dir"]), "backup")


def backup_target(path):
	return ["-d" if lib.is_dir_mode() else "-o", path]


def restore_source(path):
	return ["-d" if lib.is_dir_mode() else "-i", path]


def tool_target(tool):
	if tool == "asbackup":
		return ["-n", "test", "-s", SET_NAME, *backup_target(backup_path())]
	return restore_source(STATE["backup"])


def record_values():
	return sorted(bins["v"] for _, _, bins in
		STATE["client"].query("test", SET_NAME).results())


def truncate():
	STATE["client"].truncate("test", SET_NAME, 0)
	for _ in range(100):
		if not record_values():
			return
		time.sleep(0.1)
	assert record_values() == []


def round_trip(backup_options, restore_options, env=None):
	path = backup_path()
	rc, out = run("asbackup", *backup_options, "-n", "test", "-s", SET_NAME,
		*backup_target(path), env=env)
	assert rc == 0, out

	truncate()
	rc, out = run("asrestore", *restore_options, *restore_source(path), env=env)
	assert rc == 0, out
	assert record_values() == list(range(N_RECORDS))


def assert_rejected_by_server(rc, out):
	assert rc != 0, out
	assert SERVER_ERROR in out, out
	assert "secret" not in out.lower(), out
	assert "--password" not in out, out
	assert PASSWORD not in out, out
	assert WRONG_PASSWORD not in out, out


def test_round_trip_with_fetched_credentials(agent):
	login = [*server_args(), "--user", fetched("user"), "--password", fetched("password"),
		*agent_args()]
	round_trip(login, login)


@pytest.mark.parametrize("tool", TOOLS)
def test_wrong_fetched_password_is_rejected_by_the_server(agent, tool):
	rc, out = run(tool, *server_args(), "--user", fetched("user"), "--password",
		fetched("wrong"), *agent_args(), *tool_target(tool))
	assert_rejected_by_server(rc, out)


@pytest.mark.parametrize("tool", TOOLS)
def test_reference_is_not_sent_as_the_password(agent, tool):
	"""
	The user's password is the reference itself, so only sending the reference
	instead of the fetched value would log in.
	"""
	rc, out = run(tool, *server_args(), "--user", "sa-literal", "--password",
		fetched("wrong"), *agent_args(), *tool_target(tool))
	assert_rejected_by_server(rc, out)


def test_fetched_value_is_not_resolved_again(agent):
	"""
	The fetched value is env:ASB_SA_UNSET, which is also the user's password, so
	it only logs in if it is used as is rather than read from the environment.
	"""
	env = dict(os.environ)
	env.pop(UNSET_ENV, None)
	login = [*server_args(), "--user", "sa-env", "--password", fetched("env-ref"),
		*agent_args()]
	round_trip(login, login, env=env)


@pytest.mark.parametrize("ca_option", ["--sa-ca-file", "--sa-cafile"])
def test_tls_agent(tls_agent, ca_option):
	login = [*server_args(), "--user", fetched("user"), "--password", fetched("password"),
		"--sa-address", sa.SA_TLS_ADDR, "--sa-port", sa.SA_PORT, ca_option, SA_CA_FILE]
	round_trip(login, login)


def test_config_file(agent):
	path = os.path.join(tempfile.mkdtemp(dir=STATE["dir"]), "astools.conf")
	with open(path, "w") as f:
		f.write('[cluster]\nhost = "127.0.0.1"\nport = %d\nuser = "%s"\npassword = "%s"\n'
			'[secret-agent]\nsa-address = "127.0.0.1"\nsa-port = "%s"\n'
			% (STATE["port"], fetched("user"), fetched("password"), sa.SA_PORT))
	round_trip(["--only-config-file", path], ["--only-config-file", path])


def test_restore_with_fetched_password(agent):
	round_trip([*server_args(), "--user", USER, "--password", PASSWORD],
		[*server_args(), "--user", USER, "--password", fetched("password"), *agent_args()])


def test_maximum_length_password(agent):
	assert len(MAX_PASSWORD) == 63
	login = [*server_args(), "--user", "sa-max", "--password", fetched("max"),
		*agent_args()]
	round_trip(login, login)
