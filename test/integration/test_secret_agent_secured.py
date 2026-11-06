# coding=UTF-8

"""
Tests that asbackup and asrestore log in to an Enterprise server with security
enabled using credentials fetched from a real Secret Agent.

The module starts its own single Enterprise node, apart from the CE nodes the
other tests use. FEATKEY must hold a base64 encoded feature key file.
"""

import base64
import binascii
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time

import aerospike
import docker
import pytest

import lib
import secret_agent_servers as sa

FEATKEY = "".join(os.environ.get("FEATKEY", "").split())

SERVER_IMAGE = "aerospike/aerospike-server-enterprise:8.2.0.0"
CONTAINER_NAME = "asb-sa-sec-%d" % os.getpid()
OWNER_LABEL = "asb-sa-sec-owner"
SERVER_START_TIMEOUT = 60
SET_NAME = "sa-sec"
PROBE_SET = "sa-sec-probe"
N_RECORDS = 100
TOOLS = ["asbackup", "asrestore"]
PASSWORD_FORMS = ["separate", "long", "attached"]
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
	"sa-missing-key": "secrets:%s:absent" % RESOURCE,
	"sa-missing-resource": "secrets:absent:password",
}

SA_SECRETS_PATH = os.path.join(sa.WORK_DIRECTORY, "secured.json")
SA_OTHER_SECRETS_PATH = os.path.join(sa.WORK_DIRECTORY, "secured-other.json")
SA_CONF_PATH = os.path.join(sa.WORK_DIRECTORY, "secured.yaml")
SA_CA_FILE = os.path.join(sa.WORK_DIRECTORY, "cert.pem")
SA_KEY_FILE = os.path.join(sa.WORK_DIRECTORY, "key.pem")
SA_MAGIC = 0x51DEC1CC
SA_READY_TIMEOUT = 30

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


def cluster_stable(client):
	keys = set()
	for error, response in client.info_all("cluster-stable:size=1").values():
		value = (response or "").split("\t", 1)[-1].strip()
		keys.add(None if error or not value or value.upper().startswith("ERROR")
			else value)
	return len(keys) == 1 and None not in keys


def pid_alive(pid):
	try:
		os.kill(pid, 0)
	except ProcessLookupError:
		return False
	except PermissionError:
		pass
	return True


def remove_leftover_servers():
	for container in sa.DOCKER_CLIENT.containers.list(all=True, filters={"label": OWNER_LABEL}):
		owner = int(container.labels[OWNER_LABEL])
		if owner == os.getpid() or not pid_alive(owner):
			container.remove(force=True)


def start_server():
	STATE["dir"] = tempfile.mkdtemp(prefix=CONTAINER_NAME + "-")
	os.chmod(STATE["dir"], 0o755)
	with open(os.path.join(STATE["dir"], "aerospike.conf"), "w") as f:
		f.write(SERVER_CONF)

	remove_leftover_servers()
	try:
		sa.DOCKER_CLIENT.images.get(SERVER_IMAGE)
	except docker.errors.ImageNotFound:
		sa.DOCKER_CLIENT.images.pull(SERVER_IMAGE)

	container = sa.DOCKER_CLIENT.containers.run(SERVER_IMAGE,
		command="/usr/bin/asd --foreground --config-file /opt/asb-sa-sec/aerospike.conf",
		ports={"3000/tcp": ("127.0.0.1", None)},
		volumes={STATE["dir"]: {"bind": "/opt/asb-sa-sec", "mode": "ro"}},
		labels={OWNER_LABEL: str(os.getpid())},
		environment={"FEATURES": FEATKEY},
		tty=True, detach=True, name=CONTAINER_NAME)
	container.reload()
	STATE["port"] = int(container.attrs["NetworkSettings"]["Ports"]["3000/tcp"][0]["HostPort"])

	deadline = time.time() + SERVER_START_TIMEOUT
	while True:
		try:
			STATE["client"] = STATE.get("client") or admin_client()
			if cluster_stable(STATE["client"]):
				return
			error = "cluster not stable"
		except aerospike.exception.AerospikeError as e:
			error = e
		container.reload()
		if container.status != "running" or time.time() > deadline:
			raise Exception("admin/admin never logged in to a stable cluster (%s): %s\n%s" % (
				container.status, error, container.logs().decode(errors="replace")))
		time.sleep(0.5)


def remove_container():
	try:
		sa.DOCKER_CLIENT.containers.get(CONTAINER_NAME).remove(force=True)
	except docker.errors.NotFound:
		pass


def setup_module(module):
	if not FEATKEY and os.environ.get("CI"):
		pytest.fail("FEATKEY must be set in CI: export FEATKEY=$(base64 < features.conf)")
	if not FEATKEY:
		pytest.skip("FEATKEY is not set: export FEATKEY=$(base64 < features.conf) to run "
			"the secured server tests")
	featkey_invalid = False
	try:
		base64.b64decode(FEATKEY, validate=True)
	except (binascii.Error, ValueError):
		featkey_invalid = True
	if featkey_invalid:
		pytest.fail("FEATKEY is not base64: export FEATKEY=$(base64 < features.conf)")

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

		client.put(("test", PROBE_SET, 0), {"v": 0})

		for key, set_name in [("backup", SET_NAME), ("probe_backup", PROBE_SET)]:
			STATE[key] = backup_path()
			rc, out = run("asbackup", *server_args(), "-U", "admin", "-P", "admin", "-n", "test",
				"-s", set_name, *backup_target(STATE[key]))
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


def wait_for_agent(tls):
	body = json.dumps({"Resource": RESOURCE, "SecretKey": "probe"}).encode()
	request = struct.pack(">II", SA_MAGIC, len(body)) + body
	deadline = time.time() + SA_READY_TIMEOUT

	while time.time() < deadline:
		try:
			with socket.create_connection(("127.0.0.1", int(sa.SA_PORT)), timeout=2) as raw:
				conn = raw
				if tls:
					ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
					ctx.minimum_version = ssl.TLSVersion.TLSv1_2
					ctx.load_verify_locations(SA_CA_FILE)
					conn = ctx.wrap_socket(raw, server_hostname="localhost")
				conn.sendall(request)
				header = conn.recv(8)
				if len(header) == 8 and struct.unpack(">I", header[:4])[0] == SA_MAGIC:
					return
		except (OSError, ssl.SSLError):
			pass
		time.sleep(0.2)

	raise Exception("secret agent not ready on port %s" % sa.SA_PORT)


def run_agent(tls):
	with open(SA_SECRETS_PATH, "w") as f:
		f.write(sa.gen_secret_agent_secrets(SECRETS))
	with open(SA_OTHER_SECRETS_PATH, "w") as f:
		f.write(sa.gen_secret_agent_secrets({"password": "other"}))

	tls_cfg = sa.tls_cfg(cert_file=SA_CA_FILE, key_file=SA_KEY_FILE).get_cfg() if tls else ""
	with open(SA_CONF_PATH, "w") as f:
		f.write(sa.gen_secret_agent_conf(resources={RESOURCE: SA_SECRETS_PATH,
			"other": SA_OTHER_SECRETS_PATH}, tls_cfg=tls_cfg))

	agent = sa.get_secret_agent(config=SA_CONF_PATH)
	try:
		agent.start()
		wait_for_agent(tls)
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
		cwd=lib.absolute_path("../.."), stdin=subprocess.DEVNULL, capture_output=True,
		timeout=120, env=env)
	return proc.returncode, proc.stdout.decode(errors="replace") + \
		proc.stderr.decode(errors="replace")


def fetched(name):
	return "secrets:%s:%s" % (RESOURCE, name)


def b64(value):
	return base64.b64encode(value.encode()).decode()


def literal(password):
	return "b64:" + b64(password)


def assert_no_secret(out):
	for name in ["password", "wrong", "env-ref", "max"]:
		assert SECRETS[name] not in out, out
		assert b64(SECRETS[name]) not in out, out


def password_args(form, value):
	return {"separate": ["--password", value], "long": ["--password=" + value],
		"attached": ["-P" + value]}[form]


def closed_port():
	with socket.socket() as s:
		s.bind(("127.0.0.1", 0))
		return str(s.getsockname()[1])


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


def record_values(set_name=SET_NAME):
	return sorted(bins["v"] for _, _, bins in
		STATE["client"].query("test", set_name).results())


def truncate(set_name=SET_NAME):
	STATE["client"].truncate("test", set_name, 0)
	for _ in range(100):
		if not record_values(set_name):
			return
		time.sleep(0.1)
	assert record_values(set_name) == []


def round_trip(backup_options, restore_options, env=None):
	path = backup_path()
	rc, out = run("asbackup", *backup_options, "-n", "test", "-s", SET_NAME,
		*backup_target(path), env=env)
	assert rc == 0, out
	assert_no_secret(out)

	truncate()
	rc, out = run("asrestore", *restore_options, *restore_source(path), env=env)
	assert rc == 0, out
	assert_no_secret(out)
	assert record_values() == list(range(N_RECORDS))


def assert_rejected_by_server(rc, out):
	assert rc != 0, out
	assert SERVER_ERROR in out, out
	assert "secret" not in out.lower(), out
	assert "--password" not in out, out
	assert_no_secret(out)


@pytest.mark.parametrize("form", PASSWORD_FORMS)
def test_round_trip_with_fetched_credentials(agent, form):
	login = [*server_args(), "--user", fetched("user"),
		*password_args(form, fetched("password")), *agent_args()]
	round_trip(login, login)


@pytest.mark.parametrize("tool", TOOLS)
def test_wrong_fetched_password_is_rejected_by_the_server(agent, tool):
	rc, out = run(tool, *server_args(), "--user", fetched("user"), "--password",
		fetched("wrong"), *agent_args(), *tool_target(tool))
	assert_rejected_by_server(rc, out)


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("form", PASSWORD_FORMS)
def test_reference_is_not_sent_as_the_password(agent, tool, form):
	"""
	The user's password is the reference itself, so only sending the reference
	instead of the fetched value would log in.
	"""
	rc, out = run(tool, *server_args(), "--user", "sa-literal",
		*password_args(form, literal(USERS["sa-literal"])), *tool_target(tool))
	assert rc == 0, out

	rc, out = run(tool, *server_args(), "--user", "sa-literal",
		*password_args(form, fetched("wrong")), *agent_args(), *tool_target(tool))
	assert_rejected_by_server(rc, out)


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("form", PASSWORD_FORMS)
@pytest.mark.parametrize("user,reachable,code,detail", [
	("sa-literal", False, 3, "secret-agent: ERR: connect failed"),
	("sa-missing-key", True, 1, "secret-agent: ERR: response: absent not present in file "),
	("sa-missing-resource", True, 1,
		"secret-agent: ERR: response: resource not found in config: absent\n"),
], ids=["agent_unreachable", "missing_key", "missing_resource"])
def test_failed_fetch_never_sends_reference(agent, tool, form, user, reachable, code, detail):
	"""
	Each user's password is the reference itself, so falling back to sending the
	reference after a failed fetch would log in.
	"""
	reference = USERS[user]
	rc, out = run(tool, *server_args(), "--user", user, "--password", literal(reference),
		*tool_target(tool))
	assert rc == 0, out

	if tool == "asbackup":
		path = backup_path()
		target = ["-n", "test", "-s", SET_NAME, *backup_target(path)]
	else:
		truncate(PROBE_SET)
		target = restore_source(STATE["probe_backup"])

	rc, out = run(tool, *server_args(), "--user", user, *password_args(form, reference),
		"--sa-address", "127.0.0.1", "--sa-port", sa.SA_PORT if reachable else closed_port(),
		*target)
	assert rc == 1, out
	assert "secret agent request failed err code: %d\n" % code in out, out
	assert detail in out, out
	assert SERVER_ERROR not in out, out
	assert_no_secret(out)
	if tool == "asbackup":
		assert not os.path.exists(path), out
	else:
		assert record_values(PROBE_SET) == [], out


def test_fetched_value_is_not_resolved_again(agent):
	"""
	The fetched value is env:ASB_SA_UNSET, which is also the user's password, so
	it only logs in if it is used as is rather than read from the environment.
	"""
	env = {k: v for k, v in os.environ.items() if k not in ("FEATKEY", UNSET_ENV)}
	login = [*server_args(), "--user", "sa-env", "--password", fetched("env-ref"),
		*agent_args()]
	round_trip(login, login, env=env)


@pytest.mark.parametrize("address,ca_option", [
	("localhost", "--sa-ca-file"),
	(sa.SA_TLS_ADDR, "--sa-ca-file"),
	("localhost", "--sa-cafile"),
], ids=["hostname", "ip", "legacy_sa_cafile"])
def test_tls_agent(tls_agent, address, ca_option):
	login = [*server_args(), "--user", fetched("user"), "--password", fetched("password"),
		"--sa-address", address, "--sa-port", sa.SA_PORT, ca_option, SA_CA_FILE]
	round_trip(login, login)


def config_file(sa_port):
	path = os.path.join(tempfile.mkdtemp(dir=STATE["dir"]), "astools.conf")
	with open(path, "w") as f:
		f.write('[cluster]\nhost = "127.0.0.1"\nport = %d\nuser = "%s"\npassword = "%s"\n'
			'[secret-agent]\nsa-address = "localhost"\nsa-port = "%s"\nsa-ca-file = "%s"\n'
			% (STATE["port"], fetched("user"), fetched("password"), sa_port, SA_CA_FILE))
	return path


def test_config_file(tls_agent):
	"""
	The agent only speaks TLS, so the tools reach it only if they read the
	[secret-agent] section rather than falling back to the plain defaults.
	"""
	path = config_file(sa.SA_PORT)
	round_trip(["--only-config-file", path], ["--only-config-file", path])


@pytest.mark.parametrize("tool", TOOLS)
def test_config_file_sa_port_is_read(tls_agent, tool):
	rc, out = run(tool, "--only-config-file", config_file(closed_port()), *tool_target(tool))
	assert rc == 1, out
	assert "secret agent request failed err code: 3\n" in out, out
	assert SERVER_ERROR not in out, out
	assert_no_secret(out)


def test_restore_with_fetched_password(agent):
	round_trip([*server_args(), "--user", USER, "--password", PASSWORD],
		[*server_args(), "--user", USER, "--password", fetched("password"), *agent_args()])


def test_maximum_length_password(agent):
	assert len(MAX_PASSWORD) == 63
	login = [*server_args(), "--user", "sa-max", "--password", fetched("max"),
		*agent_args()]
	round_trip(login, login)
