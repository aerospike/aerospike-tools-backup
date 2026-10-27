# coding=UTF-8

"""
Tests how asbackup and asrestore read a password that is not given on the
command line: once per run, from the terminal or from one line of stdin.

The tools log in through a proxy that answers every login itself, as a server
without security does, and forwards everything else to a single CE node. That
lets a test see each login, and so which password was read, without an
Enterprise server.
"""

import os
import pty
import select
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import termios
import threading
import time

import aerospike
import pytest

import aerospike_servers as as_srv
import lib

CONTAINER_NAME = "asb-password-test"
TLS_NAME = "asb-pw"
KEY_PASSWORD = "kpass"
SET_NAME = "pw"
N_RECORDS = 100
ADMIN_MESSAGE_TYPE = 2
SECURITY_NOT_ENABLED = 52

STATE = {}


def recv_exact(sock, size):
	data = b""
	while len(data) < size:
		chunk = sock.recv(size - len(data))
		if not chunk:
			return None
		data += chunk
	return data


class LoginProxy:
	"""
	Answers each login with SECURITY_NOT_ENABLED and records it, and relays all
	other messages to the backend node.
	"""

	def __init__(self, tls_context=None):
		self.tls_context = tls_context
		self.logins = []
		self.server = socket.socket()
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind(("127.0.0.1", 0))
		self.server.listen(64)
		self.port = self.server.getsockname()[1]
		threading.Thread(target=self.accept, daemon=True).start()

	def accept(self):
		while True:
			try:
				conn, _ = self.server.accept()
			except OSError:
				return
			threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

	def serve(self, conn):
		try:
			if self.tls_context is not None:
				conn = self.tls_context.wrap_socket(conn, server_side=True)
			backend = socket.create_connection(("127.0.0.1", STATE["port"]))
		except (OSError, ssl.SSLError):
			conn.close()
			return

		threading.Thread(target=self.relay, args=(backend, conn), daemon=True).start()

		try:
			while True:
				header = recv_exact(conn, 8)
				if header is None:
					break
				body = recv_exact(conn, int.from_bytes(header, "big") & 0xFFFFFFFFFFFF)
				if body is None:
					break
				if header[1] == ADMIN_MESSAGE_TYPE:
					self.logins.append(body[16:])
					reply = bytearray(16)
					reply[1] = SECURITY_NOT_ENABLED
					conn.sendall(bytes([2, ADMIN_MESSAGE_TYPE]) + (16).to_bytes(6, "big") +
						bytes(reply))
				else:
					backend.sendall(header + body)
		except OSError:
			pass
		finally:
			for sock in (conn, backend):
				try:
					sock.close()
				except OSError:
					pass

	def relay(self, src, dst):
		try:
			while True:
				data = src.recv(65536)
				if not data:
					break
				dst.sendall(data)
		except OSError:
			pass
		finally:
			for sock in (src, dst):
				try:
					sock.shutdown(socket.SHUT_RDWR)
				except OSError:
					pass

	def credentials(self):
		return set(self.logins)

	def close(self):
		self.server.close()


def openssl(*args):
	subprocess.check_call(["openssl"] + list(args), cwd=STATE["dir"],
		stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_tls_files():
	with open(os.path.join(STATE["dir"], "san.cnf"), "w") as f:
		f.write("subjectAltName=DNS:%s\n" % TLS_NAME)

	openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
		"-out", "ca.pem", "-days", "2", "-subj", "/CN=asb-pw-ca")
	openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key",
		"-out", "server.csr", "-subj", "/CN=" + TLS_NAME)
	openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
		"-CAcreateserial", "-out", "server.pem", "-days", "2", "-extfile", "san.cnf")
	openssl("req", "-newkey", "rsa:2048", "-keyout", "client.key", "-passout",
		"pass:" + KEY_PASSWORD, "-out", "client.csr", "-subj", "/CN=admin")
	openssl("x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
		"-CAcreateserial", "-out", "client.pem", "-days", "2")

	context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	context.load_cert_chain(os.path.join(STATE["dir"], "server.pem"),
		os.path.join(STATE["dir"], "server.key"))
	STATE["tls_context"] = context


def remove_container():
	try:
		as_srv.DOCKER_CLIENT.containers.get(CONTAINER_NAME).remove(force=True)
	except Exception:
		pass


def free_port():
	sock = socket.socket()
	sock.bind(("127.0.0.1", 0))
	port = sock.getsockname()[1]
	sock.close()
	return port


def start_node():
	conf = os.path.join(STATE["dir"], "aerospike.conf")
	with open(conf, "w") as f:
		f.write("service {\n\tcluster-name asb-pw\n\tproto-fd-max 1024\n}\n"
			"logging {\n\tconsole {\n\t\tcontext any info\n\t}\n}\n"
			"network {\n"
			"\tservice {\n\t\taddress any\n\t\tport 3000\n"
			"\t\taccess-address 127.0.0.1 virtual\n\t}\n"
			"\theartbeat {\n\t\tmode mesh\n\t\tport 3002\n\t}\n"
			"\tfabric {\n\t\tport 3001\n\t}\n"
			"\tinfo {\n\t\tport 3003\n\t}\n"
			"}\n"
			"namespace test {\n\treplication-factor 1\n"
			"\tstorage-engine memory {\n\t\tdata-size 1G\n\t}\n}\n")

	remove_container()
	as_srv.DOCKER_CLIENT.images.pull(as_srv.SERVER_IMAGE)
	STATE["port"] = free_port()
	as_srv.DOCKER_CLIENT.containers.run(as_srv.SERVER_IMAGE,
		command="/usr/bin/asd --foreground --config-file /opt/asb-pw/aerospike.conf",
		ports={"3000/tcp": STATE["port"]},
		volumes={STATE["dir"]: {"bind": "/opt/asb-pw", "mode": "ro"}},
		tty=True, detach=True, name=CONTAINER_NAME)

	for attempt in range(60):
		try:
			STATE["client"] = aerospike.client(
				{"hosts": [("127.0.0.1", STATE["port"])]}).connect()
			return
		except Exception:
			if attempt == 59:
				raise
			time.sleep(0.5)


def setup_module(module):
	STATE["dir"] = tempfile.mkdtemp()
	os.chmod(STATE["dir"], 0o755)
	make_tls_files()
	start_node()

	for i in range(N_RECORDS):
		STATE["client"].put(("test", SET_NAME, i), {"v": i})

	STATE["dir_backup"] = os.path.join(STATE["dir"], "backup")
	STATE["file_backup"] = os.path.join(STATE["dir"], "backup.asb")
	rc, out, _ = run("asbackup", b"", "-h", "127.0.0.1", "-p", str(STATE["port"]),
		"-n", "test", "-s", SET_NAME, "-d", STATE["dir_backup"])
	assert rc == 0, out
	rc, out, _ = run("asbackup", b"", "-h", "127.0.0.1", "-p", str(STATE["port"]),
		"-n", "test", "-s", SET_NAME, "-o", STATE["file_backup"])
	assert rc == 0, out


def teardown_module(module):
	client = STATE.pop("client", None)
	if client is not None:
		client.close()
	remove_container()
	shutil.rmtree(STATE["dir"], ignore_errors=True)


def run(tool, data, *options, valgrind_log=None):
	"""
	Runs the tool with no controlling terminal and data on stdin. Returns the
	exit code, the output and whatever the tool left unread on stdin. With
	valgrind_log, the tool runs under valgrind, which reports there.
	"""
	command = [os.path.join("test_target", tool), "--no-config-file"] + list(options)

	if valgrind_log is not None:
		command = ["valgrind", "--leak-check=full", "--show-reachable=yes",
			"--suppressions=" + lib.absolute_path(lib.VAL_SUP_FILE),
			"--log-file=" + valgrind_log] + command

	read_end, write_end = os.pipe()
	os.write(write_end, data)
	os.close(write_end)

	try:
		proc = subprocess.run(command, cwd=lib.absolute_path("../.."), stdin=read_end,
			capture_output=True, start_new_session=True, timeout=120)
		os.set_blocking(read_end, False)
		try:
			left = os.read(read_end, 65536)
		except BlockingIOError:
			left = b""
	finally:
		os.close(read_end)

	return proc.returncode, proc.stdout.decode(errors="replace") + \
		proc.stderr.decode(errors="replace"), left


def via(proxy):
	return ["-h", "127.0.0.1", "-p", str(proxy.port)]


def via_tls(proxy):
	return ["-h", "127.0.0.1:%s:%d" % (TLS_NAME, proxy.port), "--tls-enable",
		"--tls-cafile", os.path.join(STATE["dir"], "ca.pem"),
		"--tls-certfile", os.path.join(STATE["dir"], "client.pem"),
		"--tls-keyfile", os.path.join(STATE["dir"], "client.key")]


def backup_target():
	return ["-o", os.path.join(tempfile.mkdtemp(dir=STATE["dir"]), "out.asb")]


def restore_source():
	if lib.is_dir_mode():
		return ["-d", STATE["dir_backup"]]
	return ["-i", STATE["file_backup"]]


def truncate():
	STATE["client"].truncate("test", SET_NAME, 0)
	for _ in range(100):
		if not record_count():
			return
		time.sleep(0.1)
	assert record_count() == 0


def record_count():
	return len(STATE["client"].scan("test", SET_NAME).results())


def login_with(password):
	"""
	Returns the login a literal -P password produces.
	"""
	proxy = LoginProxy()
	try:
		rc, out, _ = run("asbackup", b"", *via(proxy), "-U", "admin", "-P", password,
			"-n", "test", "-s", SET_NAME, "--estimate")
		assert rc == 0, out
		assert len(proxy.credentials()) == 1, out
		return proxy.credentials().pop()
	finally:
		proxy.close()


def test_backup_to_file_reads_the_password_once():
	proxy = LoginProxy()
	try:
		rc, out, left = run("asbackup", b"pw\nleft\n", *via(proxy), "-U", "admin", "-P",
			"-n", "test", "-s", SET_NAME, *backup_target())
	finally:
		proxy.close()

	assert left == b"left\n", "the estimate pass read stdin again:\n" + out
	assert proxy.credentials() == {login_with("pw")}, out
	assert rc == 0, out


def test_backup_to_stdout_reads_the_password_once():
	proxy = LoginProxy()
	try:
		rc, out, left = run("asbackup", b"pw\nleft\n", *via(proxy), "-U", "admin", "-P",
			"-n", "test", "-s", SET_NAME, "-o", "-")
	finally:
		proxy.close()

	assert left == b"left\n", "the estimate pass read stdin again:\n" + out[-2000:]
	assert proxy.credentials() == {login_with("pw")}, out[-2000:]
	assert rc == 0, out[-2000:]


def test_backup_to_file_reads_the_keyfile_password_once():
	proxy = LoginProxy(STATE["tls_context"])
	try:
		rc, out, left = run("asbackup", (KEY_PASSWORD + "\nleft\n").encode(),
			*via_tls(proxy), "--tls-keyfile-password", "-n", "test", "-s", SET_NAME,
			*backup_target())
	finally:
		proxy.close()

	assert left == b"left\n", "the estimate pass read stdin again:\n" + out
	assert rc == 0, out


def test_backup_to_file_reads_both_passwords_once():
	proxy = LoginProxy(STATE["tls_context"])
	try:
		rc, out, left = run("asbackup", ("pw\n" + KEY_PASSWORD + "\nleft\n").encode(),
			*via_tls(proxy), "-U", "admin", "-P", "--tls-keyfile-password", "-n", "test",
			"-s", SET_NAME, *backup_target())
	finally:
		proxy.close()

	assert left == b"left\n", "the estimate pass read stdin again:\n" + out
	assert len(proxy.credentials()) == 1, out
	assert rc == 0, out


def test_restore_reads_the_password_once():
	truncate()
	proxy = LoginProxy()
	try:
		rc, out, left = run("asrestore", b"pw\nleft\n", *via(proxy), "-U", "admin", "-P",
			*restore_source())
	finally:
		proxy.close()

	assert left == b"left\n", "the second connection read stdin again:\n" + out
	assert proxy.credentials() == {login_with("pw")}, out
	assert rc == 0, out
	assert record_count() == N_RECORDS


def test_restore_from_stdin_reads_the_password_once():
	truncate()
	with open(STATE["file_backup"], "rb") as f:
		data = b"pw\n" + f.read()

	proxy = LoginProxy()
	try:
		rc, out, _ = run("asrestore", data, *via(proxy), "-U", "admin", "-P", "-i", "-")
	finally:
		proxy.close()

	assert rc == 0, out
	assert proxy.credentials() == {login_with("pw")}, out
	assert record_count() == N_RECORDS


def test_restore_reads_the_keyfile_password_once():
	truncate()
	proxy = LoginProxy(STATE["tls_context"])
	try:
		rc, out, left = run("asrestore", (KEY_PASSWORD + "\nleft\n").encode(),
			*via_tls(proxy), "--tls-keyfile-password", *restore_source())
	finally:
		proxy.close()

	assert left == b"left\n", "the second connection read stdin again:\n" + out
	assert rc == 0, out
	assert record_count() == N_RECORDS


@pytest.mark.skipif(shutil.which("valgrind") is None, reason="valgrind is not installed")
def test_restore_frees_the_keyfile_password():
	"""
	The second connection takes the keyfile password from the first, so the copy
	it replaces must be freed.
	"""
	truncate()
	log = os.path.join(STATE["dir"], "val_keyfile_pw.log")
	proxy = LoginProxy(STATE["tls_context"])
	try:
		rc, out, _ = run("asrestore", (KEY_PASSWORD + "\n").encode(), *via_tls(proxy),
			"--tls-keyfile-password", *restore_source(), valgrind_log=log)
	finally:
		proxy.close()

	with open(log) as f:
		report = f.read()

	assert rc == 0, out + report
	assert not lib.parse_val_logs(log), report
	assert record_count() == N_RECORDS


def type_password(tool, line, *options, ignore=(), send=None):
	"""
	Runs the tool with a terminal as stdin but no controlling terminal and types
	line once echo is off. The signals in ignore are ignored from the start, and
	send is delivered half a second before line is typed. Returns the exit code,
	stdout, stderr, what the terminal echoed, whether echo was off before typing
	and whether it is on again at the end.
	"""
	master, slave = pty.openpty()
	echo_was_off = False
	echoed = b""

	def ignore_signals():
		for sig in ignore:
			signal.signal(sig, signal.SIG_IGN)

	try:
		proc = subprocess.Popen([os.path.join("test_target", tool), "--no-config-file",
				*options],
			cwd=lib.absolute_path("../.."), stdin=slave, stdout=subprocess.PIPE,
			stderr=subprocess.PIPE, start_new_session=True,
			preexec_fn=ignore_signals if ignore else None)

		deadline = time.time() + 5
		while time.time() < deadline:
			if not termios.tcgetattr(slave)[3] & termios.ECHO:
				echo_was_off = True
				break
			time.sleep(0.05)

		if send is not None:
			proc.send_signal(send)
			time.sleep(0.5)

		os.write(master, line)

		while select.select([master], [], [], 1)[0]:
			try:
				chunk = os.read(master, 1024)
			except OSError:
				break
			if not chunk:
				break
			echoed += chunk

		out, err = proc.communicate(timeout=60)
		echo_restored = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
	finally:
		os.close(master)
		os.close(slave)

	return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace"), \
		echoed, echo_was_off, echo_restored


def test_typed_password_without_controlling_terminal():
	"""
	Under setsid or su -c, stdin is a terminal but /dev/tty cannot be opened.
	The tool prompts on stderr, reads with echo off and uses the typed line as is.
	"""
	proxy = LoginProxy()
	try:
		rc, out, err, echoed, echo_was_off, echo_restored = type_password("asbackup",
			b" pw \n", *via(proxy), "-U", "admin", "-P", "-n", "test", "-s", SET_NAME,
			"-d", tempfile.mkdtemp(dir=STATE["dir"]))
	finally:
		proxy.close()

	output = out + err
	assert echo_was_off, "echo was not turned off before the password was typed:\n" + output
	assert b"pw" not in echoed, echoed
	assert echo_restored
	assert "Enter Password: " in err, output
	assert rc == 0, output
	assert proxy.credentials() == {login_with(" pw ")}, output


def test_backup_prompt_survives_an_ignored_sigint():
	"""
	A signal the tool starts with ignored, as after trap '' INT, stays ignored
	while the password is typed, so the read goes on and the typed line is used.
	"""
	proxy = LoginProxy()
	try:
		rc, out, err, _, _, _ = type_password("asbackup", b"pw\n", *via(proxy), "-U",
			"admin", "-P", "-n", "test", "-s", SET_NAME, "-d",
			tempfile.mkdtemp(dir=STATE["dir"]), ignore=(signal.SIGINT,),
			send=signal.SIGINT)
	finally:
		proxy.close()

	assert proxy.credentials() == {login_with("pw")}, out + err
	assert rc == 0, out + err


def test_restore_prompt_survives_an_ignored_sighup():
	"""
	As above for asrestore, which sets its own SIGINT handler before it prompts,
	so an ignored SIGHUP is used instead.
	"""
	truncate()
	proxy = LoginProxy()
	try:
		rc, out, err, _, _, _ = type_password("asrestore", b"pw\n", *via(proxy), "-U",
			"admin", "-P", *restore_source(), ignore=(signal.SIGHUP,),
			send=signal.SIGHUP)
	finally:
		proxy.close()

	assert proxy.credentials() == {login_with("pw")}, out + err
	assert rc == 0, out + err
	assert record_count() == N_RECORDS


def echo_after_interrupted_prompt(tool, *options):
	"""
	Sends SIGINT while the tool waits for a typed password with no controlling
	terminal, and returns whether the terminal echoes once the signal is handled.
	"""
	master, slave = pty.openpty()
	proc = None

	try:
		proc = subprocess.Popen([os.path.join("test_target", tool), "--no-config-file",
				"-h", "127.0.0.1", "-p", "1", "-U", "admin", "-P", *options],
			cwd=lib.absolute_path("../.."), stdin=slave, stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL, start_new_session=True)

		deadline = time.time() + 2
		while time.time() < deadline and termios.tcgetattr(slave)[3] & termios.ECHO:
			time.sleep(0.05)

		proc.send_signal(signal.SIGINT)

		try:
			proc.wait(timeout=5)
		except subprocess.TimeoutExpired:
			pass

		return bool(termios.tcgetattr(slave)[3] & termios.ECHO)
	finally:
		if proc is not None and proc.poll() is None:
			proc.kill()
			proc.wait()
		os.close(master)
		os.close(slave)


def test_interrupted_prompt_restores_echo():
	"""
	asbackup prompts before it installs its signal handlers, so SIGINT ends it;
	asrestore's handler only sets a stop flag, so its read keeps waiting. Either
	way the terminal must echo again.
	"""
	assert echo_after_interrupted_prompt("asbackup", "-n", "test", "-d",
		tempfile.mkdtemp(dir=STATE["dir"])), "asbackup left echo off"
	assert echo_after_interrupted_prompt("asrestore", "-d", STATE["dir_backup"]), \
		"asrestore left echo off"
