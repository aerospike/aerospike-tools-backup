# coding=UTF-8

"""
Tests backing up and restoring to S3.
"""

import contextlib
import os
import socket

import aerospike_servers as as_srv
import lib
import minio_servers as min_srv
import record_gen
from run_backup import backup_async, restore_async, backup_to_directory, backup_to_file, multi_backup_and_restore

S3_BUCKET = "asbackup-test"
S3_REGION = "us-west-1"
S3_ENV = {
	"AWS_ACCESS_KEY_ID": "key",
	"AWS_SECRET_ACCESS_KEY": "secretkey"
}


MINIO_NAME = "asbackup-minio"

COMMON_S3_OPTS = ['--s3-endpoint-override', '127.0.0.1:9000']


def do_s3_backup(max_interrupts, n_records=10000, backup_opts=None,
		restore_opts=None, state_file_dir=False, state_file_explicit=False,
		backup_cout=0, state_file_to_s3=False):
	if backup_opts == None:
		backup_opts = []
	if restore_opts == None:
		restore_opts = []

	as_srv.start_aerospike_servers()

	backup_files_loc = lib.temporary_path("minio_dir")
	os.mkdir(backup_files_loc, 0o755)
	min_srv.start_minio_server(MINIO_NAME, backup_files_loc)

	# make the bucket
	os.mkdir(backup_files_loc + "/" + S3_BUCKET, 0o755)

	for comp_enc_mode in [
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]:

		i = 1
		state_file = None
		context = {}

		prev_rec_total = 0
		prev_bytes_total = 0

		if lib.is_dir_mode():
			path = "s3://" + S3_BUCKET + "/test_dir"
		else:
			path = "s3://" + S3_BUCKET + "/test_file.asb"

		env = S3_ENV

		if state_file_dir:
			state_path = lib.temporary_path("state_dir")
			os.mkdir(state_path, 0o755)
			state_file = os.path.join(state_path, lib.NAMESPACE + '.asb.state')
		elif state_file_explicit:
			state_path = lib.temporary_path("asb.state")
			state_file = state_path
		
		if state_file_to_s3:
			if state_file_explicit:
				state_path = "s3://" + S3_BUCKET + "/test_dir"
				state_file = state_path + "/" + lib.NAMESPACE + '.asb.state'
				state_path = state_file
			else:
				# state path cannot be the same as backup directory
				state_path = "s3://" + S3_BUCKET + "/state_file.asb.state"
				state_file = state_path

		while True:
			opts = comp_enc_mode + backup_opts

			if i > 1:
				if state_file is None:
					# if not using explicit backup state, reconstruct the backup
					# state to where we know it to be
					state_file = lib.NAMESPACE + ".asb.state"
				opts += ['--continue', state_file]
				filler = lambda context: None
			else:
				opts += ['--remove-files']
				filler = lambda context: record_gen.put_records(n_records, context,
						lib.SET, False, 0)

			if state_file_dir or state_file_explicit or state_file_to_s3:
				opts += ['--state-file-dst', state_path]

			opts += COMMON_S3_OPTS

			use_opts = opts
			# don't throttle if we won't be interrupting the backup
			if i > max_interrupts and ('--records-per-second' in opts):
				idx = opts.index('--records-per-second')
				use_opts = opts[:idx] + opts[idx + 2:]

			bup, path = backup_async(filler,
					env=env,
					context=context,
					backup_opts=use_opts,
					path=path)

			if i <= max_interrupts:
				lib.sync_wait(lib.kill_after(bup, dt=20))

			bup_ret = lib.sync_wait(bup.wait())
			stdout, stderr = lib.sync_wait(bup.communicate())
			print(stderr.decode())

			(record_total, sindexes, udfs, bytes_total, _) = \
					record_gen.backup_output_get_records_written(stderr.decode('utf-8'))
			assert(record_total >= prev_rec_total)
			assert(bytes_total >= prev_bytes_total)
			assert(sindexes == 0)
			assert(udfs == 0)

			prev_rec_total = record_total
			prev_bytes_total = bytes_total

			if bup_ret == 0 or i > max_interrupts:
				assert(record_total == n_records)
				break
			else:
				i += 1
		assert(bup_ret == 0)

		# give database a second to update
		lib.safe_sleep(1)

		restore_opts += COMMON_S3_OPTS
		res = restore_async(path, env=env,
				restore_opts=comp_enc_mode + restore_opts)
		ret_code = lib.sync_wait(res.wait())
		stdout, stderr = lib.sync_wait(res.communicate())
		print(stderr.decode())
		assert(ret_code == 0)

		(expired, skipped, err_ignored, inserted, failed, existed, fresher) = \
				record_gen.restore_output_get_records_written(stderr.decode('utf-8'))
		assert(expired == 0)
		assert(skipped == 0)
		assert(err_ignored == 0)
		assert(inserted == n_records)
		assert(failed == 0)
		assert(existed == 0)
		assert(fresher == 0)

		record_gen.check_records(n_records, context, lib.SET, False, 0)

		# remove backup artifacts
		if lib.is_dir_mode():
			backup_to_directory(path, *COMMON_S3_OPTS, '--remove-artifacts', env=env)
		else:
			backup_to_file(path, *COMMON_S3_OPTS, '--remove-artifacts', env=env)
		
	min_srv.stop_minio_server(MINIO_NAME)

def test_s3_state_file_to_s3():
	do_s3_backup(1, n_records=50000, backup_opts=['--records-per-second', '2000'], state_file_to_s3=True)

def test_s3_backup_multiple_files_state_file_to_s3():
	do_s3_backup(10, n_records=10000, backup_opts=['--file-limit', '1'], state_file_to_s3=True, state_file_explicit=True)

def test_s3_backup_small():
	do_s3_backup(0, n_records=100, backup_opts=['--s3-region', S3_REGION])

def test_s3_backup():
	do_s3_backup(0)

def test_s3_backup_multiple_files():
	do_s3_backup(0, n_records=10000, backup_opts=['--file-limit', '1', '--s3-connect-timeout', '2000'], restore_opts=['--s3-connect-timeout', '2000'])

def test_s3_backup_interrupt():
	do_s3_backup(1, n_records=10000, backup_opts=['--records-per-second', '200'])

def test_s3_backup_multiple_files_interrupt():
	do_s3_backup(10, n_records=10000, backup_opts=['--file-limit', '1'])

def test_s3_restore_directory_list():
	as_srv.start_aerospike_servers()

	backup_files_loc = lib.temporary_path("minio_dir")
	os.mkdir(backup_files_loc, 0o755)
	min_srv.start_minio_server(MINIO_NAME, backup_files_loc)

	# make the buckets
	backup_bucket_names = ["dir1", "dir2"]
	paths = []
	restore_dirs = ""
	for bucket in backup_bucket_names:

		path_string = backup_files_loc + "/" + bucket
		os.mkdir(path_string, 0o755)

		s3_path = "s3://" + bucket + "/test_dir"
		restore_dirs += s3_path + ","
		paths.append(s3_path)

	# trim trailing comma
	restore_dirs = restore_dirs[:-1]

	n_records = 8000
	filler = lambda context: record_gen.put_records(n_records, context, lib.SET, False, 0)
	checker = lambda context: record_gen.check_records(n_records, context, lib.SET, False, 0)

	backup_options1 = COMMON_S3_OPTS + ["-d", paths[0], "--partition-list", "0-2048"]
	backup_options2 = COMMON_S3_OPTS + ["-d", paths[1], "--partition-list", "2048-2048"]
	restore_options = COMMON_S3_OPTS + ["--directory-list", restore_dirs]

	multi_backup_and_restore(filler, None, checker, backup_opts=[backup_options1, backup_options2],
		 restore_opts=restore_options, env=S3_ENV, do_compress_and_encrypt=False)

	# remove backup artifacts
	for path in paths:
		backup_to_directory(path, *COMMON_S3_OPTS, '--remove-artifacts', env=S3_ENV)

	min_srv.stop_minio_server(MINIO_NAME)

@contextlib.contextmanager
def _dead_proxy_env(extra=None):
	"""
	Context manager that yields an env dict with HTTP_PROXY/HTTPS_PROXY/ALL_PROXY
	pointing at a port that is bound but not listening (guaranteed ECONNREFUSED),
	and with NO_PROXY cleared.  The socket is held open for the lifetime of the
	``with`` block so the port cannot be reused by another process between setup
	and the actual connection attempt.

	Pass ``extra`` to override or extend individual keys, e.g.::

		with _dead_proxy_env(extra={"NO_PROXY": "127.0.0.1"}) as env:
			...
	"""
	with socket.socket() as s:
		s.bind(('127.0.0.1', 0))
		# Deliberately NOT calling s.listen() — connections get ECONNREFUSED
		# immediately and the socket stays open until the with-block exits.
		dead_port = s.getsockname()[1]
		dead_addr = f"http://127.0.0.1:{dead_port}"
		env = {
			**S3_ENV,
			"HTTP_PROXY":  dead_addr,
			"http_proxy":  dead_addr,
			"HTTPS_PROXY": dead_addr,
			"https_proxy": dead_addr,
			"ALL_PROXY":   dead_addr,
			"all_proxy":   dead_addr,
			# Override any system NO_PROXY so 127.0.0.1 is not excluded.
			"NO_PROXY": "",
			"no_proxy": "",
		}
		if extra:
			env.update(extra)
		yield env
		# Socket closes here — after all assertions — so the port is never
		# recycled while a connection attempt is in flight.


def test_s3_allow_system_proxy():
	"""
	Two-part behavioral test for --s3-allow-system-proxy:

	1. Without the flag: HTTP_PROXY/HTTPS_PROXY env vars are ignored and the
	   backup reaches MinIO directly — backup succeeds.
	2. With the flag: libcurl honors HTTP_PROXY and routes through a dead proxy —
	   backup fails, proving the env var is now in effect.
	"""
	as_srv.start_aerospike_servers()

	backup_files_loc = lib.temporary_path("minio_proxy_dir")
	os.mkdir(backup_files_loc, 0o755)
	min_srv.start_minio_server(MINIO_NAME, backup_files_loc)
	os.mkdir(backup_files_loc + "/" + S3_BUCKET, 0o755)

	if lib.is_dir_mode():
		path = "s3://" + S3_BUCKET + "/proxy_test_dir"
	else:
		path = "s3://" + S3_BUCKET + "/proxy_test.asb"

	with _dead_proxy_env() as dead_env:
		# Part 1: without --s3-allow-system-proxy the proxy env is ignored →
		# direct connection to MinIO works.
		bup, path = backup_async(
			lambda context: record_gen.put_records(100, context, lib.SET, False, 0),
			env=dead_env,
			backup_opts=COMMON_S3_OPTS + ['--remove-files'],
			path=path,
		)
		bup_ret = lib.sync_wait(bup.wait())
		assert bup_ret == 0, \
			"backup without --s3-allow-system-proxy should succeed even with a dead HTTP_PROXY set"

		# Part 2: with --s3-allow-system-proxy libcurl honors HTTP_PROXY → routes
		# through the dead proxy → backup fails.
		bup, path = backup_async(
			lambda context: None,
			env=dead_env,
			backup_opts=COMMON_S3_OPTS + ['--remove-files', '--s3-allow-system-proxy'],
			path=path,
		)
		bup_ret = lib.sync_wait(bup.wait())
		assert bup_ret != 0, \
			"backup with --s3-allow-system-proxy and a dead HTTP_PROXY should fail " \
			"(expected ECONNREFUSED or connection-timeout to proxy)"

	min_srv.stop_minio_server(MINIO_NAME)


def test_s3_allow_system_proxy_restore():
	"""
	Restore counterpart to test_s3_allow_system_proxy. The ticket's acceptance
	criteria require both backup AND restore to succeed via the proxy env vars,
	so this test verifies the same two-part behavior for restore:

	1. Without --s3-allow-system-proxy: dead HTTP_PROXY/HTTPS_PROXY env vars
	   are ignored and restore reaches MinIO directly — restore succeeds.
	2. With --s3-allow-system-proxy: routes through the dead proxy — restore
	   fails (S3 client connects to dead port and errors out).

	Step 0 creates a real backup against MinIO without any proxy env in play,
	so there is data to restore.
	"""
	as_srv.start_aerospike_servers()

	backup_files_loc = lib.temporary_path("minio_proxy_restore_dir")
	os.mkdir(backup_files_loc, 0o755)
	min_srv.start_minio_server(MINIO_NAME, backup_files_loc)
	os.mkdir(backup_files_loc + "/" + S3_BUCKET, 0o755)

	if lib.is_dir_mode():
		path = "s3://" + S3_BUCKET + "/proxy_restore_test_dir"
	else:
		path = "s3://" + S3_BUCKET + "/proxy_restore_test.asb"

	# Step 0: produce a backup to restore from. Direct connection, no proxy env.
	bup, path = backup_async(
		lambda context: record_gen.put_records(100, context, lib.SET, False, 0),
		env=S3_ENV,
		backup_opts=COMMON_S3_OPTS + ['--remove-files'],
		path=path,
	)
	bup_ret = lib.sync_wait(bup.wait())
	assert bup_ret == 0, "preparatory backup must succeed before restore parts run"

	with _dead_proxy_env() as dead_env:
		# Part 1: without --s3-allow-system-proxy the proxy env is ignored →
		# direct connection to MinIO works, restore succeeds.
		res = restore_async(path, env=dead_env, restore_opts=COMMON_S3_OPTS)
		res_ret = lib.sync_wait(res.wait())
		assert res_ret == 0, \
			"restore without --s3-allow-system-proxy should succeed even with a dead HTTP_PROXY set"

		# Part 2: with --s3-allow-system-proxy libcurl honors HTTPS_PROXY → routes
		# through the dead proxy → restore fails.
		res = restore_async(path, env=dead_env,
				restore_opts=COMMON_S3_OPTS + ['--s3-allow-system-proxy'])
		res_ret = lib.sync_wait(res.wait())
		assert res_ret != 0, \
			"restore with --s3-allow-system-proxy and a dead HTTP_PROXY should fail " \
			"(expected ECONNREFUSED or connection-timeout to proxy)"

	min_srv.stop_minio_server(MINIO_NAME)


def test_s3_allow_system_proxy_no_proxy_exempts_host():
	"""
	NO_PROXY exemption behavior: with --s3-allow-system-proxy on AND a dead
	proxy advertised via HTTPS_PROXY/HTTP_PROXY/ALL_PROXY AND NO_PROXY listing
	the destination host, the backup must SUCCEED because the destination is
	exempted from going through the proxy.

	This mirrors the realistic customer scenario where external traffic goes
	through a corporate proxy but internal services (their own MinIO/Ceph or
	an in-VPC S3 endpoint) must connect directly.
	"""
	as_srv.start_aerospike_servers()

	backup_files_loc = lib.temporary_path("minio_no_proxy_dir")
	os.mkdir(backup_files_loc, 0o755)
	min_srv.start_minio_server(MINIO_NAME, backup_files_loc)
	os.mkdir(backup_files_loc + "/" + S3_BUCKET, 0o755)

	if lib.is_dir_mode():
		path = "s3://" + S3_BUCKET + "/no_proxy_test_dir"
	else:
		path = "s3://" + S3_BUCKET + "/no_proxy_test.asb"

	# Dead proxy + NO_PROXY exempting the destination host.
	with _dead_proxy_env(extra={
		"NO_PROXY": "127.0.0.1",
		"no_proxy": "127.0.0.1",
	}) as env:
		bup, path = backup_async(
			lambda context: record_gen.put_records(100, context, lib.SET, False, 0),
			env=env,
			backup_opts=COMMON_S3_OPTS + ['--remove-files', '--s3-allow-system-proxy'],
			path=path,
		)
		bup_ret = lib.sync_wait(bup.wait())
		assert bup_ret == 0, \
			"backup with --s3-allow-system-proxy and NO_PROXY listing the destination host should succeed"

	min_srv.stop_minio_server(MINIO_NAME)

