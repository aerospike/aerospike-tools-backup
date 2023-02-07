# coding=UTF-8

"""
Aerospike backup tool running utilities.
"""
import aerospike_servers as as_srv
import lib

def backup(*options, env={}, do_async=False, pipe_stdout=None):
	"""
	Runs asbackup with the given options.
	"""
	print("Running asbackup")
	return lib.run("asbackup", *options, do_async=do_async,
			pipe_stdout=pipe_stdout, env=env)

def restore(*options, env={}, do_async=False, pipe_stdin=None):
	"""
	Runs asrestore with the given options.
	"""
	print("Running asrestore")
	return lib.run("asrestore", *options, do_async=do_async,
			pipe_stdin=pipe_stdin, env=env)

def backup_to_file(path, *options, env={}, do_async=False, pipe_stdout=None):
	"""
	Backup to the given file using the default options plus the given options.
	"""
	return backup("--output-file", path, \
			"--namespace", lib.NAMESPACE, \
			"--verbose", \
			*options,
			env=env, do_async=do_async, pipe_stdout=pipe_stdout)

def restore_from_file(path, *options, env={}, do_async=False, pipe_stdin=None):
	"""
	Restore from the given file using the default options plus the given options.
	"""
	return restore("--input", path, \
			"--verbose", \
			*options,
			env=env, do_async=do_async, pipe_stdin=pipe_stdin)

def backup_to_directory(path, *options, env={}, do_async=False):
	"""
	Backup to the given directory using the default options plus the given options.
	"""
	return backup("--directory", path, \
			"--namespace", lib.NAMESPACE, \
			"--verbose", \
			*options,
			env=env, do_async=do_async)

def restore_from_directory(path, *options, env={}, do_async=False):
	"""
	Restore from the given file using the default options plus the given options.
	"""
	return restore("--directory", path, \
			"--verbose", \
			*options,
			env=env, do_async=do_async)

def backup_async(filler, context={}, path=None, env={}, backup_opts=None,
		pipe_stdout=None):
	if backup_opts is None:
		backup_opts = []

	as_srv.start_aerospike_servers()

	filler(context)

	try:
		if lib.is_dir_mode():
			if path is None:
				path = lib.temporary_path("dir")
			return backup_to_directory(path, *backup_opts, env=env, do_async=True), path
		else:
			if path is None:
				path = lib.temporary_path("asb")
			return backup_to_file(path, *backup_opts, env=env, do_async=True,
					pipe_stdout=pipe_stdout), path

	except Exception:
		as_srv.reset_aerospike_servers()
		raise

def restore_async(path, env={}, restore_opts=None, pipe_stdin=None):
	try:
		# keep metadata (sets/indexes) so they can be erased after
		# asrestore runs
		as_srv.reset_aerospike_servers(keep_metadata=True)

		if restore_opts is None:
			restore_opts = []

		if lib.is_dir_mode():
			return restore_from_directory(path, *restore_opts, env=env, do_async=True)
		else:
			return restore_from_file(path, *restore_opts, env=env, do_async=True,
					pipe_stdin=pipe_stdin)

	except Exception:
		as_srv.reset_aerospike_servers()
		raise

def backup_and_restore(filler, preparer, checker, env={}, backup_opts=None,
		restore_opts=None, restore_delay=0.5, do_compress_and_encrypt=True):
	"""
	Do one backup-restore cycle.
	"""
	if backup_opts is None:
		backup_opts = ["--host=localhost"]

	if restore_opts is None:
		restore_opts = ["--host=localhost"]

	as_srv.start_aerospike_servers()

	context = {}
	# fill once, since we can just keep all data after running asrestore
	filler(context)

	for i, comp_enc_mode in enumerate([
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]):

		if not do_compress_and_encrypt and i > 0:
			break

		try:
			if lib.is_dir_mode():
				path = lib.temporary_path("dir")
				backup_to_directory(path, *(backup_opts + comp_enc_mode), env=env)
			else:
				path = lib.temporary_path("asb")
				backup_to_file(path, *(backup_opts + comp_enc_mode), env=env)

			# keep metadata (sets/indexes) so they can be erased after
			# asrestore runs
			as_srv.reset_aerospike_servers(keep_metadata=True)

			# give SMD time to get deleted
			lib.safe_sleep(restore_delay)

			if preparer is not None:
				preparer(context)

			if lib.is_dir_mode():
				restore_from_directory(path, *(restore_opts + comp_enc_mode), env=env)
			else:
				restore_from_file(path, *(restore_opts + comp_enc_mode), env=env)
			# give SMD time to be restored
			lib.safe_sleep(restore_delay)

			checker(context)

		except Exception:
			as_srv.reset_aerospike_servers()
			raise
	as_srv.reset_aerospike_servers()

def multi_backup_and_restore(filler, preparer, checker, env={}, backup_opts=None,
		restore_opts=None, restore_delay=0.5, do_compress_and_encrypt=True):
	"""
	Do one backup-restore cycle. Unlike backup_and_restore backup directory/file paths must be provided in backup/restore opts
	multi_backup_and_restore only runs in dir-mode.
	"""
	if backup_opts is None:
		backup_opts = [["--host=localhost"]]

	if restore_opts is None:
		restore_opts = ["--host=localhost"]

	as_srv.start_aerospike_servers()

	context = {}
	# fill once, since we can just keep all data after running asrestore
	filler(context)

	for i, comp_enc_mode in enumerate([
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]):

		if not do_compress_and_encrypt and i > 0:
			break

		try:
			for backup_opt in backup_opts:
				backup("--namespace", lib.NAMESPACE, \
			"--verbose", *(backup_opt + comp_enc_mode), env=env)

			# keep metadata (sets/indexes) so they can be erased after
			# asrestore runs
			as_srv.reset_aerospike_servers(keep_metadata=True)

			# give SMD time to get deleted
			lib.safe_sleep(restore_delay)

			if preparer is not None:
				preparer(context)

			restore("--namespace", lib.NAMESPACE, \
			"--verbose", *(restore_opts + comp_enc_mode), env=env)
			# give SMD time to be restored
			lib.safe_sleep(restore_delay)

			checker(context)

		except Exception:
			as_srv.reset_aerospike_servers()
			raise
	as_srv.reset_aerospike_servers()

def run_backup_w_valgrind(filler, context={}, backup_options=None):
	"""
	Run asbackup command with given options using valgrind
	"""
	res = False
	as_srv.start_aerospike_servers()
	filler(context)
	try:
		with open(lib.VAL_LOGS_BACKUP, "w") as pipe_stdout:
			lib.run("asbackup", *backup_options, do_async=False,
				pipe_stderr=pipe_stdout, env={}, USE_VALGRIND=True)
		res = lib.parse_val_logs(lib.VAL_LOGS_BACKUP)
	except:
		as_srv.reset_aerospike_servers()
		raise
	as_srv.reset_aerospike_servers()
	return res

def run_restore_w_valgrind(*restore_options):
	"""
	Run asrestore command with given options using valgrind
	"""
	res = False
	as_srv.start_aerospike_servers()
	try:
		with open(lib.VAL_LOGS_RESTORE, "w") as pipe_stdout:
			lib.run("asrestore", *restore_options, do_async=False,
				pipe_stderr=pipe_stdout, env={}, USE_VALGRIND=True)
		res = lib.parse_val_logs(lib.VAL_LOGS_RESTORE)
	except:
		as_srv.reset_aerospike_servers()
		raise
	as_srv.reset_aerospike_servers()
	return res

