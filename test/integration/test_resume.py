# coding=UTF-8

"""
Tests the resumption of failed/interrupted backups.
"""

import signal
import asyncio
import os
import random

import aerospike_servers as as_srv
import lib
import record_gen
from run_backup import backup_async, restore_async

_built_file_overrides = False

def build_file_overrides():
	global _built_file_overrides
	if not _built_file_overrides:
		print("building overrides")
		lib.init_file_overrides()
		_built_file_overrides = True

class interruptMethod():
	sigkill = 0
	fileIssue = 1

def do_interrupt_run(max_interrupts, n_records=10000, do_indexes=False,
		n_udfs=0, backup_opts=None, restore_opts=None, state_file_dir=False,
		state_file_explicit=False, to_stdout=False, do_matrix=False, interrupt_method=interruptMethod.sigkill):
	if backup_opts == None:
		backup_opts = []
	if restore_opts == None:
		restore_opts = []

	as_srv.start_aerospike_servers()

	# breakpoint()
	build_file_overrides()

	if do_matrix:
		comp_enc_mode_list = [
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]
	else:
		comp_enc_mode_list = [[],]

	for comp_enc_mode in comp_enc_mode_list:
		i = 1
		path = None
		# where to find the backup state on failure
		state_file = None
		context = {}

		prev_rec_total = 0
		prev_bytes_total = 0

		as_srv.start_aerospike_servers()

		if state_file_dir:
			state_path = lib.temporary_path("state_dir")
			os.mkdir(state_path)
			state_file = os.path.join(state_path, lib.NAMESPACE + '.asb.state')
		elif state_file_explicit:
			state_path = lib.temporary_path("asb.state")
			state_file = state_path

		if to_stdout:
			bup_file_path = lib.temporary_path("asb")
			print(bup_file_path)

		while True:
			opts = comp_enc_mode + backup_opts
			if i > 1:
				if state_file is None:
					# if not using explicit backup state, reconstruct the backup
					# state to where we know it to be
					if lib.GLOBALS["dir_mode"]:
						state_file = os.path.join(path, lib.NAMESPACE + '.asb.state')
					elif to_stdout:
						state_file = str(lib.NAMESPACE) + ".asb.state"
					else:
						state_file = path + '.state'

				opts += ['--continue', state_file]
				filler = lambda context: None
			else:
				filler = lambda context: record_gen.put_records(n_records, context, lib.SET,
						do_indexes, n_udfs)

			if state_file_dir or state_file_explicit:
				opts += ['--state-file-dst', state_path]

			if to_stdout:
				bup_file = open(bup_file_path, 'ab')
				path = "-"

			use_opts = opts
			# don't throttle if we won't be interrupting the backup
			if i > max_interrupts and ('--records-per-second' in opts):
				idx = opts.index('--records-per-second')
				use_opts = opts[:idx] + opts[idx + 2:]

			backup_env = {}
			if i <= max_interrupts:
				if interrupt_method == interruptMethod.fileIssue:
					file_override = ["file_close_override.so", "file_open_override.so"][random.randint(0, 1)]
					print("using file override: " + file_override)
					backup_env = {"LD_LIBRARY_PATH": lib.absolute_path(lib.WORK_DIRECTORY), "LD_PRELOAD": file_override}
			
			bup, path = backup_async(
				filler,
				context=context,
				backup_opts=use_opts,
				path=path,
				pipe_stdout=bup_file if to_stdout else None,
				env=backup_env
			)
			if interrupt_method == interruptMethod.sigkill:
				lib.sync_wait(lib.kill_after(bup, dt=10))
			res = lib.sync_wait(bup.wait())

			if to_stdout:
				bup_file.close()

			stdout, stderr = lib.sync_wait(bup.communicate())
			print(stderr.decode())

			(record_total, sindexes, udfs, bytes_total, _) = \
					record_gen.backup_output_get_records_written(stderr.decode('utf-8'))
			assert(record_total >= prev_rec_total)
			assert(bytes_total >= prev_bytes_total)
			assert(sindexes == 2 if do_indexes else sindexes == 0)
			assert(udfs == n_udfs)

			prev_rec_total = record_total
			prev_bytes_total = bytes_total

			if res == 0 or i > max_interrupts:
				break
			else:
				i += 1
		assert(res == 0)

		if to_stdout:
			path = '-'
			stdin_fd = open(bup_file_path, 'rb')
		else:
			stdin_fd = None

		# give database a second to update
		lib.safe_sleep(1)

		res = restore_async(path, restore_opts=comp_enc_mode + restore_opts,
				pipe_stdin=stdin_fd)
		ret_code = lib.sync_wait(res.wait())
		stdout, stderr = lib.sync_wait(res.communicate())
		print(stderr.decode())
		assert(ret_code == 0)

		if to_stdout:
			stdin_fd.close()

		(expired, skipped, err_ignored, inserted, failed, existed, fresher) = \
				record_gen.restore_output_get_records_written(stderr.decode('utf-8'))
		assert(inserted == n_records)
		assert(expired == 0)
		assert(skipped == 0)
		assert(err_ignored == 0)
		assert(existed == 0)
		assert(fresher == 0)
		assert(failed == 0)

		record_gen.check_records(n_records, context, lib.SET, do_indexes, n_udfs)

def test_set_state_file_explicit_dir():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], state_file_dir=True)

def test_set_state_file_explicit_file():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], state_file_explicit=True)

def test_interrupt_once():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_matrix=True)

def test_interrupt_once_parallel():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '8'])

def test_interrupt_many():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_matrix=True)

def test_file_interrupt_many():
	# TODO add this for single file backups and with > 1 parallel threads
	# NOTE the file issue overrides only take affect on Linux because they use the LD_PRELOAD trick
	if lib.GLOBALS["dir_mode"]:
		do_interrupt_run(3, backup_opts=['--records-per-second', '500', '--file-limit', '1'],
			do_matrix=False, interrupt_method=interruptMethod.fileIssue)

def test_interrupt_many_parallel():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '8'])

def test_interrupt_many_multipart():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--partition-list',
	   '0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
	   '--parallel', '1'])

def test_interrupt_many_multipart_parallel():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--partition-list',
		'0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
		'--parallel', '4'])

def test_interrupt_once_sindex():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_indexes=True)

def test_interrupt_many_sindex():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_indexes=True)

def test_interrupt_once_udf():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], n_udfs=5)

def test_interrupt_many_udf():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], n_udfs=5)

def test_interrupt_once_sindex_udf():
	do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_indexes=True,
			n_udfs=5)

def test_interrupt_many_sindex_udf():
	do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '1'], do_indexes=True,
			n_udfs=5)

def test_interrupt_stdout_backup():
	if not lib.GLOBALS["dir_mode"]:
		do_interrupt_run(1, backup_opts=['--records-per-second', '500', '--parallel', '1'], to_stdout=True, do_matrix=True)

def test_interrupt_stdout_backup_many():
	if not lib.GLOBALS["dir_mode"]:
		do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '1'], to_stdout=True)

def test_interrupt_stdout_backup_many_parallel():
	if not lib.GLOBALS["dir_mode"]:
		do_interrupt_run(10, backup_opts=['--records-per-second', '500', '--parallel', '8'], to_stdout=True)

