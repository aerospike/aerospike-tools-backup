# coding=UTF-8

"""
Tests backing up and restoring to S3.
"""

import os

import aerospike_servers as as_srv
import lib
import minio_servers as min_srv
import record_gen
from run_backup import backup_async, restore_async, backup_to_directory, backup_to_file

S3_BUCKET = "asbackup-test"
S3_REGION = "us-west-1"

MINIO_NAME = "asbackup-minio"

def do_s3_backup(max_interrupts, n_records=10000, backup_opts=None,
		restore_opts=None, state_file_dir=False, state_file_explicit=False):
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

		env = {
			"AWS_ACCESS_KEY_ID": "key",
			"AWS_SECRET_ACCESS_KEY": "secretkey"
		}

		if state_file_dir:
			state_path = lib.temporary_path("state_dir")
			os.mkdir(state_path, 0o755)
			state_file = os.path.join(state_path, lib.NAMESPACE + '.asb.state')
		elif state_file_explicit:
			state_path = lib.temporary_path("asb.state")
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

			if state_file_dir or state_file_explicit:
				opts += ['--state-file-dst', state_path]
			opts += ['--s3-endpoint-override', '127.0.0.1:9000']

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

		res = restore_async(path, env=env,
				restore_opts=comp_enc_mode + restore_opts +
				['--s3-endpoint-override', '127.0.0.1:9000'])
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
			backup_to_directory(path, '--s3-endpoint-override', '127.0.0.1:9000',
					'--remove-artifacts', env=env)
		else:
			backup_to_file(path, '--s3-endpoint-override', '127.0.0.1:9000',
					'--remove-artifacts', env=env)

def test_s3_backup_small():
	do_s3_backup(0, n_records=100)

def test_s3_backup():
	do_s3_backup(0)

def test_s3_backup_multiple_files():
	do_s3_backup(0, n_records=10000, backup_opts=['--file-limit', '1'])

def test_s3_backup_interrupt():
	do_s3_backup(1, n_records=10000, backup_opts=['--records-per-second', '200'])

def test_s3_backup_multiple_files_interrupt():
	do_s3_backup(10, n_records=10000, backup_opts=['--file-limit', '1'])

