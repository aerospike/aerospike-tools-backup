# coding=UTF-8


"""
Tests the resumption of failed/interrupted backups.
"""

import lib
import random
import signal
import asyncio
import os
import re

chars = [chr(i) for i in range(ord('a'), ord('z'))]

INF_CMD_HEADER_RE = r"^[\d]{4}-[\d]{2}-[\d]{2} [\d]{1,2}:[\d]{2}:[\d]{2} (?:GMT|UTC) \[INF\] \[[\s\d]+\]"

def gen_text(pkey):
	random.seed(pkey * 16381)
	return ' '.join([''.join(random.choices(chars, k=random.randint(2, 11))) for _ in range(random.randint(10, 100))])

def get_key(idx):
	return (idx * 32749) % 32768

def gen_record(pkey):
	bin_1 = pkey
	bin_2 = gen_text(pkey)

	return ['bin_1', 'bin_2'], [bin_1, bin_2]

def put_udf_file(context, idx):
	"""
	Creates UDF files with the given comments.
	"""
	content = "--[=======[\n" + gen_text(idx + 32768) + "\n--]=======]\n"
	path = lib.put_udf_file(content)
	context[os.path.basename(path)] = content

def check_udf_files(context, expected_n_udfs):
	"""
	Retrieves and verifies the UDF files referred to by the context.
	"""
	udf_cnt = 0
	for path in context:
		udf_cnt += 1
		content = lib.get_udf_file(path)
		assert lib.eq(content, context[path]), "UDF file %s has invalid content" % path
	assert(udf_cnt == expected_n_udfs)

def put_records(n_records, context, set_name=None, do_indexes=False, n_udfs=0):
	lib.reset()

	for key_idx in range(n_records):
		key = get_key(key_idx)
		lib.write_record(set_name, key, *gen_record(key))

	if do_indexes:
		lib.create_integer_index(set_name, 'bin_1', 'idx_1')
		lib.create_string_index(set_name, 'bin_2', 'idx_2')

	for i in range(n_udfs):
		put_udf_file(context, i)

def check_records(n_records, context, set_name=None, do_indexes=False, n_udfs=0):
	"""
	Ensures that all n_records records are in the database
	"""
	for key_idx in range(n_records):
		key = get_key(key_idx)
		meta_key, meta_ttl, record = lib.read_record(set_name, key)

		expected_bins, expected_values = gen_record(key)

		lib.validate_record(key, record, expected_bins, expected_values)
		lib.validate_meta(key, meta_key, meta_ttl)

	if do_indexes:
		lib.check_simple_index(set_name, 'bin_1', 1234)
		lib.check_simple_index(set_name, 'bin_2', "miozfow o")

	check_udf_files(context, n_udfs)

def backup_output_get_records_written(backup_stderr):
	"""
	Parses the output of asbackup and returns a list of:

	[total records backed up, secondary indexes backed up, udfs backed up,
	 total bytes backed up, approximate bytes per record in backup files]
	"""
	reg = re.compile(INF_CMD_HEADER_RE + r" Backed up ([\d]+) record\(s\), " + \
			r"([\d]+) secondary index\(es\), ([\d]+) UDF file\(s\), " + \
			r"([\d]+) byte\(s\) in total \(\~([\d]+) B\/rec\)$",
			flags=re.MULTILINE)
	match = reg.search(backup_stderr)
	assert(match is not None)

	return (int(match.group(i)) for i in range(1, 6))

def restore_output_get_records_written(restore_stderr):
	"""
	Parses the output of asrestore and returns a list of:

	[expired, skipped, err_ignored, inserted, failed, existed, fresher]

	This statement is printed multiple times, so only look at the last one.
	"""
	reg = re.compile(INF_CMD_HEADER_RE + r" Expired ([\d]+) : skipped ([\d]+) : " + \
			r"err_ignored ([\d]+) : inserted ([\d]+): failed ([\d]+) " + \
			r"\(existed ([\d]+) , fresher ([\d]+)\)",
			flags=re.MULTILINE)
	match = reg.findall(restore_stderr)
	assert(match is not None)

	return (int(num) for num in match[-1])

async def kill_after(process, dt):
	await asyncio.sleep(dt)
	try:
		os.killpg(os.getpgid(process.pid), signal.SIGINT)
	except Exception:
		pass

def do_interrupt_run(max_interrupts, n_records=10000, do_indexes=False,
		n_udfs=0, backup_opts=None, restore_opts=None, state_file_dir=False,
		state_file_explicit=False):
	if backup_opts == None:
		backup_opts = []
	if restore_opts == None:
		restore_opts = []

	prev_rec_total = 0
	prev_bytes_total = 0

	for comp_enc_mode in [
			[],
			['--compress=zstd'],
			['--encrypt=aes128', '--encryption-key-file=test/test_key.pem'],
			['--compress=zstd', '--encrypt=aes128',
				'--encryption-key-file=test/test_key.pem'],
			]:

		i = 1
		path = None
		# where to find the backup state on failure
		state_file = None
		context = {}

		lib.start()

		if state_file_dir:
			state_path = lib.temporary_path("state_dir")
			os.mkdir(state_path)
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
					if lib.GLOBALS["dir_mode"]:
						state_file = os.path.join(path, lib.NAMESPACE + '.asb.state')
					else:
						state_file = path + '.state'

				opts += ['--continue', state_file]
				filler = lambda context: None
			else:
				filler = lambda context: put_records(n_records, context, lib.SET,
						do_indexes, n_udfs)

			if state_file_dir or state_file_explicit:
				opts += ['--state-file-dst', state_path]

			bup, path = lib.backup_async(
				filler,
				context=context,
				backup_opts=opts,
				path=path
			)
			if i <= max_interrupts:
				lib.sync_wait(kill_after(bup, dt=6))
			res = lib.sync_wait(bup.wait())

			stdout, stderr = lib.sync_wait(bup.communicate())
			print(stderr.decode())

			(record_total, sindexes, udfs, bytes_total, _) = \
					backup_output_get_records_written(stderr.decode('utf-8'))
			assert(record_total >= prev_rec_total)
			assert(bytes_total >= prev_bytes_total)
			assert(sindexes == 2 if do_indexes else sindexes == 0)
			assert(udfs == n_udfs)

			if res == 0 or i > max_interrupts:
				break
			else:
				i += 1
		assert(res == 0)

		res = lib.restore_async(path, restore_opts=comp_enc_mode + restore_opts)
		ret_code = lib.sync_wait(res.wait())
		stdout, stderr = lib.sync_wait(res.communicate())
		print(stderr.decode())
		assert(ret_code == 0)

		(expired, skipped, err_ignored, inserted, failed, existed, fresher) = \
				restore_output_get_records_written(stderr.decode('utf-8'))
		assert(inserted == n_records)
		assert(expired == 0)
		assert(skipped == 0)
		assert(err_ignored == 0)
		assert(existed == 0)
		assert(fresher == 0)
		assert(failed == 0)

		check_records(n_records, context, lib.SET, do_indexes, n_udfs)

def test_set_state_file_explicit_dir():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], state_file_dir=True)

def test_set_state_file_explicit_file():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], state_file_explicit=True)

def test_interrupt_once():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'])

def test_interrupt_once_parallel():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '8'])

def test_interrupt_many():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--parallel', '1'])

def test_interrupt_many_parallel():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--parallel', '8'])

def test_interrupt_once_multipart():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--partition-list',
	   '0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
	   '--parallel', '1'])

def test_interrupt_once_multipart_parallel():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--partition-list',
	   '0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
	   '--parallel', '4'])

def test_interrupt_many_multipart():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--partition-list',
	   '0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
	   '--parallel', '1'])

def test_interrupt_many_multipart_parallel():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--partition-list',
		'0-512,512-512,1024-512,1536-512,2048-512,2560-512,3072-512,3584-512',
		'--parallel', '4'])

def test_interrupt_once_sindex():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], do_indexes=True)

def test_interrupt_many_sindex():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--parallel', '1'], do_indexes=True)

def test_interrupt_once_udf():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], n_udfs=5)

def test_interrupt_many_udf():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], n_udfs=5)

def test_interrupt_once_sindex_udf():
	do_interrupt_run(1, backup_opts=['--nice', '1', '--parallel', '1'], do_indexes=True,
			n_udfs=5)

def test_interrupt_many_sindex_udf():
	do_interrupt_run(10, backup_opts=['--nice', '1', '--parallel', '1'], do_indexes=True,
			n_udfs=5)

