# coding=UTF-8

import lib
import random
import re
import os

from aerospike_servers import reset_aerospike_servers

INF_CMD_HEADER_RE = r"^[\d]{4}-[\d]{2}-[\d]{2} [\d]{1,2}:[\d]{2}:[\d]{2} (?:GMT|UTC) \[INF\] \[[\s\d]+\]"

chars = [chr(i) for i in range(ord('a'), ord('z'))]

def gen_text(pkey):
	random.seed(pkey * 16381)
	return ' '.join([''.join(random.choices(chars, k=random.randint(2, 11))) for _ in range(random.randint(10, 100))])

def get_key(idx):
	return (idx * 32749) % 16777216

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
	reset_aerospike_servers()

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

