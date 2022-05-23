# coding=UTF-8

"""
Tests the backing up of individual sets and groups of sets
"""

import aerospike
import os.path

import lib
from run_backup import backup_and_restore

SET_NAMES = [None] + lib.index_variations(63)

N_RECORDS = 5

KEYS = [ "key %d" % i for i in range(N_RECORDS) ]
SET_NAME_1 = "set-1"
SET_NAME_2 = "set-2"
SET_NAME_3 = "set-3"
BIN_NAME_1 = "bin-1"
BIN_NAME_2 = "bin-2"
VALUE_1S = [ "value %d" % i for i in range(N_RECORDS) ]
VALUE_2S = [ i for i in range(N_RECORDS) ]
INDEX_NAME_1 = "index-1"
INDEX_NAME_2 = "index-2"
INDEX_NAME_3 = "index-3"
UDF_FILE_DATA = "-- Just an empty UDF file.\n"

def put_data(context):
	"""
	Inserts the test data that we'll then filter.
	"""
	for i in range(N_RECORDS):
		lib.write_record(SET_NAME_1, KEYS[i], [BIN_NAME_1, BIN_NAME_2],
				[VALUE_1S[i], VALUE_2S[i]])
		lib.write_record(SET_NAME_2, KEYS[i], [BIN_NAME_1, BIN_NAME_2],
				[VALUE_1S[i], VALUE_2S[i]])
		lib.write_record(SET_NAME_3, KEYS[i], [BIN_NAME_1, BIN_NAME_2],
				[VALUE_1S[i], VALUE_2S[i]])
	lib.create_string_index(SET_NAME_1, BIN_NAME_1, INDEX_NAME_1)
	lib.create_integer_index(SET_NAME_2, BIN_NAME_2, INDEX_NAME_2)
	lib.create_string_index(SET_NAME_3, BIN_NAME_1, INDEX_NAME_3)
	context["udf_file"] = os.path.basename(lib.put_udf_file(UDF_FILE_DATA))

def check_set(exists, set_name):
	"""
	Verifies that the given set does or doesn't exist.
	"""
	records = []
	if exists:
		for i in range(N_RECORDS):
			assert lib.test_record(set_name, KEYS[i]), \
					"Record %s:%s does not exist" % (set_name, KEYS[i])
			records += [lib.read_record(set_name, KEYS[i])]
	else:
		for i in range(N_RECORDS):
			assert not lib.test_record(set_name, KEYS[i]), \
					"Unexpected record %s:%s" % (set_name, KEYS[i])
	return records

def check_bin(exists, record, bin_name):
	"""
	Verifies that the given record does or doesn't have the given bin.
	"""
	if exists:
		assert bin_name in record, "Record should have bin " + bin_name
	else:
		assert bin_name not in record, "Unexpected bin " + bin_name + " in record"

def check_index(exists, set_name, bin_name, is_integer_index):
	"""
	Verifies that the given index does or doesn't exist.
	"""
	try:
		lib.check_simple_index(set_name, bin_name, 42 if is_integer_index else "foobar")
		found = True
	except aerospike.exception.IndexNotFound:
		found = False
	except aerospike.exception.MaxRetriesExceeded:
		found = False

	if exists:
		assert found, "Missing index in set " + set_name
	else:
		assert not found, "Unexpected index in set " + set_name

def check_data(context, set_1, set_2, set_3, bin_1, bin_2, index_1, index_2, index_3, udf_file):
	"""
	Verifies that the test data was filtered according to the backup
	and restore options.
	"""
	records = []
	records += check_set(set_1, SET_NAME_1)
	records += check_set(set_2, SET_NAME_2)
	records += check_set(set_3, SET_NAME_3)

	for record in records:
		check_bin(bin_1, record[2], BIN_NAME_1)
		check_bin(bin_2, record[2], BIN_NAME_2)

	check_index(index_1, SET_NAME_1, BIN_NAME_1, False)
	check_index(index_2, SET_NAME_2, BIN_NAME_2, True)
	check_index(index_3, SET_NAME_3, BIN_NAME_1, False)

	try:
		lib.get_udf_file(context["udf_file"])
		found = True
	except Exception:
		found = False

	if udf_file:
		assert found, "Missing UDF file " + context["udf_file"]
	else:
		assert not found, "Unexpected UDF file " + context["udf_file"]


def test_no_filter():
	"""
	Tests backup and restore without any filters.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			True, True, True,
			True),
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_backup_no_bins():
	"""
	Tests the --no-bins backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			False, False, False,
			False, False,
			True, True, True,
			True),
		backup_opts=["--no-bins"],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_backup_set():
	"""
	Tests the --set backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, False, False,
			True, True,
			True, False, False,
			True),
		backup_opts=["--set", SET_NAME_1],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_backup_sets():
	"""
	Tests the --set backup option with 2 sets.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, False,
			True, True,
			True, True, False,
			True),
		backup_opts=["--set", "%s,%s" % (SET_NAME_1, SET_NAME_2)],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_backup_all_sets():
	"""
	Tests the --set backup option with all 3 sets.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			True, True, True,
			True),
		backup_opts=["--set", "%s,%s,%s" % (SET_NAME_1, SET_NAME_2, SET_NAME_3)],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_restore_set_list():
	"""
	Tests the --set-list restore option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, False, False,
			True, True,
			True, False, False,
			True),
		restore_opts=["--set-list", SET_NAME_1, "--wait"],
		restore_delay=1
	)

def test_backup_bin_list():
	"""
	Tests the --bin-list backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, False,
			True, True, True,
			True),
		backup_opts=["--bin-list", BIN_NAME_1],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_restore_bin_list():
	"""
	Tests the --bin-list restore option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, False,
			True, True, True,
			True),
		restore_opts=["--bin-list", BIN_NAME_1, "--wait"],
		restore_delay=1
	)

def test_backup_no_records():
	"""
	Tests the --no-records backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			False, False, False,
			False, False,
			True, True, True,
			True),
		backup_opts=["--no-records"],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_restore_no_records():
	"""
	Tests the --no-records restore option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			False, False, False,
			False, False,
			True, True, True,
			True),
		restore_opts=["--no-records", "--wait"],
		restore_delay=1
	)

def test_backup_no_indexes():
	"""
	Tests the --no-indexes backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			False, False, False,
			True),
		backup_opts=["--no-indexes"],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_restore_no_indexes():
	"""
	Tests the --no-indexes restore option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			False, False, False,
			True),
		restore_opts=["--no-indexes", "--wait"],
		restore_delay=1
	)

def test_backup_no_udfs():
	"""
	Tests the --no-udfs backup option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			True, True, True,
			False),
		backup_opts=["--no-udfs"],
		restore_opts=["--wait"],
		restore_delay=1
	)

def test_restore_no_udfs():
	"""
	Tests the --no-udfs restore option.
	"""
	backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context,
			True, True, True,
			True, True,
			True, True, True,
			False),
		restore_opts=["--no-udfs", "--wait"],
		restore_delay=1
	)

