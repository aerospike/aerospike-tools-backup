# coding=UTF-8

"""
Tests backup and restore filter options.
"""

import os.path

import lib

KEY = u"key"
SET_NAME_1 = u"set-1"
SET_NAME_2 = u"set-2"
BIN_NAME_1 = u"bin-1"
BIN_NAME_2 = u"bin-2"
VALUE_1 = u"value-1"
VALUE_2 = u"value-2"
INDEX_NAME_1 = u"index-1"
INDEX_NAME_2 = u"index-2"
UDF_FILE_DATA = u"-- Just an empty UDF file.\n"

def put_data(context):
	"""
	Inserts the test data that we'll then filter.
	"""
	lib.write_record(SET_NAME_1, KEY, [BIN_NAME_1, BIN_NAME_2], [VALUE_1, VALUE_2])
	lib.write_record(SET_NAME_2, KEY, [BIN_NAME_1, BIN_NAME_2], [VALUE_1, VALUE_2])
	lib.create_string_index(SET_NAME_1, BIN_NAME_1, INDEX_NAME_1)
	lib.create_string_index(SET_NAME_2, BIN_NAME_2, INDEX_NAME_2)
	context["udf_file"] = os.path.basename(lib.put_udf_file(UDF_FILE_DATA))

def check_set(exists, set_name):
	"""
	Verifies that the given set does or doesn't exist.
	"""
	if exists:
		assert lib.test_record(set_name, KEY), "Record %s:%s does not exist" % (set_name, KEY)
		return [lib.read_record(set_name, KEY)]
	else:
		assert not lib.test_record(set_name, KEY), "Unexpected record %s:%s" % (set_name, KEY)
		return []

def check_bin(exists, record, bin_name):
	"""
	Verifies that the given record does or doesn't have the given bin.
	"""
	if exists:
		assert bin_name in record, "Record should have bin " + bin_name
	else:
		assert bin_name not in record, "Unexpected bin " + bin_name + " in record"

def check_index(exists, set_name, bin_name):
	"""
	Verifies that the given index does or doesn't exist.
	"""
	try:
		lib.check_simple_index(set_name, bin_name, u"foobar")
		found = True
	except Exception:
		found = False

	if exists:
		assert found, "Missing index in set " + set_name
	else:
		assert not found, "Unexpected index in set " + set_name

def check_data(context, set_1, set_2, bin_1, bin_2, index_1, index_2, udf_file):
	"""
	Verifies that the test data was filtered according to the backup
	and restore options.
	"""
	records = []
	records += check_set(set_1, SET_NAME_1)
	records += check_set(set_2, SET_NAME_2)

	for record in records:
		check_bin(bin_1, record[2], BIN_NAME_1)
		check_bin(bin_2, record[2], BIN_NAME_2)

	check_index(index_1, SET_NAME_1, BIN_NAME_1)
	check_index(index_2, SET_NAME_2, BIN_NAME_2)

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
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, True, True, True, True),
		None,
		None
	)

def test_backup_no_bins():
	"""
	Tests the --no-bins backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, False, False, False, False, True, True, True),
		["--no-bins"],
		None
	)

def test_backup_set():
	"""
	Tests the --set backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, False, True, True, True, False, True),
		["--set", SET_NAME_1],
		None
	)

def test_restore_set_list():
	"""
	Tests the --set-list restore option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, False, True, True, True, False, True),
		None,
		["--set-list", SET_NAME_1]
	)

def test_backup_bin_list():
	"""
	Tests the --bin-list backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, False, True, True, True),
		["--bin-list", BIN_NAME_1],
		None
	)

def test_restore_bin_list():
	"""
	Tests the --bin-list restore option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, False, True, True, True),
		None,
		["--bin-list", BIN_NAME_1]
	)

def test_backup_no_records():
	"""
	Tests the --no-records backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, False, False, False, False, True, True, True),
		["--no-records"],
		None
	)

def test_restore_no_records():
	"""
	Tests the --no-records restore option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, False, False, False, False, True, True, True),
		None,
		["--no-records"]
	)

def test_backup_no_indexes():
	"""
	Tests the --no-indexes backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, True, False, False, True),
		["--no-indexes"],
		None
	)

def test_restore_no_indexes():
	"""
	Tests the --no-indexes restore option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, True, False, False, True),
		None,
		["--no-indexes"]
	)

def test_backup_no_udfs():
	"""
	Tests the --no-udfs backup option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, True, True, True, False),
		["--no-udfs"],
		None
	)

def test_restore_no_udfs():
	"""
	Tests the --no-udfs restore option.
	"""
	lib.backup_and_restore(
		put_data,
		None,
		lambda context: check_data(context, True, True, True, True, True, True, False),
		None,
		["--no-udfs"]
	)
