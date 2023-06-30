# coding=UTF-8

"""
Tests the representation of bin names in backup files.
"""

import lib
import aerospike
import subprocess
from run_backup import backup_and_restore, restore_from_file

SET_NAME = lib.SET
BIN_NAME = "bin1"
VAL = "val1"
KEY = "key"
INDEX_NAME = "idx1"
UDF_PATH = ""

def put_all():
	lib.write_record(SET_NAME, KEY, BIN_NAME, VAL)
	lib.create_integer_index(SET_NAME, BIN_NAME, INDEX_NAME)
	content = "--[=======[\n" + "TEST" + "\n--]=======]\n"
	UDF_PATH = lib.put_udf_file(content)
	# time for the index and udf to be created

def check_all():
	assert lib.test_record(SET_NAME, KEY) is False
	assert lib.check_index(SET_NAME, BIN_NAME, aerospike.INDEX_NUMERIC) is False

	try:
		lib.get_udf_file(UDF_PATH)
	except aerospike.exception.UDFNotFound:
		pass

def test_validate():
	"""
	Test that --validate does not restore anything.
	"""
	backup_and_restore(
		lambda context: put_all(),
		None,
		lambda context: check_all(),
		restore_opts=["--validate"],
		restore_delay=25
	)

def test_validate_bad_file():
	"""
	Test that --validate fails with a corrupted backup file.
	"""
	try:
		restore_from_file("test/test_bad_backup_file.asb", "--validate")
	except subprocess.CalledProcessError:
	    pass

def test_validate_good_file():
	"""
	Test that --validate returns 0 with a valid backup file
	"""
	restore_from_file("test/test_backup_file.asb", "--validate")
