# coding=UTF-8

"""
Tests the representation of bin names in backup files.
"""

import lib
from run_backup import backup_and_restore

COMMENTS = lib.identifier_variations(100, False)

def put_udf_files(context, comments):
	"""
	Creates UDF files with the given comments.
	"""
	for comment in comments:
		content = "--[=======[\n" + comment + "\n--]=======]\n"
		path = lib.put_udf_file(content)
		context[os.path.basename(path)] = content

def check_udf_files(context):
	"""
	Retrieves and verifies the UDF files referred to by the context.
	"""
	for path in context:
		content = lib.get_udf_file(path)
		assert lib.eq(content, context[path]), "UDF file %s has invalid content" % path

SET_NAME = lib.SET
BIN_NAME = "bin1"
VAL = "val1"
KEY = "key"
INDEX_NAME = "idx1"
UDF_PATH = ""

def put_all(context):
	lib.write_record(SET_NAME, KEY, BIN_NAME, VAL)
	lib.create_integer_index(SET_NAME, BIN_NAME, INDEX_NAME)
	content = "--[=======[\n" + "TEST" + "\n--]=======]\n"
	UDF_PATH = lib.put_udf_file(content)

def check_all(context):
	assert lib.test_record(SET_NAME, KEY) is False
	lib.check_simple_index(SET_NAME, BIN_NAME)
	content = lib.get_udf_file(UDF_PATH)
	assert not content

def test_validate():
	"""
	Test that --validate does not restore anything.
	"""
	backup_and_restore(
		lambda context: put_all(context),
		None,
		lambda context: check_all(context),
		restore_opts=["--validate"],
		restore_delay=1
	)

