# coding=UTF-8

"""
Tests the representation of UDF files in backup files.
"""

import os.path

import lib

COMMENTS = lib.identifier_variations(100, False)

def put_udf_files(context, comments):
	"""
	Creates UDF files with the given comments.
	"""
	for comment in comments:
		content = u"--[=======[\n" + comment + u"\n--]=======]\n"
		path = lib.put_udf_file(content)
		context[os.path.basename(path)] = content

def check_udf_files(context):
	"""
	Retrieves and verifies the UDF files referred to by the context.
	"""
	for path in context:
		content = lib.get_udf_file(path)
		assert lib.eq(content, context[path]), "UDF file %s has invalid content" % path

def test_udf_file():
	"""
	Test UDF files.
	"""
	lib.backup_and_restore(
		lambda context: put_udf_files(context, COMMENTS),
		None,
		check_udf_files
	)
