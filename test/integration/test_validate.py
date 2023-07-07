# coding=UTF-8

"""
Tests the representation of bin names in backup files.
"""

import lib
import aerospike
import subprocess
from run_backup import restore_from_file

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
