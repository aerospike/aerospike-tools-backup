# coding=UTF-8

"""
Tests the representation of bin names in backup files.
"""

import lib

BIN_NAMES = lib.identifier_variations(14, False)

def put_bins(set_name, key, bin_names, value):
	"""
	Inserts the given key with the given bins with the given value.
	"""
	values = [value] * len(bin_names)
	lib.write_record(set_name, key, bin_names, values)

def check_bins(set_name, key, bin_names, value):
	"""
	Ensures that the given key has the given bins with the given value.
	"""
	meta_key, meta_ttl, record = lib.read_record(set_name, key)
	values = [value] * len(bin_names)
	lib.validate_record(key, record, bin_names, values)
	lib.validate_meta(key, meta_key, meta_ttl)

def test_bin_name():
	"""
	Test bin names.
	"""
	lib.backup_and_restore(
		lambda context: put_bins(lib.SET, "key", BIN_NAMES, u"foobar"),
		None,
		lambda context: check_bins(lib.SET, "key", BIN_NAMES, u"foobar")
	)
