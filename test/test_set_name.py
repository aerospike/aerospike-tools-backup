# coding=UTF-8

"""
Tests the representation of set names in backup files.
"""

import lib

SET_NAMES = [None]
SET_NAMES += lib.identifier_variations(63, False)

def put_sets(set_names, key, bin_name, value):
	"""
	Inserts the given key with the given bin with the given value
	into the given sets.
	"""
	for set_name in set_names:
		lib.write_record(set_name, key, [bin_name], [value])

def check_sets(set_names, key, bin_name, value):
	"""
	Ensures that the given key has the given bin with the given value
	across all given sets.
	"""
	for set_name in set_names:
		meta_key, meta_ttl, record = lib.read_record(set_name, key)
		lib.validate_record(key, record, [bin_name], [value])
		lib.validate_meta(key, meta_key, meta_ttl)

def test_set_name():
	"""
	Test set names.
	"""
	lib.backup_and_restore(
		lambda context: put_sets(SET_NAMES, "key", u"value", u"value"),
		None,
		lambda context: check_sets(SET_NAMES, "key", u"value", u"value")
	)
