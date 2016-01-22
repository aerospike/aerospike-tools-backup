# coding=UTF-8

"""
Tests the representation of indexes in backup files.
"""

import lib

SET_NAMES = [None] + lib.index_variations(63)
INDEX_NAMES = [u"normal"] + lib.index_variations(63)
INDEX_PATHS = [u"normal"] + lib.index_variations(14)

def create_indexes(create_func):
	"""
	Invokes the given index creation function for all set names, index
	names, and index paths.
	"""
	for set_name, index_path, index_name in zip(SET_NAMES, INDEX_PATHS, INDEX_NAMES):
		create_func(set_name, index_path, index_name)

def check_indexes(check_func, value):
	"""
	Invokes the given index check function for all set names, index names,
	and index paths.
	"""
	for set_name, index_path in zip(SET_NAMES, INDEX_PATHS):
		check_func(set_name, index_path, value)

def test_integer_index():
	"""
	Tests integer indexes across all set names, index names, and index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_integer_index),
		None,
		lambda context: check_indexes(lib.check_simple_index, 12345)
	)

def test_string_index():
	"""
	Tests string indexes across all set names, index names, and index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_string_index),
		None,
		lambda context: check_indexes(lib.check_simple_index, u"foobar")
	)

def test_geo_index():
	"""
	Tests geo indexes across all set names, index names, and index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_geo_index),
		None,
		lambda context: check_indexes(lib.check_geo_index, (0.0, 0.0))
	)

def test_integer_list_index():
	"""
	Tests integer list indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_integer_list_index),
		None,
		lambda context: check_indexes(lib.check_list_index, 12345)
	)

def test_string_list_index():
	"""
	Tests string list indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_string_list_index),
		None,
		lambda context: check_indexes(lib.check_list_index, u"foobar")
	)

def test_integer_map_key_index():
	"""
	Tests integer map key indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_integer_map_key_index),
		None,
		lambda context: check_indexes(lib.check_map_key_index, 12345)
	)

def test_string_map_key_index():
	"""
	Tests string map key indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_string_map_key_index),
		None,
		lambda context: check_indexes(lib.check_map_key_index, u"foobar")
	)

def test_integer_map_value_index():
	"""
	Tests integer map value indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_integer_map_value_index),
		None,
		lambda context: check_indexes(lib.check_map_value_index, 12345)
	)

def test_string_map_value_index():
	"""
	Tests string map value indexes across all set names, index names, and
	index paths.
	"""
	lib.backup_and_restore(
		lambda context: create_indexes(lib.create_string_map_value_index),
		None,
		lambda context: check_indexes(lib.check_map_value_index, u"foobar")
	)
