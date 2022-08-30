# coding=UTF-8

"""
Tests the representation of indexes in backup files.
"""
import aerospike

import lib
from run_backup import backup_and_restore

SET_NAMES = [None] + lib.index_variations(63)
INDEX_NAMES = ["normal"] + lib.index_variations(63)
INDEX_PATHS = ["normal"] + lib.index_variations(14)
CTX = lib.ctx_variations()

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

def create_cdt_indexes(create_func, bin_type, index_type, ctx_type):
	"""
	Invokes the given cdt index creation function for all set names, index
	names, index paths and ctx.
	"""
	for set_name, index_path, index_name, ctx in zip(SET_NAMES, INDEX_PATHS, INDEX_NAMES, CTX[ctx_type]):
		create_func(set_name, index_path, index_name, bin_type, index_type, ctx)


def test_integer_list_cdt_index_with_ctx():
	"""
	Tests cdt indexes on list with ctx across all set names, index names, 
	bin types, and list-realted ctx (list_index, list_rank, list_value)
	"""
	backup_and_restore(
		lambda context: create_cdt_indexes(lib.create_cdt_index, aerospike.INDEX_NUMERIC,\
			 aerospike.INDEX_TYPE_LIST, "list_int"),
		None,
		lambda context: check_indexes(lib.check_list_index, 12345),
		restore_delay=1
	)
	
def test_integer_index():
	"""
	Tests integer indexes across all set names, index names, and index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_integer_index),
		None,
		lambda context: check_indexes(lib.check_simple_index, 12345),
		restore_delay=1
	)

def test_string_index():
	"""
	Tests string indexes across all set names, index names, and index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_string_index),
		None,
		lambda context: check_indexes(lib.check_simple_index, "foobar"),
		restore_delay=1
	)

def test_geo_index():
	"""
	Tests geo indexes across all set names, index names, and index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_geo_index),
		None,
		lambda context: check_indexes(lib.check_geo_index, (0.0, 0.0)),
		restore_delay=1
	)

def test_integer_list_index():
	"""
	Tests integer list indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_integer_list_index),
		None,
		lambda context: check_indexes(lib.check_list_index, 12345),
		restore_delay=1
	)

def test_string_list_index():
	"""
	Tests string list indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_string_list_index),
		None,
		lambda context: check_indexes(lib.check_list_index, "foobar"),
		restore_delay=1
	)

def test_integer_map_key_index():
	"""
	Tests integer map key indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_integer_map_key_index),
		None,
		lambda context: check_indexes(lib.check_map_key_index, 12345),
		restore_delay=1
	)

def test_string_map_key_index():
	"""
	Tests string map key indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_string_map_key_index),
		None,
		lambda context: check_indexes(lib.check_map_key_index, "foobar"),
		restore_delay=1
	)

def test_integer_map_value_index():
	"""
	Tests integer map value indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_integer_map_value_index),
		None,
		lambda context: check_indexes(lib.check_map_value_index, 12345),
		restore_delay=1
	)

def test_string_map_value_index():
	"""
	Tests string map value indexes across all set names, index names, and
	index paths.
	"""
	backup_and_restore(
		lambda context: create_indexes(lib.create_string_map_value_index),
		None,
		lambda context: check_indexes(lib.check_map_value_index, "foobar"),
		restore_delay=1
	)
