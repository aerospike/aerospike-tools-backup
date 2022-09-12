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

def check_cdt_indexes(check_func, index_type):
	"""
	Invokes the given cdt index check function for all set names, index names,
	and given index type.
	"""
	for set_name, index_path in zip(SET_NAMES, INDEX_PATHS):
		check_func(set_name, index_path, index_type)

def create_cdt_indexes(create_func, bin_type, index_type, ctx_type):
	"""
	Invokes the given cdt index creation function for all set names, index
	names, index paths and ctx.
	"""
	for set_name, index_path, index_name, ctx in zip(SET_NAMES, INDEX_PATHS, INDEX_NAMES, CTX[ctx_type]):
		create_func(set_name, index_path, index_name, bin_type, index_type, ctx)

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
