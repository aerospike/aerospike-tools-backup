# coding=UTF-8

"""
Tests the --unique, --replace, and --no-generation restore policy options.
"""

import lib
from run_backup import backup_and_restore

def fill_bins():
	"""
	Creates two records, one with generation count 2, the other with 1.
	"""
	lib.write_record(lib.SET, "key-1", ["bin-1"], ["dummy"])
	lib.write_record(lib.SET, "key-1", ["bin-1"], ["value-1a"])
	lib.write_record(lib.SET, "key-2", ["bin-1"], ["value-1a"])

def prepare_bins():
	"""
	Creates two records with generation count 1.
	"""
	lib.write_record(lib.SET, "key-1", ["bin-1", "bin-2"], ["value-1b", "value-2b"])
	lib.write_record(lib.SET, "key-2", ["bin-1", "bin-2"], ["value-1b", "value-2b"])

def check_bins_no_policy():
	"""
	Verifies restore without any policy options.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, ["bin-1", "bin-2"], ["value-1a", "value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, ["bin-1", "bin-2"], ["value-1b", "value-2b"])

def check_bins_no_gen():
	"""
	Verifies restore with --no-generation.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, ["bin-1", "bin-2"], ["value-1a", "value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, ["bin-1", "bin-2"], ["value-1a", "value-2b"])

def check_bins_replace():
	"""
	Verifies restore with --replace.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, ["bin-1"], ["value-1a"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, ["bin-1", "bin-2"], ["value-1b", "value-2b"])

def check_bins_replace_no_gen():
	"""
	Verifies restore with --replace and --no-generation.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, ["bin-1"], ["value-1a"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, ["bin-1"], ["value-1a"])

def check_bins_unique():
	"""
	Verifies restore with --unique.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, ["bin-1", "bin-2"], ["value-1b", "value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, ["bin-1", "bin-2"], ["value-1b", "value-2b"])

def test_no_policy():
	"""
	Tests restore without any policy options.
	"""
	backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_no_policy(),
		backup_opts=None,
		restore_opts=None
	)

def test_no_gen():
	"""
	Tests restore with --no-generation.
	"""
	backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_no_gen(),
		backup_opts=None,
		restore_opts=["--no-generation"]
	)

def test_replace():
	"""
	Tests restore with --replace.
	"""
	backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_replace(),
		backup_opts=None,
		restore_opts=["--replace"]
	)

def test_replace_no_gen():
	"""
	Tests restore with --replace and --no-generation.
	"""
	backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_replace_no_gen(),
		backup_opts=None,
		restore_opts=["--replace", "--no-generation"]
	)

def test_unique():
	"""
	Tests restore with --unique.
	"""
	backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_unique(),
		backup_opts=None,
		restore_opts=["--unique"]
	)
