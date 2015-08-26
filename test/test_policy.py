# coding=UTF-8

"""
Tests the --unique, --replace, and --no-generation restore policy options.
"""

import lib

def fill_bins():
	"""
	Creates two records, one with generation count 2, the other with 1.
	"""
	lib.write_record(lib.SET, "key-1", [u"bin-1"], [u"dummy"])
	lib.write_record(lib.SET, "key-1", [u"bin-1"], [u"value-1a"])
	lib.write_record(lib.SET, "key-2", [u"bin-1"], [u"value-1a"])

def prepare_bins():
	"""
	Creates two records with generation count 1.
	"""
	lib.write_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])
	lib.write_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])

def check_bins_no_policy():
	"""
	Verifies restore without any policy options.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, [u"bin-1", u"bin-2"], [u"value-1a", u"value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])

def check_bins_no_gen():
	"""
	Verifies restore with --no-generation.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, [u"bin-1", u"bin-2"], [u"value-1a", u"value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, [u"bin-1", u"bin-2"], [u"value-1a", u"value-2b"])

def check_bins_replace():
	"""
	Verifies restore with --replace.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, [u"bin-1"], [u"value-1a"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])

def check_bins_replace_no_gen():
	"""
	Verifies restore with --replace and --no-generation.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, [u"bin-1"], [u"value-1a"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, [u"bin-1"], [u"value-1a"])

def check_bins_unique():
	"""
	Verifies restore with --unique.
	"""
	record = lib.read_record(lib.SET, "key-1")[2]
	lib.validate_record("key-1", record, [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])
	record = lib.read_record(lib.SET, "key-2")[2]
	lib.validate_record("key-2", record, [u"bin-1", u"bin-2"], [u"value-1b", u"value-2b"])

def test_no_policy():
	"""
	Tests restore without any policy options.
	"""
	lib.backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_no_policy(),
		None,
		None
	)

def test_no_gen():
	"""
	Tests restore with --no-generation.
	"""
	lib.backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_no_gen(),
		None,
		["--no-generation"]
	)

def test_replace():
	"""
	Tests restore with --replace.
	"""
	lib.backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_replace(),
		None,
		["--replace"]
	)

def test_replace_no_gen():
	"""
	Tests restore with --replace and --no-generation.
	"""
	lib.backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_replace_no_gen(),
		None,
		["--replace", "--no-generation"]
	)

def test_unique():
	"""
	Tests restore with --unique.
	"""
	lib.backup_and_restore(
		lambda context: fill_bins(),
		lambda context: prepare_bins(),
		lambda context: check_bins_unique(),
		None,
		["--unique"]
	)

def fill_ldt_bins():
	"""
	Creates two LDT records, one with generation count 3, the other with 2.
	"""
	lib.write_ldt_record(lib.SET, "key-1", [u"bin-1"], [[u"value-1a1"]])
	lib.write_ldt_record(lib.SET, "key-1", [u"bin-1"], [[u"value-1a2"]])
	lib.write_ldt_record(lib.SET, "key-1", [u"bin-1"], [[u"value-1a3"]])
	lib.write_ldt_record(lib.SET, "key-2", [u"bin-1"], [[u"value-1a1"]])
	lib.write_ldt_record(lib.SET, "key-2", [u"bin-1"], [[u"value-1a2"]])

def prepare_ldt_bins():
	"""
	Creates two LDT records with generation count 2.
	"""
	lib.write_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [[u"value-1b1"], [u"value-2b1"]])
	lib.write_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [[u"value-1b1"], [u"value-2b1"]])

def check_ldt_bins_no_policy():
	"""
	Verifies LDT restore without any policy options.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2", u"value-1a3"],
			[u"value-2b1"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
			[u"value-1b1"], [u"value-2b1"]])

def check_ldt_bins_no_gen():
	"""
	Verifies LDT restore with --no-generation.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2", u"value-1a3"],
			[u"value-2b1"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2"], [u"value-2b1"]])

def check_ldt_bins_replace():
	"""
	Verifies LDT restore with --replace.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1"], [
				[u"value-1a1", u"value-1a2", u"value-1a3"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
				[u"value-1b1"], [u"value-2b1"]])

def check_ldt_bins_replace_no_gen():
	"""
	Verifies LDT restore with --replace and --no-generation.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1"], [
				[u"value-1a1", u"value-1a2", u"value-1a3"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1"], [
				[u"value-1a1", u"value-1a2"]])

def check_ldt_bins_unique():
	"""
	Verifies LDT restore with --unique.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [
			[u"value-1b1"], [u"value-2b1"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
			[u"value-1b1"], [u"value-2b1"]])

def check_ldt_bins_keep_ldt():
	"""
	Verifies LDT restore with --keep-ldt.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2", u"value-1a3", u"value-1b1"],
			[u"value-2b1"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
			[u"value-1b1"], [u"value-2b1"]])

def check_ldt_bins_no_gen_keep_ldt():
	"""
	Verifies LDT restore with --no-generation and --keep-ldt.
	"""
	lib.validate_ldt_record(lib.SET, "key-1", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2", u"value-1a3", u"value-1b1"],
			[u"value-2b1"]])
	lib.validate_ldt_record(lib.SET, "key-2", [u"bin-1", u"bin-2"], [
			[u"value-1a1", u"value-1a2", u"value-1b1"], [u"value-2b1"]])

def test_ldt_no_policy():
	"""
	Tests LDT restore without any policy options.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_no_policy(),
		None,
		None
	)

def test_ldt_no_gen():
	"""
	Tests LDT restore with --no-generation.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_no_gen(),
		None,
		["--no-generation"]
	)

def test_ldt_replace():
	"""
	Tests LDT restore with --replace.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_replace(),
		None,
		["--replace"]
	)

def test_ldt_replace_no_gen():
	"""
	Tests LDT restore with --replace and --no-generation.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_replace_no_gen(),
		None,
		["--replace", "--no-generation"]
	)

def test_ldt_unique():
	"""
	Tests LDT restore with --unique.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_unique(),
		None,
		["--unique"]
	)

def test_ldt_keep_ldt():
	"""
	Tests LDT restore with --keep-ldt.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_keep_ldt(),
		None,
		["--keep-ldt"]
	)

def test_ldt_no_gen_keep_ldt():
	"""
	Tests LDT restore with --no-generation and --keep-ldt.
	"""
	lib.backup_and_restore(
		lambda context: fill_ldt_bins(),
		lambda context: prepare_ldt_bins(),
		lambda context: check_ldt_bins_no_gen_keep_ldt(),
		None,
		["--no-generation", "--keep-ldt"]
	)
