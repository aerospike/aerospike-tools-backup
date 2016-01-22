# coding=UTF-8

"""
Tests the representation of values in backup files.
"""

import lib

STRING_VALUES = lib.identifier_variations(10, False)
STRING_VALUES += lib.identifier_variations(100, False)
STRING_VALUES += lib.identifier_variations(1000, False)
STRING_VALUES += lib.identifier_variations(10000, False)

BLOB_VALUES = lib.identifier_variations(10)
BLOB_VALUES += lib.identifier_variations(100)
BLOB_VALUES += lib.identifier_variations(1000)
BLOB_VALUES += lib.identifier_variations(10000)
BLOB_VALUES = [bytearray(string.encode("UTF-8")) for string in BLOB_VALUES]

INTEGER_VALUES = [
	0, 1, -1,
	32767, -32768,
	2147483647, -2147483648,
	4294967296,
	1099511627776,
	9223372036854775807, -9223372036854775808
]

DOUBLE_VALUES = [
	0.0, 1.0, -1.0,
	1.2345, 1.234567890123456,
	-1.2345, -1.234567890123456,
	0.00000000000000000001,
	100000000000000000000.0,
	-0.00000000000000000001,
	-100000000000000000000.0,
	float("nan"), float("+inf"), float("-inf"),
	2.2250738585072014e-308,
	1.7976931348623157e+308
]

MAP_KEYS = [[lib.identifier(10) for _ in xrange(100)] for _ in xrange(50)]
MAP_VALUES = [[lib.identifier(10) for _ in xrange(100)] for _ in xrange(50)]

LIST_VALUES = [[lib.identifier(10) for _ in xrange(100)] for _ in xrange(50)]
LARGE_LIST_VALUES = []

def put_values(set_name, key, values):
	"""
	Inserts the given key with bins "bin-0" ... "bin-<n>" with the n given values.
	"""
	bin_names = [u"bin-" + str(index) for index in xrange(len(values))]
	lib.write_record(set_name, key, bin_names, values)

def check_values(set_name, key, values):
	"""
	Ensures that the given key has bins "bin-0" ... "bin-<n>" with the n given values.
	"""
	meta_key, meta_ttl, record = lib.read_record(set_name, key)
	bin_names = [u"bin-" + str(index) for index in xrange(len(values))]
	lib.validate_record(key, record, bin_names, values)
	lib.validate_meta(key, meta_key, meta_ttl)

def put_large_list(set_name, key, values):
	"""
	Inserts the given key with bins "bin-0" ... "bin-<n>" with the n given large
	list values.
	"""
	bin_names = [u"bin-" + str(index) for index in xrange(len(values))]
	lib.write_ldt_record(set_name, key, bin_names, values)

def check_large_list(set_name, key, values):
	"""
	Ensures that the given key has bins "bin-0" ... "bin-<n>" with the n given
	large list values.
	"""
	bin_names = [u"bin-" + str(index) for index in xrange(len(values))]
	lib.validate_ldt_record(set_name, key, bin_names, values)

def test_string_value():
	"""
	Test string values.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", STRING_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", STRING_VALUES)
	)

def test_blob_value():
	"""
	Test BLOB values.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", BLOB_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", BLOB_VALUES)
	)

def test_blob_value_compact():
	"""
	Test BLOB values, pass --compact to backup.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", BLOB_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", BLOB_VALUES),
		["--compact"]
	)

def test_integer_value():
	"""
	Test integer values.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", INTEGER_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", INTEGER_VALUES)
	)

def test_double_value():
	"""
	Test double values.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", DOUBLE_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", DOUBLE_VALUES)
	)

def test_map_value():
	"""
	Test map values. As they are BLOBs, we don't need that much variation
	here.
	"""
	values = []

	for key_list, value_list in zip(MAP_KEYS, MAP_VALUES):
		data = {}

		for key, value in zip(key_list, value_list):
			data[key] = value

		values.append(data)

	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", values),
		None,
		lambda context: check_values(lib.SET, "key", values)
	)

def test_list_value():
	"""
	Test list values. As they are BLOBs, we don't need that much variation
	here.
	"""
	lib.backup_and_restore(
		lambda context: put_values(lib.SET, "key", LIST_VALUES),
		None,
		lambda context: check_values(lib.SET, "key", LIST_VALUES)
	)

def populate():
	"""
	Populates the LDT list test data.
	"""
	for expo in xrange(2, 4):
		base_value = lib.identifier(pow(10, expo))

		for expo2 in xrange(2, 6):
			ldt = []

			for index in xrange(pow(10, expo2)):
				ldt.append(base_value + "-" + str(index))

			LARGE_LIST_VALUES.append(ldt)

def test_large_list_value():
	"""
	Test LDT list values. As they are stored as BLOBs, we don't need that
	much variation here.
	"""
	if not LARGE_LIST_VALUES:
		populate()

	lib.backup_and_restore(
		lambda context: put_large_list(lib.SET, "key", LARGE_LIST_VALUES),
		None,
		lambda context: check_large_list(lib.SET, "key", LARGE_LIST_VALUES)
	)

def test_large_list_value_1_mib():
	"""
	Test LDT list values. Use a 1-MiB batch size.
	"""
	if not LARGE_LIST_VALUES:
		populate()

	lib.backup_and_restore(
		lambda context: put_large_list(lib.SET, "key", LARGE_LIST_VALUES),
		None,
		lambda context: check_large_list(lib.SET, "key", LARGE_LIST_VALUES),
		restore_opts=["--batch-size", "1"]
	)
