# coding=UTF-8

"""
Tests the representation of keys in backup files.
"""

import lib

STRING_KEYS = lib.identifier_variations(10, False)
STRING_KEYS += lib.identifier_variations(100, False)
STRING_KEYS += lib.identifier_variations(1000, False)
STRING_KEYS += lib.identifier_variations(10000, False)

BLOB_KEYS = lib.identifier_variations(10)
BLOB_KEYS += lib.identifier_variations(100)
BLOB_KEYS += lib.identifier_variations(1000)
BLOB_KEYS += lib.identifier_variations(10000)
BLOB_KEYS = [bytearray(string.encode("UTF-8")) for string in BLOB_KEYS if len(string) > 0]

INTEGER_KEYS = [
	0, 1, -1,
	32767, -32768,
	2147483647, -2147483648,
	4294967296,
	1099511627776,
	9223372036854775807, -9223372036854775808
]

def put_keys(set_name, keys, value, send_key):
	"""
	Inserts the given keys with a single "value" bin with the given value.
	"""
	for key in keys:
		lib.write_record(set_name, key, [u"value"], [value], send_key)

def check_keys(set_name, keys, value, expect_key):
	"""
	Ensures that the given keys have a single "value" bin with the given value.

	We use a scan here, so that we can honor the expect_key flag. A get operation
	wouldn't allow us to determine whether a record in the database has a user key
	or not.
	"""
	records = lib.read_all_records(set_name)

	for key in keys:
		digest = lib.get_key_digest(set_name, key)
		meta_key, meta_ttl, record = records[str(digest).encode("hex")]
		lib.validate_record(key, record, [u"value"], [value])
		lib.validate_meta(key, meta_key, meta_ttl, expect_key)

def test_string_key():
	"""
	Test string keys, don't store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, STRING_KEYS, u"foobar", False),
		None,
		lambda context: check_keys(lib.SET, STRING_KEYS, u"foobar", False)
	)

def test_string_key_stored():
	"""
	Test string keys, store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, STRING_KEYS, u"foobar", True),
		None,
		lambda context: check_keys(lib.SET, STRING_KEYS, u"foobar", True)
	)

def test_blob_key():
	"""
	Test BLOB keys, don't store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, BLOB_KEYS, u"foobar", False),
		None,
		lambda context: check_keys(lib.SET, BLOB_KEYS, u"foobar", False)
	)

def test_blob_key_stored():
	"""
	Test BLOB keys, store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, BLOB_KEYS, u"foobar", True),
		None,
		lambda context: check_keys(lib.SET, BLOB_KEYS, u"foobar", True)
	)

def test_blob_key_stored_compact():
	"""
	Test BLOB keys, store the user key, pass --compact to backup.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, BLOB_KEYS, u"foobar", True),
		None,
		lambda context: check_keys(lib.SET, BLOB_KEYS, u"foobar", True),
		["--compact"]
	)

def test_integer_key():
	"""
	Test integer keys, don't store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, INTEGER_KEYS, u"foobar", False),
		None,
		lambda context: check_keys(lib.SET, INTEGER_KEYS, u"foobar", False)
	)

def test_integer_key_stored():
	"""
	Test integer keys, store the user key.
	"""
	lib.backup_and_restore(
		lambda context: put_keys(lib.SET, INTEGER_KEYS, u"foobar", True),
		None,
		lambda context: check_keys(lib.SET, INTEGER_KEYS, u"foobar", True)
	)
