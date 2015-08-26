# coding=UTF-8

"""
Tests the representation of TTLs in backup files.
"""

import lib

def put_ttl(key, ttl):
	"""
	Inserts the given key with the given TTL.
	"""
	lib.write_record(lib.SET, key, [u"value"], [u"value"], False, ttl)

def check_ttl(key, expected_ttl):
	"""
	Ensures that the given key has the given TTL.
	"""
	meta_key, meta_ttl, record = lib.read_record(lib.SET, key)
	lib.validate_record(key, record, [u"value"], [u"value"])
	lib.validate_meta(key, meta_key, meta_ttl, False, expected_ttl)

def check_expired(key):
	"""
	Ensures that the given key does not exist.
	"""
	assert not lib.test_record(lib.SET, key), "Key %s should not exist" % key

def test_no_ttl():
	"""
	Test without a TTL.
	"""
	lib.backup_and_restore(
		lambda context: put_ttl(0, None),
		None,
		lambda context: check_ttl(0, None)
	)

def test_ttl():
	"""
	Test TTL without a delay.
	"""
	lib.backup_and_restore(
		lambda context: put_ttl(1, 100),
		None,
		lambda context: check_ttl(1, (90, 100))
	)

def test_ttl_delay_10():
	"""
	Test TTL with a 10 second delay.
	"""
	lib.backup_and_restore(
		lambda context: put_ttl(2, 100),
		None,
		lambda context: check_ttl(2, (80, 90)),
		restore_delay=10
	)

def test_ttl_expired():
	"""
	Make sure that expired records are not restored. Works, because we prevent
	asd from expiring records (low-water-pct set to 10).
	"""
	lib.backup_and_restore(
		lambda context: put_ttl(3, 5),
		None,
		lambda context: check_expired(3),
		restore_delay=10
	)
