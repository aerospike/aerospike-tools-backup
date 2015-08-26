# coding=UTF-8

"""
Tests the --node-list option.
"""

import lib

def backup_and_restore(fill, check, node_lists):
	"""
	Do one backup-restore cycle.
	"""
	lib.start()

	try:
		fill()
		paths = []

		for node_list in node_lists:
			argument = ",".join([host + ":" + str(port) for host, port in node_list])

			if lib.is_dir_mode():
				path = lib.temporary_path("dir")
				lib.backup_to_directory(path, "--node-list", argument)
			else:
				path = lib.temporary_path("asb")
				lib.backup_to_file(path, "--node-list", argument)

			paths.append(path)

		lib.reset()

		for path in paths:
			if lib.is_dir_mode():
				lib.restore_from_directory(path)
			else:
				lib.restore_from_file(path)

		check()
	except Exception:
		lib.stop(True)
		raise
	else:
		lib.stop()

def filler():
	"""
	Fills the namespace with a few records.
	"""
	for index in xrange(10000):
		lib.write_record(lib.SET, index, [u"bin-1"], [index])

def checker():
	"""
	Verifies that the expected records are there.
	"""
	for index in xrange(10000):
		assert lib.test_record(lib.SET, index), "Key %s is missing" % index

def test_node_list_1():
	"""
	Tests the --node-list option with one node.
	"""
	backup_and_restore(filler, checker, [[("127.0.0.1", 3000)], [("127.0.0.1", 4000)]])

def test_node_list_2():
	"""
	Tests the --node-list option with two nodes.
	"""
	backup_and_restore(filler, checker, [[("127.0.0.1", 3000), ("127.0.0.1", 4000)]])
