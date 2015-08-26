"""
Parse test-specific py.test command line options.
"""

import lib

def pytest_addoption(parser):
	"""
	Tells the option parser about our options.
	"""
	parser.addoption("--dir-mode", action="store_true", dest="dir_mode", default=False)
	parser.addoption("--file-mode", action="store_true", dest="file_mode", default=False)

def pytest_configure(config):
	"""
	Evaluates our options.
	"""
	if config.option.dir_mode == config.option.file_mode:
		raise Exception("Please pass either --dir-mode or --file-mode to py.test")

	if config.option.dir_mode:
		lib.enable_dir_mode()
	else:
		lib.disable_dir_mode()
