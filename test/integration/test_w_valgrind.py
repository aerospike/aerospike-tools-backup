# coding=UTF-8

"""
Tests basic asbackup/asrestore commands with valgrind for memory leaks/errors
"""

import lib
from run_backup import run_backup_w_valgrind, run_restore_w_valgrind
import record_gen

path = lib.VAL_BACKUP_FILES

def get_basic_backup_options():
    backup_options = "--directory", path, \
			"--namespace", lib.NAMESPACE, \
			"-r"
    return backup_options

def get_basic_restore_options():
    restore_options = "--directory", path,
    return restore_options

def test_backup_to_dir():
    """
	Tests backup to dir running by valgrind
    """
    backup_options = get_basic_backup_options()
    context = {}
    n_records = 5000
    filler = lambda context: record_gen.put_records(n_records, context, lib.SET, do_indexes=True)
    assert run_backup_w_valgrind(filler, context=context, backup_options=backup_options) == False, "Backup test with valgrind failed, cmd options {0}".format(backup_options)

def test_restore_batch_writes_to_dir():
    """
	Tests restore to dir with batch write enabled running by valgrind
    """
    restore_options = get_basic_restore_options()
    assert run_restore_w_valgrind(*restore_options) == False, "Restore test with valgrind failed, cmd options {0}".format(restore_options)


def test_restore_to_dir_batch_writes_disabled():
    """
	Tests restore to dir with batch write disabled running by valgrind
    """
    restore_options = get_basic_restore_options()
    assert run_restore_w_valgrind(*restore_options, "--disable-batch-writes") == False, "Restore test with valgrind failed, cmd options {0}".format(restore_options)
