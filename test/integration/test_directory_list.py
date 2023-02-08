# coding=UTF-8

"""
Tests usage of the asrestore --directory-list option.
"""

import lib
from run_backup import run_backup_w_valgrind, run_restore_w_valgrind, multi_backup_and_restore
import record_gen

path1 = "dir1"
path2 = "dir2"
path3 = "dir3"
path4 = "dir4"

def get_basic_backup_options():
    backup_options = ["--namespace", lib.NAMESPACE, "-r"]
    return backup_options

def test_restore_from_multi_dir():
    """
	Tests restoring from multiple backup dirs
    """
    local_path1 = lib.temporary_path(path1)
    local_path2 = lib.temporary_path(path2)
    local_path3 = lib.temporary_path(path3)
    local_path4 = lib.temporary_path(path4)

    backup_options1 = get_basic_backup_options() + ["--directory", local_path1, "--partition-list", "0-1024"]
    backup_options2 = get_basic_backup_options() + ["--directory", local_path2, "--partition-list", "1024-1024"]
    backup_options3 = get_basic_backup_options() + ["--directory", local_path3, "--partition-list", "2048-1024"]
    backup_options4 = get_basic_backup_options() + ["--directory", local_path4, "--partition-list", "3072-1024"]

    restore_options = ["--directory-list", local_path1 + "," + local_path2 + "," + local_path3 + "," + local_path4]

    n_records = 5000
    filler = lambda context: record_gen.put_records(n_records, context, lib.SET, False, 0)
    checker = lambda context: record_gen.check_records(n_records, context, lib.SET, False, 0)

    multi_backup_and_restore(filler, None, checker, backup_opts=[backup_options1, backup_options2, backup_options3, backup_options4], restore_opts=restore_options)

def test_restore_from_multi_parent_dir():
    """
	Tests restoring from multiple backup dirs using --parent-directory
    """
    root_path = lib.absolute_path(lib.WORK_DIRECTORY)

    local_path1 = lib.temporary_path(path1)
    local_path2 = lib.temporary_path(path2)

    backup_options1 = get_basic_backup_options() + ["--directory", local_path1, "--partition-list", "0-2048"]
    backup_options2 = get_basic_backup_options() + ["--directory", local_path2, "--partition-list", "2048-2048"]

    restore_options = ["--parent-directory", root_path, "--directory-list", local_path1[len(root_path):] + "," + local_path2[len(root_path):]]

    n_records = 5000
    filler = lambda context: record_gen.put_records(n_records, context, lib.SET, False, 0)
    checker = lambda context: record_gen.check_records(n_records, context, lib.SET, False, 0)

    multi_backup_and_restore(filler, None, checker, backup_opts=[backup_options1, backup_options2], restore_opts=restore_options)