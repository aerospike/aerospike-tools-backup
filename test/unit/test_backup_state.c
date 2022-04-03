
#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include <aerospike/as_random.h>

#include <utils.h>
#include <backup.h>
#include <backup_state.h>

#include "backup_tests.h"

#define TMP_FILE_1 "./test/unit/tmp1.asb.state"
#define TMP_FILE_2 "./test/unit/tmp2.asb.state"
#define TMP_FILE_3 "./test/unit/tmp3.asb.state"
#define TMP_FILE_4 "./test/unit/tmp4.asb.state"

#define TMP_FILE_N(var, n) \
	char var[] = "./test/unit/tmp0.asb.state"; \
	var[15] += (char) (n)


static void 
test_setup(void) 
{
}

static void
test_teardown(void)
{
	remove(TMP_FILE_1);
	remove(TMP_FILE_2);
	remove(TMP_FILE_3);
	remove(TMP_FILE_4);
}


static void
cmp_backup_state(const backup_state_t* b1, const backup_state_t* b2)
{

	for (uint16_t part_id = 0; part_id < MAX_PARTITIONS; part_id++) {
		as_digest_value dig1 = { 0 }, dig2 = { 0 };
		ck_assert_int_eq(backup_state_get_status(b1, part_id, dig1),
				backup_state_get_status(b2, part_id, dig2));
		ck_assert_int_eq(memcmp(dig1, dig2, sizeof(as_digest_value)), 0);
	}

	ck_assert_int_eq((int64_t) b1->backup_global_status.file_count,
			(int64_t) b2->backup_global_status.file_count);
	ck_assert_int_eq((int64_t) b1->backup_global_status.index_count,
			(int64_t) b2->backup_global_status.index_count);
	ck_assert_int_eq((int64_t) b1->backup_global_status.udf_count,
			(int64_t) b2->backup_global_status.udf_count);
	ck_assert_int_eq((int64_t) b1->backup_global_status.rec_count_total,
			(int64_t) b2->backup_global_status.rec_count_total);
	ck_assert_int_eq((int64_t) b1->backup_global_status.byte_count_total,
			(int64_t) b2->backup_global_status.byte_count_total);
	ck_assert_int_eq((int64_t) b1->backup_global_status.rec_count_total_committed,
			(int64_t) b2->backup_global_status.rec_count_total_committed);
	ck_assert_int_eq((int64_t) b1->backup_global_status.byte_count_total_committed,
			(int64_t) b2->backup_global_status.byte_count_total_committed);

	ck_assert_int_eq(b1->files.size, b2->files.size);
	for (uint32_t i = 0; i < b1->files.size; i++) {
		const backup_state_file_t* f1 =
			(const backup_state_file_t*) as_vector_get((as_vector*) &b1->files, i);
		const backup_state_file_t* f2 =
			(const backup_state_file_t*) as_vector_get((as_vector*) &b2->files, i);

		ck_assert_str_eq(io_proxy_file_path(f1->io_proxy), io_proxy_file_path(f2->io_proxy));
		ck_assert_int_eq((int64_t) f1->rec_count_file, (int64_t) f2->rec_count_file);
		ck_assert_int_eq((int64_t) f1->io_proxy->byte_cnt, (int64_t) f2->io_proxy->byte_cnt);
		ck_assert_int_eq((int64_t) f1->io_proxy->raw_byte_cnt, (int64_t) f2->io_proxy->raw_byte_cnt);
		ck_assert_int_eq((int64_t) (f1->io_proxy->flags & ~IO_PROXY_DESERIALIZE),
				(int64_t) (f2->io_proxy->flags & ~IO_PROXY_DESERIALIZE));
		ck_assert_int_eq((int64_t) f1->io_proxy->num, (int64_t) f2->io_proxy->num);
	}
}


START_TEST(test_init)
{
	backup_state_t b1, b2;

	ck_assert_int_eq(backup_state_init(&b1, TMP_FILE_1), 0);
	ck_assert_int_eq(backup_state_save(&b1), 0);

	ck_assert_int_eq(backup_state_load(&b2, TMP_FILE_1), 0);

	cmp_backup_state(&b1, &b2);

	backup_state_free(&b2);
	backup_state_free(&b1);
}
END_TEST

START_TEST(test_init_globals)
{
	backup_state_t b1, b2;
	as_random r;
	as_random_init(&r);

	backup_status_t status1, status2;
	memset(&status1, 0, sizeof(backup_status_t));
	memset(&status2, 0, sizeof(backup_status_t));

	status1.index_count = as_random_next_uint32(&r);
	status1.udf_count = as_random_next_uint32(&r);
	status1.file_count = as_random_next_uint64(&r);
	status1.rec_count_total = as_random_next_uint64(&r);
	status1.byte_count_total = as_random_next_uint64(&r);
	status1.rec_count_total_committed = as_random_next_uint64(&r);
	status1.byte_count_total_committed = as_random_next_uint64(&r);

	ck_assert_int_eq(backup_state_init(&b1, TMP_FILE_1), 0);
	backup_state_set_global_status(&b1, &status1);
	ck_assert_int_eq(backup_state_save(&b1), 0);

	ck_assert_int_eq(backup_state_load(&b2, TMP_FILE_1), 0);

	cmp_backup_state(&b1, &b2);

	backup_state_load_global_status(&b2, &status2);
	ck_assert_int_eq(memcmp(&status1, &status2, sizeof(backup_status_t)), 0);

	backup_state_free(&b2);
	backup_state_free(&b1);
}
END_TEST

START_TEST(test_serialize_io_proxy)
{
	file_proxy_t bup, fd;
	ck_assert_int_eq(file_proxy_write_init(&bup, TMP_FILE_1, 0), 0);

	io_write_proxy_t io;
	io_write_proxy_init(&io, TMP_FILE_2, 0);

	ck_assert_int_eq(io_proxy_write(&io, "test", 4), 4);
	ck_assert_int_eq(io_proxy_flush(&io), 0);
	ck_assert_int_eq(io_proxy_serialize(&io, &bup), 0);

	ck_assert_int_eq(file_proxy_close(&bup), 0);

	ck_assert_int_eq(file_proxy_read_init(&bup, TMP_FILE_1), 0);

	io_write_proxy_t io2;
	ck_assert_int_eq(io_proxy_deserialize(&io2, &bup), 0);
	file_proxy_close(&bup);

	ck_assert_int_eq((int64_t) io.byte_cnt, (int64_t) io2.byte_cnt);
	ck_assert_int_eq((int64_t) io.raw_byte_cnt, (int64_t) io2.raw_byte_cnt);
	ck_assert_int_eq(io.num, io2.num);
	ck_assert_int_eq(io.flags, io2.deserialized_flags);
	ck_assert_int_eq(io2.flags, IO_PROXY_DESERIALIZE);

	file_proxy_close(&fd);
}
END_TEST

START_TEST(test_init_single_file)
{
	backup_state_t b1, b2;
	as_random r;
	as_random_init(&r);
	uint64_t rec_count = as_random_next_uint64(&r);

	ck_assert_int_eq(backup_state_init(&b1, TMP_FILE_1), 0);
	{
		io_write_proxy_t* io = test_malloc(sizeof(io_write_proxy_t));
		ck_assert_ptr_ne(io, NULL);
		io_write_proxy_init(io, TMP_FILE_2, 0);

		ck_assert(backup_state_save_file(&b1, io, rec_count));
	}
	ck_assert_int_eq(backup_state_save(&b1), 0);

	ck_assert_int_eq(backup_state_load(&b2, TMP_FILE_1), 0);

	{
		ck_assert_int_eq(b2.files.size, 1);
		backup_state_file_t* f = (backup_state_file_t*) as_vector_get(&b2.files, 0);

		ck_assert_str_eq(io_proxy_file_path(f->io_proxy), TMP_FILE_2);
		ck_assert_int_eq((int64_t) f->rec_count_file, (int64_t) rec_count);
	}

	cmp_backup_state(&b1, &b2);

	backup_state_free(&b2);
	backup_state_free(&b1);
}
END_TEST

START_TEST(test_init_multiple_files)
{
#define N_FILES 3
	backup_state_t b1, b2;
	as_random r;
	as_random_init(&r);
	uint64_t rec_counts[N_FILES];
	
	for (uint32_t i = 0; i < N_FILES; i++) {
		rec_counts[i] = as_random_next_uint64(&r);
	}

	ck_assert_int_eq(backup_state_init(&b1, TMP_FILE_1), 0);

	for (uint32_t i = 2; i < 2 + N_FILES; i++) {
		TMP_FILE_N(file_name, i);

		io_write_proxy_t* io = test_malloc(sizeof(io_write_proxy_t));
		ck_assert_ptr_ne(io, NULL);
		io_write_proxy_init(io, file_name, 0);

		ck_assert(backup_state_save_file(&b1, io, rec_counts[i - 2]));
	}
	ck_assert_int_eq(backup_state_save(&b1), 0);

	ck_assert_int_eq(backup_state_load(&b2, TMP_FILE_1), 0);

	ck_assert_int_eq(b2.files.size, N_FILES);
	for (uint32_t i = 0; i < N_FILES; i++) {
		TMP_FILE_N(file_name, i + 2);

		backup_state_file_t* f = (backup_state_file_t*) as_vector_get(&b2.files, i);

		ck_assert_str_eq(io_proxy_file_path(f->io_proxy), file_name);
		ck_assert_int_eq((int64_t) f->rec_count_file, (int64_t) rec_counts[i]);
	}

	cmp_backup_state(&b1, &b2);

	backup_state_free(&b2);
	backup_state_free(&b1);
}
END_TEST


START_TEST(test_random_partitions)
{
	backup_state_t b1, b2;
	as_random r;
	as_random_init(&r);

	ck_assert_int_eq(backup_state_init(&b1, TMP_FILE_1), 0);
	for (uint16_t pid = 0; pid < MAX_PARTITIONS; pid++) {
		uint32_t v = as_random_next_uint32(&r);
		if (v & 0x3) {
			uint8_t last_digest[sizeof(as_digest_value)];
			for (uint64_t i = 0; i < sizeof(as_digest_value); i++) {
				last_digest[i] = (uint8_t) as_random_next_uint32(&r);
			}
			*(uint16_t*) last_digest =
				(uint16_t) ((*((uint16_t*) last_digest) & ~(MAX_PARTITIONS - 1)) | pid);

			if (v & 0x4) {
				if (v & 0x8) {
					backup_state_mark_complete(&b1, pid, NULL);
				}
				else {
					backup_state_mark_complete(&b1, pid, last_digest);
				}
			}
			else {
				backup_state_mark_incomplete(&b1, pid, last_digest);
			}
		}
		else {
			backup_state_mark_not_started(&b1, pid);
		}
	}

	ck_assert_int_eq(backup_state_save(&b1), 0);

	ck_assert_int_eq(backup_state_load(&b2, TMP_FILE_1), 0);

	cmp_backup_state(&b1, &b2);

	backup_state_free(&b2);
	backup_state_free(&b1);
}
END_TEST


Suite* backup_state_suite()
{
	Suite* s;
	TCase* tc_init;
	TCase* tc_parts;

	s = suite_create("Backup State");

	tc_init = tcase_create("Init");
	tcase_add_checked_fixture(tc_init, test_setup, test_teardown);
	tcase_add_test(tc_init, test_init);
	tcase_add_test(tc_init, test_init_globals);
	tcase_add_test(tc_init, test_serialize_io_proxy);
	tcase_add_test(tc_init, test_init_single_file);
	tcase_add_test(tc_init, test_init_multiple_files);
	suite_add_tcase(s, tc_init);

	tc_parts = tcase_create("Partitions");
	tcase_add_checked_fixture(tc_parts, test_setup, test_teardown);
	tcase_add_test(tc_parts, test_random_partitions);
	suite_add_tcase(s, tc_parts);

	return s;
}

