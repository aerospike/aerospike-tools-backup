
#include <check.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <utils.h>
#include <file_proxy.h>

#include "backup_tests.h"

#define TMP_FILE_1 "./test/unit/tmp1.asb.state"

static int stderr_tmp;
static int dev_null_fd;

static void 
silence_stderr_setup(void) 
{
	// redirect stderr to /dev/null
	stderr_tmp = dup(STDERR_FILENO);
	dev_null_fd = open("/dev/null", O_WRONLY);
	dup2(dev_null_fd, STDERR_FILENO);
}

static void
silence_stderr_teardown(void)
{
	dup2(stderr_tmp, STDERR_FILENO);
	close(stderr_tmp);
	close(dev_null_fd);

	remove(TMP_FILE_1);
}


START_TEST(test_init_write)
{
	file_proxy_t fp;
	ck_assert_int_eq(file_proxy_write_init(&fp, TMP_FILE_1, 0), 0);
	file_proxy_close(&fp);
}
END_TEST

START_TEST(test_init_read)
{
	file_proxy_t fp;
	// make the file so it exists
	ck_assert_int_eq(file_proxy_write_init(&fp, TMP_FILE_1, 0), 0);
	file_proxy_close(&fp);

	ck_assert_int_eq(file_proxy_read_init(&fp, TMP_FILE_1), 0);
	file_proxy_close(&fp);
}
END_TEST

START_TEST(test_write_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";

	file_proxy_t wfp;
	file_proxy_write_init(&wfp, TMP_FILE_1, 0);

	ck_assert_int_eq(file_proxy_tellg(&wfp), 0);
	ck_assert_int_eq((ssize_t) file_proxy_write(&wfp, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(file_proxy_tellg(&wfp), sizeof(buf) - 1);
	ck_assert_int_eq(file_proxy_flush(&wfp), 0);
	ck_assert_int_eq(file_proxy_tellg(&wfp), sizeof(buf) - 1);

	file_proxy_close(&wfp);
}

START_TEST(test_read_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	file_proxy_t wfp;
	ck_assert_int_eq(file_proxy_write_init(&wfp, TMP_FILE_1, 0), 0);

	ck_assert_int_eq((ssize_t) file_proxy_write(&wfp, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(file_proxy_flush(&wfp), 0);

	file_proxy_close(&wfp);

	file_proxy_t rfp;
	ck_assert_int_eq(file_proxy_read_init(&rfp, TMP_FILE_1), 0);

	ck_assert_int_eq(file_proxy_tellg(&rfp), 0);
	ck_assert_int_eq((ssize_t) file_proxy_read(&rfp, buf2, sizeof(buf2)), sizeof(buf) - 1);
	ck_assert_int_eq(file_proxy_tellg(&rfp), sizeof(buf) - 1);

	file_proxy_close(&rfp);
}

#define SIZE 1048576L
START_TEST(test_large_write) {
	char* buf = (char*) cf_malloc(SIZE);
	for (uint64_t i = 0; i < SIZE; i++) {
		buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
	}

	file_proxy_t wfp;
	ck_assert_int_eq(file_proxy_write_init(&wfp, TMP_FILE_1, 0), 0);
	ck_assert_int_eq((ssize_t) file_proxy_write(&wfp, buf, SIZE), SIZE);

	file_proxy_close(&wfp);
	cf_free(buf);
}
END_TEST

START_TEST(test_large_read) {
	char* buf = (char*) cf_malloc(SIZE);
	for (uint64_t i = 0; i < SIZE - 1; i++) {
		buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
	}
	buf[SIZE - 1] = '\0';

	file_proxy_t wfp;
	ck_assert_int_eq(file_proxy_write_init(&wfp, TMP_FILE_1, 0), 0);
	ck_assert_int_eq((ssize_t) file_proxy_write(&wfp, buf, SIZE), SIZE);
	file_proxy_close(&wfp);

	char* buf2 = (char*) cf_malloc(SIZE + 10);
	file_proxy_t rfp;
	ck_assert_int_eq(file_proxy_read_init(&rfp, TMP_FILE_1), 0);
	ck_assert_int_eq((ssize_t) file_proxy_read(&rfp, buf2, SIZE + 10), SIZE);
	ck_assert_str_eq(buf, buf2);

	file_proxy_close(&rfp);
	cf_free(buf2);
	cf_free(buf);
}
END_TEST


Suite* file_proxy_suite()
{
	Suite* s;
	TCase* tc_init;
	TCase* tc_rw;

	s = suite_create("File Proxy");

	tc_init = tcase_create("Init");
	tcase_add_checked_fixture(tc_init, silence_stderr_setup,
			silence_stderr_teardown);
	tcase_add_test(tc_init, test_init_write);
	tcase_add_test(tc_init, test_init_read);
	suite_add_tcase(s, tc_init);

	tc_rw = tcase_create("Read/Write");
	tcase_add_checked_fixture(tc_rw, silence_stderr_setup,
			silence_stderr_teardown);
	tcase_add_test(tc_rw, test_write_file_pos);
	tcase_add_test(tc_rw, test_read_file_pos);
	tcase_add_test(tc_rw, test_large_write);
	tcase_add_test(tc_rw, test_large_read);
	suite_add_tcase(s, tc_rw);

	return s;
}

