
#include <check.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <aerospike/as_random.h>

#include <utils.h>
#include <io_proxy.h>

#include "backup_tests.h"

#define TMP_FILE_1 "./test/unit/tmp1.asb.state"
#define TMP_FILE_2 "./test/unit/tmp2.asb.state"

static const char* const key_path = "test/test_key.pem";
static const char* const key2_path = "test/test_key2.pem";

const encryption_key_t aes_key = {
	.data = (uint8_t[32]) {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f
	},
	.len = 32
};


static int stderr_tmp;
static int dev_null_fd;

static void 
silence_stderr_setup(void) 
{
	stderr_tmp = dup(STDERR_FILENO);
	dev_null_fd = open("/dev/null", O_WRONLY);
	dup2(dev_null_fd, STDERR_FILENO);

	remove(TMP_FILE_1);
	remove(TMP_FILE_2);
}

static void
silence_stderr_teardown(void)
{
	dup2(stderr_tmp, STDERR_FILENO);
	close(stderr_tmp);
	close(dev_null_fd);

	remove(TMP_FILE_1);
	remove(TMP_FILE_2);
}

/*
 * all different ways an IO proxy can be configured
 */
#define INIT_MATRIX_SIZE (2 * 5)

#define INIT_MATRIX_OPTS(io, idx) \
	do { \
		if (idx % 2 == 1) { \
			ck_assert_int_eq(io_proxy_init_compression(&io, \
						IO_PROXY_COMPRESS_ZSTD), 0); \
		} \
		if ((idx / 2) % 5 == 1) { \
			ck_assert_int_eq(io_proxy_init_encryption(&io, &aes_key, \
						IO_PROXY_ENCRYPT_AES128), 0); \
		} \
		else if ((idx / 2) % 5 == 2) { \
			ck_assert_int_eq(io_proxy_init_encryption(&io, &aes_key, \
						IO_PROXY_ENCRYPT_AES256), 0); \
		} \
		else if ((idx / 2) % 5 == 3) { \
			ck_assert_int_eq(io_proxy_init_encryption_file(&io, key_path, \
						IO_PROXY_ENCRYPT_AES128), 0); \
		} \
		else if ((idx / 2) % 5 == 4) { \
			ck_assert_int_eq(io_proxy_init_encryption_file(&io, key_path, \
						IO_PROXY_ENCRYPT_AES256), 0); \
		} \
	} while (0)

#define WRITE_INIT_MATRIX(io, file, idx) \
	do { \
		ck_assert_int_eq(io_write_proxy_init(&io, file, 0), 0); \
		INIT_MATRIX_OPTS(io, idx); \
	} while(0)

#define READ_INIT_MATRIX(io, file, idx) \
	do { \
		ck_assert_int_eq(io_read_proxy_init(&io, file), 0); \
		INIT_MATRIX_OPTS(io, idx); \
	} while(0)


#define WRITE_TEST_MATRIX(fn_name, fn_body) \
	START_TEST(fn_name) { \
		uint32_t init_idx = 0; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _zstd) { \
		uint32_t init_idx = 1; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128) { \
		uint32_t init_idx = 2; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128 ## _zstd) { \
		uint32_t init_idx = 3; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256) { \
		uint32_t init_idx = 4; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256 ## _zstd) { \
		uint32_t init_idx = 5; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file) { \
		uint32_t init_idx = 6; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file ## _zstd) { \
		uint32_t init_idx = 7; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file) { \
		uint32_t init_idx = 8; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file ## _zstd) { \
		uint32_t init_idx = 9; \
		io_write_proxy_t wio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
	} \
	END_TEST

#define TEST_MATRIX(fn_name, write_fn_body, read_fn_body) \
	START_TEST(fn_name) { \
		uint32_t init_idx = 0; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _zstd) { \
		uint32_t init_idx = 1; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128) { \
		uint32_t init_idx = 2; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128 ## _zstd) { \
		uint32_t init_idx = 3; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256) { \
		uint32_t init_idx = 4; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256 ## _zstd) { \
		uint32_t init_idx = 5; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file) { \
		uint32_t init_idx = 6; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file ## _zstd) { \
		uint32_t init_idx = 7; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file) { \
		uint32_t init_idx = 8; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file ## _zstd) { \
		uint32_t init_idx = 9; \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		WRITE_INIT_MATRIX(wio, TMP_FILE_1, init_idx); \
		write_fn_body \
		io_proxy_close2(&wio, FILE_PROXY_EOF); \
		READ_INIT_MATRIX(rio, TMP_FILE_1, init_idx); \
		read_fn_body \
		io_proxy_close(&rio); \
	} \
	END_TEST

#define RUN_TEST_MATRIX(fn_name, tc_name) \
	tcase_add_test(tc_name, fn_name); \
	tcase_add_test(tc_name, fn_name ## _zstd); \
	tcase_add_test(tc_name, fn_name ## _aes128); \
	tcase_add_test(tc_name, fn_name ## _aes128 ## _zstd); \
	tcase_add_test(tc_name, fn_name ## _aes256); \
	tcase_add_test(tc_name, fn_name ## _aes256 ## _zstd); \
	tcase_add_test(tc_name, fn_name ## _aes128_file); \
	tcase_add_test(tc_name, fn_name ## _aes128_file ## _zstd); \
	tcase_add_test(tc_name, fn_name ## _aes256_file); \
	tcase_add_test(tc_name, fn_name ## _aes256_file ## _zstd)




// test init write io proxies
WRITE_TEST_MATRIX(test_init_write, {});
// test init write+read io proxies
TEST_MATRIX(test_init_read, {
	// empty files aren't saved, so write something to the file
	io_proxy_putc(&wio, 'a');
	io_proxy_flush(&wio);
}, {});


#define VA_ARGS(...) , ##__VA_ARGS__

#define DEFINE_WRITE_TO(write_fn, io, expected_ret, ...) \
	do { \
		ck_assert_int_eq(write_fn(&io VA_ARGS(__VA_ARGS__)), expected_ret); \
		ck_assert_int_eq(io_proxy_flush(&io), 0); \
	} while (0)

#define DEFINE_READ_FROM(read_fn, io, expected_ret, eof_ret, ...) \
	do { \
		ck_assert_int_eq(read_fn(&io VA_ARGS(__VA_ARGS__)), expected_ret); \
		ck_assert_int_eq(read_fn(&io VA_ARGS(__VA_ARGS__)), eof_ret); \
	} while (0)


WRITE_TEST_MATRIX(test_rw_putc, DEFINE_WRITE_TO(io_proxy_putc, wio, 'a', 'a'););

TEST_MATRIX(test_rw_getc, DEFINE_WRITE_TO(io_proxy_putc, wio, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_getc, rio, 'a', EOF););

TEST_MATRIX(test_rw_getc_unlocked, DEFINE_WRITE_TO(io_proxy_putc, wio, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_getc_unlocked, rio, 'a', EOF););

TEST_MATRIX(test_rw_peekc_unlocked, DEFINE_WRITE_TO(io_proxy_putc, wio, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_peekc_unlocked, rio, 'a', 'a'););

WRITE_TEST_MATRIX(test_rw_write,
		// write to write proxy
		char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
		DEFINE_WRITE_TO(io_proxy_write, wio, sizeof(buf) - 1, buf, sizeof(buf) - 1);
		);

TEST_MATRIX(test_rw_read,
		char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
		char buf2[sizeof(buf)];
		// write to write proxy
		DEFINE_WRITE_TO(io_proxy_write, wio, sizeof(buf) - 1, buf, sizeof(buf) - 1);
		,
		// read from read proxy
		DEFINE_READ_FROM(io_proxy_read, rio, sizeof(buf) - 1, 0, buf2, sizeof(buf2));
		buf2[sizeof(buf2) - 1] = '\0';
		ck_assert_str_eq(buf, buf2);
		);

TEST_MATRIX(test_rw_gets,
		char buf[] = "abcdefghijklmnopqrstuv\nwxyz1234567890";
		char word1[] = "abcdefghijklmnopqrstuv\n";
		char word2[] = "wxyz1234567890";
		char buf2[sizeof(buf)];
		// write to write proxy
		DEFINE_WRITE_TO(io_proxy_write, wio, sizeof(buf) - 1, buf, sizeof(buf) - 1);
		,
		// read words from read proxy
		ck_assert_ptr_eq(io_proxy_gets(&rio, buf2, sizeof(buf2)), buf2);
		ck_assert_str_eq(word1, buf2);
		ck_assert_ptr_eq(io_proxy_gets(&rio, buf2, sizeof(buf2)), buf2);
		ck_assert_str_eq(word2, buf2);
		ck_assert_ptr_eq(io_proxy_gets(&rio, buf2, sizeof(buf2)), NULL);
		);

TEST_MATRIX(test_rw_printf,
		char format[] = "String: %s, int: %d, float: %1.2f";
		char expect[] = "String: test%s, int: 42, float: 3.14";
		char buf[sizeof(expect) + 10];

		// write to write proxy
		DEFINE_WRITE_TO(io_proxy_printf, wio, sizeof(expect) - 1, format,
				"test%s", 42, 3.14);
		,
		// read from read proxy
		DEFINE_READ_FROM(io_proxy_read, rio, sizeof(expect) - 1, 0, buf, sizeof(buf));
		buf[sizeof(expect) - 1] = '\0';

		ck_assert_str_eq(expect, buf);
		);

START_TEST(test_rw_putc_with_reader)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	io_proxy_putc(&wio, 'a');
	io_proxy_flush(&wio);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_putc(&rio, 'a'), 0);
	io_proxy_close(&rio);
}

START_TEST(test_rw_getc_with_writer)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_getc(&wio), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_rw_getc_unlocked_with_writer)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_getc_unlocked(&wio), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_rw_peekc_unlocked_with_writer)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_peekc_unlocked(&wio), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_rw_write_with_reader)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	io_proxy_putc(&wio, 'a');
	io_proxy_flush(&wio);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	char buf[] = "123";
	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_write(&rio, buf, sizeof(buf) - 1), 0);
	io_proxy_close(&rio);
}

START_TEST(test_rw_read_with_writer)
{
	char buf[] = "123";
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_read(&wio, buf, sizeof(buf) - 1), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_rw_gets_with_writer)
{
	char buf[] = "123";
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	ck_assert_ptr_eq(io_proxy_gets(&wio, buf, sizeof(buf) - 1), NULL);
	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_rw_printf_with_reader)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	io_proxy_putc(&wio, 'a');
	io_proxy_flush(&wio);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_printf(&rio, "%s * %d = %c", "test", 2, 'a'), 0);
	io_proxy_close(&rio);
}

START_TEST(test_rw_flush_with_reader)
{
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);
	io_proxy_putc(&wio, 'a');
	io_proxy_flush(&wio);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_1, 0);
	ck_assert_int_lt(io_proxy_flush(&rio), 0);
	io_proxy_close(&rio);
}


START_TEST(test_cmp_parse_zstd)
{
	compression_opt opt;
	ck_assert_int_eq(parse_compression_type("zstd", &opt), 0);
	ck_assert_int_eq(opt, IO_PROXY_COMPRESS_ZSTD);
}
END_TEST

START_TEST(test_cmp_parse_unknown)
{
	compression_opt opt;
	ck_assert_int_eq(parse_compression_type("aes128", &opt), -1);
	ck_assert_int_eq(parse_compression_type("notawnfoew", &opt), -1);
	ck_assert_int_eq(parse_compression_type("()!)H", &opt), -1);
	ck_assert_int_eq(parse_compression_type("zstdd", &opt), -1);
	ck_assert_int_eq(parse_compression_type("zst", &opt), -1);
	ck_assert_int_eq(parse_compression_type("zzzz", &opt), -1);
	ck_assert_int_eq(parse_compression_type("", &opt), -1);
}
END_TEST


START_TEST(test_enc_encryption_key_init)
{
	encryption_key_t key;
	uint64_t len = 32;
	uint8_t* buffer = (uint8_t*) test_malloc(len);

	encryption_key_init(&key, buffer, len);

	ck_assert_ptr_eq(key.data, buffer);
	ck_assert_int_eq((int64_t) key.len, (int64_t) len);

	encryption_key_free(&key);
}
END_TEST

START_TEST(test_enc_no_such_key_file)
{
	io_read_proxy_t io;
	io_read_proxy_init(&io, TMP_FILE_1);
	ck_assert_int_lt(io_proxy_init_encryption_file(&io, "this_file_does_not_exist.pem",
			IO_PROXY_ENCRYPT_AES128), 0);
}
END_TEST

START_TEST(test_enc_malformed_key_file)
{
	io_read_proxy_t io;
	io_read_proxy_init(&io, TMP_FILE_1);
	ck_assert_int_lt(io_proxy_init_encryption_file(&io, "test/bad_test_key.pem",
			IO_PROXY_ENCRYPT_AES128), 0);
}
END_TEST

START_TEST(test_enc_parse_aes128)
{
	encryption_opt opt;
	ck_assert_int_eq(parse_encryption_type("aes128", &opt), 0);
	ck_assert_int_eq(opt, IO_PROXY_ENCRYPT_AES128);
}
END_TEST

START_TEST(test_enc_parse_aes256)
{
	encryption_opt opt;
	ck_assert_int_eq(parse_encryption_type("aes256", &opt), 0);
	ck_assert_int_eq(opt, IO_PROXY_ENCRYPT_AES256);
}
END_TEST

START_TEST(test_enc_parse_unknown)
{
	encryption_opt opt;
	ck_assert_int_eq(parse_encryption_type("aes", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("notawnfoew", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("()!)H", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("aes127", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("aes1288", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("aes2566", &opt), -1);
	ck_assert_int_eq(parse_encryption_type("", &opt), -1);
}
END_TEST

START_TEST(test_enc_wrong_key_aes128)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	// encrypt with test_key.pem
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 6);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	ck_assert_int_eq(io_read_proxy_init(&rio, TMP_FILE_1), 0);
	ck_assert_int_eq(io_proxy_init_encryption_file(&rio, key2_path,
				IO_PROXY_ENCRYPT_AES128), 0);

	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	buf2[sizeof(buf) - 1] = '\0';
	ck_assert_str_ne(buf, buf2);
	io_proxy_close(&rio);
}

START_TEST(test_enc_wrong_key_aes256)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	// encrypt with test_key.pem
	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 8);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	ck_assert_int_eq(io_read_proxy_init(&rio, TMP_FILE_1), 0);
	ck_assert_int_eq(io_proxy_init_encryption_file(&rio, key2_path,
				IO_PROXY_ENCRYPT_AES256), 0);

	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	buf2[sizeof(buf) - 1] = '\0';
	ck_assert_str_ne(buf, buf2);
	io_proxy_close(&rio);
}

#define SIZE 1048576
WRITE_TEST_MATRIX(test_large_write,
		char* buf = (char*) test_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		DEFINE_WRITE_TO(io_proxy_write, wio, SIZE, buf, SIZE);
		cf_free(buf);
		);

TEST_MATRIX(test_large_read,
		char* buf = (char*) test_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE - 1; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		buf[SIZE - 1] = '\0';
		DEFINE_WRITE_TO(io_proxy_write, wio, SIZE, buf, SIZE);
		,
		char* buf2 = (char*) test_malloc(SIZE + 10);
		DEFINE_READ_FROM(io_proxy_read, rio, SIZE, 0, buf2, SIZE + 10);
		ck_assert_str_eq(buf, buf2);
		cf_free(buf2);
		cf_free(buf);
		);

WRITE_TEST_MATRIX(test_large_write_putc,
		char* buf = (char*) test_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_putc(&wio, buf[i]), buf[i]);
		cf_free(buf);
		);

TEST_MATRIX(test_large_read_getc,
		char* buf = (char*) test_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		buf[SIZE - 1] = '\0';
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_putc(&wio, buf[i]), buf[i]);
		ck_assert_int_eq(io_proxy_flush(&wio), 0);
		,
		char* buf2 = (char*) test_malloc(SIZE + 10);
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_getc_unlocked(&rio), buf[i]);
		ck_assert_int_eq(io_proxy_getc_unlocked(&rio), EOF);
		cf_free(buf2);
		cf_free(buf);
		);

START_TEST(test_write_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";

	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);

	ck_assert_int_eq(io_write_proxy_absolute_pos(&wio), 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_write_proxy_absolute_pos(&wio), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	ck_assert_int_eq(io_write_proxy_absolute_pos(&wio), sizeof(buf) - 1);

	io_proxy_close2(&wio, FILE_PROXY_EOF);
}

START_TEST(test_read_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 0);

	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);

	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	ck_assert_int_eq(io_read_proxy_init(&rio, TMP_FILE_1), 0);

	ck_assert_int_eq(io_read_proxy_estimate_pos(&rio), 0);
	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	ck_assert_int_eq(io_read_proxy_estimate_pos(&rio), sizeof(buf) - 1);

	io_proxy_close(&rio);
}

/*
START_TEST(test_buffered_write_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";

	FILE* tmp = tmpfile();
	file_proxy_t wfp;
	io_write_proxy_t wio;
	local_file_proxy_init_fd(&wfp, tmp, FILE_PROXY_WRITE_MODE);
	WRITE_INIT_MATRIX(wio, &wfp, 0);

	ck_assert_int_eq(io_write_proxy_bytes_written(&wio), 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	// since it's buffered, this write should not have gone through yet
	ck_assert_int_eq(io_write_proxy_bytes_written(&wio), 0);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	ck_assert_int_eq(io_write_proxy_bytes_written(&wio), sizeof(buf) - 1);

	io_proxy_close2(&wio, FILE_PROXY_EOF);
	file_proxy_close(&wfp);
	fclose(tmp);
}

START_TEST(test_buffered_read_file_pos)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	FILE* tmp = tmpfile();
	file_proxy_t wfp;
	io_write_proxy_t wio;
	local_file_proxy_init_fd(&wfp, tmp, FILE_PROXY_WRITE_MODE);
	WRITE_INIT_MATRIX(wio, &wfp, 0);

	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);

	io_proxy_close2(&wio, FILE_PROXY_EOF);
	file_proxy_close(&wfp);

	fseek(tmp, 0, SEEK_SET);

	file_proxy_t rfp;
	io_read_proxy_t rio;
	local_file_proxy_init_fd(&rfp, tmp, FILE_PROXY_READ_MODE);
	ck_assert_int_eq(io_read_proxy_init(&rio, &rfp), 0);

	ck_assert_int_eq(io_read_proxy_estimate_pos(&rio), 0);
	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	ck_assert_int_eq(io_read_proxy_estimate_pos(&rio), sizeof(buf) - 1);

	io_proxy_close(&rio);
	file_proxy_close(&rfp);
	fclose(tmp);
}
*/

START_TEST(test_read_compressed_data_monotonicity)
{
	const uint64_t n_chars = 130000;
	as_random random;
	as_random_init(&random);

	char* buf = (char*) test_malloc(n_chars * sizeof(char));
	char* buf2 = (char*) test_malloc(n_chars * sizeof(char));
	for (uint64_t i = 0; i < n_chars; i++) {
		uint32_t offset = as_random_next_uint32(&random) % 26;
		buf[i] = 'a' + (char) offset;
	}

	io_write_proxy_t wio;
	// initialize the write proxy with zstd compression
	WRITE_INIT_MATRIX(wio, TMP_FILE_1, 1);

	ck_assert_int_eq(io_proxy_write(&wio, buf, n_chars), n_chars);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);

	long file_size = io_write_proxy_bytes_written(&wio);
	io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_1, 1);

	int64_t pos = 0;
	int64_t last_file_pos = 0;
	while (pos < (int64_t) n_chars) {
		int64_t read_amt = (int64_t) (as_random_next_uint32(&random) % 1021) + 1;
		int64_t expected_read_amt = MIN(read_amt, (int64_t) n_chars - pos);
		ck_assert_int_eq(io_proxy_read(&rio, buf2, (uint64_t) read_amt), expected_read_amt);
		pos += expected_read_amt;

		int64_t file_pos = io_read_proxy_estimate_pos(&rio);
		ck_assert_int_le(last_file_pos, file_pos);
		last_file_pos = file_pos;
	}
	ck_assert_int_eq(last_file_pos, file_size);

	io_proxy_close(&rio);
	cf_free(buf2);
	cf_free(buf);
}


static void
cmp_consumer_buffers(const consumer_buffer_t* c1, const consumer_buffer_t* c2)
{
	ck_assert_int_eq((int64_t) c1->size, (int64_t) c2->size);
	ck_assert_int_eq((int64_t) c1->pos, (int64_t) c2->pos);
	ck_assert_int_eq((int64_t) c1->data_pos, (int64_t) c2->data_pos);
	ck_assert_mem_eq(c1->src, c2->src, c1->pos);
}

static void
cmp_serialized_io_proxy(const io_proxy_t* deserialized_io, const io_proxy_t* io)
{
	ck_assert_int_eq((int64_t) deserialized_io->byte_cnt, (int64_t) io->byte_cnt);
	ck_assert_int_eq((int64_t) deserialized_io->raw_byte_cnt, (int64_t) io->raw_byte_cnt);
	ck_assert_int_eq(deserialized_io->num, io->num);
	ck_assert_int_eq(deserialized_io->deserialized_flags, io->flags & IO_PROXY_INIT_FLAGS);

	cmp_consumer_buffers(&io->buffer, &deserialized_io->buffer);

	if (io_proxy_do_compress(io)) {
		cmp_consumer_buffers(&io->comp_buffer, &deserialized_io->comp_buffer);
	}

	if (io_proxy_do_encrypt(io)) {
		ck_assert_mem_eq(deserialized_io->ecount_buf, io->ecount_buf, AES_BLOCK_SIZE);
		ck_assert_mem_eq(deserialized_io->iv, io->iv, AES_BLOCK_SIZE);

		cmp_consumer_buffers(&io->encrypt_buffer, &deserialized_io->encrypt_buffer);
	}
}

static void
serialize_and_deserialize(io_proxy_t* io, file_proxy_t* bup, uint32_t init_idx)
{
	ck_assert_int_eq(io_proxy_serialize(io, bup), 0);
	ck_assert_int_eq(file_proxy_flush(bup), 0);

	char* bup_path = safe_strdup(file_proxy_path(bup));
	file_proxy_close2(bup, FILE_PROXY_EOF);
	file_proxy_read_init(bup, bup_path);
	cf_free(bup_path);
	file_proxy_close2(&io->file, FILE_PROXY_CONTINUE);

	io_write_proxy_t* io2 = test_malloc(sizeof(io_write_proxy_t));
	ck_assert_int_eq(io_proxy_deserialize(io2, bup), 0);
	INIT_MATRIX_OPTS(*io2, init_idx);
	io_proxy_initialize(io2);
	cmp_serialized_io_proxy(io2, io);

	// transfer ownership of io2's contents to io, freeing what io had before
	if (io_proxy_do_compress(io)) {
		if (io_proxy_is_writer(io)) {
			ZSTD_freeCCtx(io->cctx);
		}
		else {
			ZSTD_freeDCtx(io->dctx);
		}
		// comp_buffer and decomp_buffer alias each other
		cf_free(io->comp_buffer.src);
	}
	if (io_proxy_do_encrypt(io)) {
		// encrypt_buffer and decrypt_buffer alias each other
		cf_free(io->encrypt_buffer.src);
	}
	cf_free(io->buffer.src);

	memcpy(io, io2, sizeof(io_write_proxy_t));
	cf_free(io2);
}

WRITE_TEST_MATRIX(test_serialize_empty, {
	file_proxy_t fd;
	ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
	ck_assert_int_eq(io_proxy_serialize(&wio, &fd), 0);
	// ensure this wrote at least something to the file
	ck_assert_int_gt(file_proxy_tellg(&fd), 0);
	file_proxy_close2(&fd, FILE_PROXY_EOF);
})

WRITE_TEST_MATRIX(test_deserialize_empty, {
	file_proxy_t fd;
	ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
	serialize_and_deserialize(&wio, &fd, init_idx);
	file_proxy_close2(&fd, FILE_PROXY_EOF);
})

WRITE_TEST_MATRIX(test_serialize_with_data, {
	static const char text[] = "some test text";
	ck_assert_int_eq(io_proxy_write(&wio, text, sizeof(text) - 1), sizeof(text) - 1);

	file_proxy_t fd;
	ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
	serialize_and_deserialize(&wio, &fd, init_idx);
	file_proxy_close2(&fd, FILE_PROXY_EOF);
})

WRITE_TEST_MATRIX(test_serialize_with_data_flushed, {
	static const char text[] = "some test text";
	ck_assert_int_eq(io_proxy_write(&wio, text, sizeof(text) - 1), sizeof(text) - 1);

	file_proxy_t fd;
	ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
	io_proxy_flush(&wio);
	serialize_and_deserialize(&wio, &fd, init_idx);
	file_proxy_close2(&fd, FILE_PROXY_EOF);
})

TEST_MATRIX(test_write_twice, {
	static const char text[] = "some test text";
	static const char text2[] = ", and some more text";

	ck_assert_int_eq(io_proxy_write(&wio, text, sizeof(text) - 1), sizeof(text) - 1);

	file_proxy_t fd;
	ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
	serialize_and_deserialize(&wio, &fd, init_idx);
	file_proxy_close2(&fd, FILE_PROXY_EOF);

	ck_assert_int_eq(io_proxy_write(&wio, text2, sizeof(text2) - 1), sizeof(text2) - 1);
	io_proxy_flush(&wio);
},
{
	static const char combined[] = "some test text, and some more text";
	char buf[sizeof(combined) + 10];
	ck_assert_int_eq(io_proxy_read(&rio, buf, sizeof(buf)), sizeof(combined) - 1);
	buf[sizeof(combined) - 1] = '\0';
	ck_assert_str_eq(buf, combined);
})

const uint64_t write_many_n_chars = 1000000;
static char* write_many_buf;

TEST_MATRIX(test_write_many, {
	as_random r;
	as_random_init(&r);

	write_many_buf = (char*) test_malloc(write_many_n_chars * sizeof(char));

	for (uint64_t i = 0; i < write_many_n_chars; i++) {
		write_many_buf[i] = 'a' + (char) (as_random_next_uint32(&r) % ('z' - 'a' + 1));
	}

	uint64_t pos = 0;
	while (pos < write_many_n_chars) {
		uint64_t to = pos + as_random_next_uint32(&r) % 16384 + 1;
		to = MIN(to, write_many_n_chars);

		ck_assert_int_eq(io_proxy_write(&wio, write_many_buf + pos, to - pos),
				(int64_t) (to - pos));

		// only serialize/deserialize half the time
		if ((as_random_next_uint32(&r) & 1) == 0) {
			file_proxy_t fd;
			ck_assert_int_eq(file_proxy_write_init(&fd, TMP_FILE_2, 0), 0);
			serialize_and_deserialize(&wio, &fd, init_idx);
			file_proxy_close2(&fd, FILE_PROXY_ABORT);
		}

		pos = to;
	}

	io_proxy_flush(&wio);
},
{
	char* buf = (char*) test_malloc(write_many_n_chars * sizeof(char));

	ck_assert_int_eq(io_proxy_read(&rio, buf, write_many_n_chars * sizeof(char)),
			(int64_t) (write_many_n_chars * sizeof(char)));
	ck_assert_mem_eq(buf, write_many_buf, write_many_n_chars);

	cf_free(buf);
	cf_free(write_many_buf);
	write_many_buf = NULL;
})


Suite* io_proxy_suite()
{
	Suite* s;
	TCase* tc_init;
	TCase* tc_rw;
	TCase* tc_cmp;
	TCase* tc_enc;
	TCase* tc_large;
	TCase* tc_pos;
	TCase* tc_serialize;

	s = suite_create("IO Proxy");

	tc_init = tcase_create("Init");
	RUN_TEST_MATRIX(test_init_write, tc_init);
	RUN_TEST_MATRIX(test_init_read, tc_init);
	suite_add_tcase(s, tc_init);

	tc_rw = tcase_create("Read/write");
	tcase_add_checked_fixture(tc_rw, silence_stderr_setup,
			silence_stderr_teardown);
	RUN_TEST_MATRIX(test_rw_putc, tc_rw);
	RUN_TEST_MATRIX(test_rw_getc, tc_rw);
	RUN_TEST_MATRIX(test_rw_getc_unlocked, tc_rw);
	RUN_TEST_MATRIX(test_rw_peekc_unlocked, tc_rw);
	RUN_TEST_MATRIX(test_rw_write, tc_rw);
	RUN_TEST_MATRIX(test_rw_read, tc_rw);
	RUN_TEST_MATRIX(test_rw_gets, tc_rw);
	RUN_TEST_MATRIX(test_rw_printf, tc_rw);
	tcase_add_test(tc_rw, test_rw_putc_with_reader);
	tcase_add_test(tc_rw, test_rw_getc_with_writer);
	tcase_add_test(tc_rw, test_rw_getc_unlocked_with_writer);
	tcase_add_test(tc_rw, test_rw_peekc_unlocked_with_writer);
	tcase_add_test(tc_rw, test_rw_write_with_reader);
	tcase_add_test(tc_rw, test_rw_read_with_writer);
	tcase_add_test(tc_rw, test_rw_gets_with_writer);
	tcase_add_test(tc_rw, test_rw_printf_with_reader);
	tcase_add_test(tc_rw, test_rw_flush_with_reader);
	suite_add_tcase(s, tc_rw);

	tc_cmp = tcase_create("Compression");
	tcase_add_checked_fixture(tc_cmp, silence_stderr_setup,
			silence_stderr_teardown);
	tcase_add_test(tc_cmp, test_cmp_parse_zstd);
	tcase_add_test(tc_cmp, test_cmp_parse_unknown);
	suite_add_tcase(s, tc_cmp);

	tc_enc = tcase_create("Encryption");
	tcase_add_checked_fixture(tc_enc, silence_stderr_setup,
			silence_stderr_teardown);
	tcase_add_test(tc_enc, test_enc_encryption_key_init);
	tcase_add_test(tc_enc, test_enc_no_such_key_file);
	tcase_add_test(tc_enc, test_enc_malformed_key_file);
	tcase_add_test(tc_enc, test_enc_parse_aes128);
	tcase_add_test(tc_enc, test_enc_parse_aes256);
	tcase_add_test(tc_enc, test_enc_parse_unknown);
	tcase_add_test(tc_enc, test_enc_wrong_key_aes128);
	tcase_add_test(tc_enc, test_enc_wrong_key_aes256);
	suite_add_tcase(s, tc_enc);

	tc_large = tcase_create("Large");
	RUN_TEST_MATRIX(test_large_write, tc_large);
	RUN_TEST_MATRIX(test_large_read, tc_large);
	RUN_TEST_MATRIX(test_large_write_putc, tc_large);
	RUN_TEST_MATRIX(test_large_read_getc, tc_large);
	suite_add_tcase(s, tc_large);

	tc_pos = tcase_create("Position");
	tcase_add_test(tc_pos, test_write_file_pos);
	tcase_add_test(tc_pos, test_read_file_pos);
	//tcase_add_test(tc_pos, test_buffered_write_file_pos);
	//tcase_add_test(tc_pos, test_buffered_read_file_pos);
	tcase_add_test(tc_pos, test_read_compressed_data_monotonicity);
	suite_add_tcase(s, tc_pos);

	tc_serialize = tcase_create("Serialize");
	tcase_add_checked_fixture(tc_serialize, silence_stderr_setup,
			silence_stderr_teardown);
	RUN_TEST_MATRIX(test_serialize_empty, tc_serialize);
	RUN_TEST_MATRIX(test_deserialize_empty, tc_serialize);
	RUN_TEST_MATRIX(test_serialize_with_data, tc_serialize);
	RUN_TEST_MATRIX(test_serialize_with_data_flushed, tc_serialize);
	RUN_TEST_MATRIX(test_write_twice, tc_serialize);
	RUN_TEST_MATRIX(test_write_many, tc_serialize);
	suite_add_tcase(s, tc_serialize);

	return s;
}

