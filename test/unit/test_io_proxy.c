
#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include <io_proxy.h>

#include "backup_tests.h"


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


static void 
silence_stderr_setup(void) 
{
	// redirect stderr to /dev/null
	freopen("/dev/null", "w", stderr);
}

static void
silence_stderr_teardown(void)
{
}

/*
 * all different ways an IO proxy can be configured
 */
#define INIT_MATRIX_SIZE (2 * 5)
#define INIT_MATRIX(io, rw_init, file, idx) \
	do { \
		ck_assert_int_eq(rw_init(&io, file), 0); \
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
	} while(0)


#define WRITE_TEST_MATRIX(fn_name, fn_body) \
	START_TEST(fn_name) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 0); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 1); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 2); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128 ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 3); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 4); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256 ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 5); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 6); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 7); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 8); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 9); \
		fn_body \
		io_proxy_free(&wio); \
		fclose(tmp); \
	} \
	END_TEST

#define TEST_MATRIX(fn_name, write_fn_body, read_fn_body) \
	START_TEST(fn_name) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 0); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 0); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 1); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 1); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 2); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 2); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128 ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 3); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 3); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 4); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 4); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256 ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 5); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 5); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 6); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 6); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes128_file ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 7); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 7); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 8); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 8); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
	} \
	END_TEST \
	START_TEST(fn_name ## _aes256_file ## _zstd) { \
		FILE* tmp = tmpfile(); \
		io_write_proxy_t wio; \
		io_read_proxy_t rio; \
		INIT_MATRIX(wio, io_write_proxy_init, tmp, 9); \
		write_fn_body \
		io_proxy_free(&wio); \
		fseek(tmp, 0, SEEK_SET); \
		INIT_MATRIX(rio, io_read_proxy_init, tmp, 9); \
		read_fn_body \
		io_proxy_free(&rio); \
		fclose(tmp); \
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
TEST_MATRIX(test_init_read, {}, {});


#define VA_ARGS(...) , ##__VA_ARGS__

#define DEFINE_WRITE_TO(write_fn, io, file, expected_ret, ...) \
	do { \
		ck_assert_int_eq(write_fn(&io VA_ARGS(__VA_ARGS__)), expected_ret); \
		ck_assert_int_eq(io_proxy_flush(&io), 0); \
	} while (0)

#define DEFINE_READ_FROM(read_fn, io, file, expected_ret, eof_ret, ...) \
	do { \
		ck_assert_int_eq(read_fn(&io VA_ARGS(__VA_ARGS__)), expected_ret); \
		ck_assert_int_eq(read_fn(&io VA_ARGS(__VA_ARGS__)), eof_ret); \
	} while (0)


WRITE_TEST_MATRIX(test_rw_putc, DEFINE_WRITE_TO(io_proxy_putc, wio, tmp, 'a', 'a'););

TEST_MATRIX(test_rw_getc, DEFINE_WRITE_TO(io_proxy_putc, wio, tmp, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_getc, rio, tmp, 'a', EOF););

TEST_MATRIX(test_rw_getc_unlocked, DEFINE_WRITE_TO(io_proxy_putc, wio, tmp, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_getc_unlocked, rio, tmp, 'a', EOF););

TEST_MATRIX(test_rw_peekc_unlocked, DEFINE_WRITE_TO(io_proxy_putc, wio, tmp, 'a', 'a');,
		DEFINE_READ_FROM(io_proxy_peekc_unlocked, rio, tmp, 'a', 'a'););

WRITE_TEST_MATRIX(test_rw_write,
		// write to write proxy
		char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
		DEFINE_WRITE_TO(io_proxy_write, wio, tmp, sizeof(buf) - 1, buf, sizeof(buf) - 1);
		);

TEST_MATRIX(test_rw_read,
		char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
		char buf2[sizeof(buf)];
		// write to write proxy
		DEFINE_WRITE_TO(io_proxy_write, wio, tmp, sizeof(buf) - 1, buf, sizeof(buf) - 1);
		,
		// read from read proxy
		DEFINE_READ_FROM(io_proxy_read, rio, tmp, sizeof(buf) - 1, 0, buf2, sizeof(buf2));
		buf2[sizeof(buf2) - 1] = '\0';
		ck_assert_str_eq(buf, buf2);
		);

TEST_MATRIX(test_rw_gets,
		char buf[] = "abcdefghijklmnopqrstuv\nwxyz1234567890";
		char word1[] = "abcdefghijklmnopqrstuv\n";
		char word2[] = "wxyz1234567890";
		char buf2[sizeof(buf)];
		// write to write proxy
		DEFINE_WRITE_TO(io_proxy_write, wio, tmp, sizeof(buf) - 1, buf, sizeof(buf) - 1);
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
		DEFINE_WRITE_TO(io_proxy_printf, wio, tmp, sizeof(expect) - 1, format,
				"test%s", 42, 3.14);
		,
		// read from read proxy
		DEFINE_READ_FROM(io_proxy_read, rio, tmp, sizeof(expect) - 1, 0, buf, sizeof(buf));
		buf[sizeof(expect) - 1] = '\0';

		ck_assert_str_eq(expect, buf);
		);

START_TEST(test_rw_putc_with_reader)
{
	FILE* tmp = tmpfile();
	io_read_proxy_t rio;
	INIT_MATRIX(rio, io_read_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_putc(&rio, 'a'), 0);
	io_proxy_free(&rio);
	fclose(tmp);
}

START_TEST(test_rw_getc_with_writer)
{
	FILE* tmp = tmpfile();
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_getc(&wio), 0);
	io_proxy_free(&wio);
	fclose(tmp);
}

START_TEST(test_rw_getc_unlocked_with_writer)
{
	FILE* tmp = tmpfile();
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_getc_unlocked(&wio), 0);
	io_proxy_free(&wio);
	fclose(tmp);
}

START_TEST(test_rw_peekc_unlocked_with_writer)
{
	FILE* tmp = tmpfile();
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_peekc_unlocked(&wio), 0);
	io_proxy_free(&wio);
	fclose(tmp);
}

START_TEST(test_rw_write_with_reader)
{
	char buf[] = "123";
	FILE* tmp = tmpfile();
	io_read_proxy_t rio;
	INIT_MATRIX(rio, io_read_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_write(&rio, buf, sizeof(buf) - 1), 0);
	io_proxy_free(&rio);
	fclose(tmp);
}

START_TEST(test_rw_read_with_writer)
{
	char buf[] = "123";
	FILE* tmp = tmpfile();
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	io_proxy_free(&wio);

	fseek(tmp, 0, SEEK_SET);

	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_read(&wio, buf, sizeof(buf) - 1), 0);
	io_proxy_free(&wio);
	fclose(tmp);
}

START_TEST(test_rw_gets_with_writer)
{
	char buf[] = "123";
	FILE* tmp = tmpfile();
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	io_proxy_free(&wio);

	fseek(tmp, 0, SEEK_SET);

	INIT_MATRIX(wio, io_write_proxy_init, tmp, 0);
	ck_assert_ptr_eq(io_proxy_gets(&wio, buf, sizeof(buf) - 1), NULL);
	io_proxy_free(&wio);
	fclose(tmp);
}

START_TEST(test_rw_printf_with_reader)
{
	FILE* tmp = tmpfile();
	io_read_proxy_t rio;
	INIT_MATRIX(rio, io_read_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_printf(&rio, "%s * %d = %c", "test", 2, 'a'), 0);
	io_proxy_free(&rio);
	fclose(tmp);
}

START_TEST(test_rw_flush_with_reader)
{
	FILE* tmp = tmpfile();
	io_read_proxy_t rio;
	INIT_MATRIX(rio, io_read_proxy_init, tmp, 0);
	ck_assert_int_lt(io_proxy_flush(&rio), 0);
	io_proxy_free(&rio);
	fclose(tmp);
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
	uint8_t* buffer = (uint8_t*) cf_malloc(len);

	encryption_key_init(&key, buffer, len);

	ck_assert_ptr_eq(key.data, buffer);
	ck_assert_int_eq((int64_t) key.len, (int64_t) len);

	encryption_key_free(&key);
}
END_TEST

START_TEST(test_enc_no_such_key_file)
{
	io_read_proxy_t io;
	io_read_proxy_init(&io, NULL);
	ck_assert_int_lt(io_proxy_init_encryption_file(&io, "this_file_does_not_exist.pem",
			IO_PROXY_ENCRYPT_AES128), 0);
}
END_TEST

START_TEST(test_enc_malformed_key_file)
{
	io_read_proxy_t io;
	io_read_proxy_init(&io, NULL);
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

	FILE* tmp = tmpfile();
	// encrypt with test_key.pem
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 6);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	io_proxy_free(&wio);

	fseek(tmp, 0, SEEK_SET);

	io_read_proxy_t rio;
	ck_assert_int_eq(io_read_proxy_init(&rio, tmp), 0);
	ck_assert_int_eq(io_proxy_init_encryption_file(&rio, key2_path,
				IO_PROXY_ENCRYPT_AES128), 0);

	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	buf2[sizeof(buf) - 1] = '\0';
	ck_assert_str_ne(buf, buf2);
	io_proxy_free(&rio);
}

START_TEST(test_enc_wrong_key_aes256)
{
	char buf[] = "abcdefghijklmnopqrstuvwxyz1234567890";
	char buf2[sizeof(buf) + 10];

	FILE* tmp = tmpfile();
	// encrypt with test_key.pem
	io_write_proxy_t wio;
	INIT_MATRIX(wio, io_write_proxy_init, tmp, 8);
	ck_assert_int_eq(io_proxy_write(&wio, buf, sizeof(buf) - 1), sizeof(buf) - 1);
	ck_assert_int_eq(io_proxy_flush(&wio), 0);
	io_proxy_free(&wio);

	fseek(tmp, 0, SEEK_SET);

	io_read_proxy_t rio;
	ck_assert_int_eq(io_read_proxy_init(&rio, tmp), 0);
	ck_assert_int_eq(io_proxy_init_encryption_file(&rio, key2_path,
				IO_PROXY_ENCRYPT_AES256), 0);

	ck_assert_int_eq(io_proxy_read(&rio, buf2, sizeof(buf2)), sizeof(buf) - 1);
	buf2[sizeof(buf) - 1] = '\0';
	ck_assert_str_ne(buf, buf2);
	io_proxy_free(&rio);
}

#define SIZE 1048576
WRITE_TEST_MATRIX(test_large_write,
		char* buf = (char*) cf_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		DEFINE_WRITE_TO(io_proxy_write, wio, tmp, SIZE, buf, SIZE);
		cf_free(buf);
		);

TEST_MATRIX(test_large_read,
		char* buf = (char*) cf_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE - 1; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		buf[SIZE - 1] = '\0';
		DEFINE_WRITE_TO(io_proxy_write, wio, tmp, SIZE, buf, SIZE);
		,
		char* buf2 = (char*) cf_malloc(SIZE + 10);
		DEFINE_READ_FROM(io_proxy_read, rio, tmp, SIZE, 0, buf2, SIZE + 10);
		ck_assert_str_eq(buf, buf2);
		cf_free(buf2);
		cf_free(buf);
		);

WRITE_TEST_MATRIX(test_large_write_putc,
		char* buf = (char*) cf_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_putc(&wio, buf[i]), buf[i]);
		cf_free(buf);
		);

TEST_MATRIX(test_large_read_getc,
		char* buf = (char*) cf_malloc(SIZE);
		for (uint64_t i = 0; i < SIZE; i++)
			buf[i] = (char) (' ' + (char) ((31 * i) % ((uint64_t) ('~' - ' '))));
		buf[SIZE - 1] = '\0';
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_putc(&wio, buf[i]), buf[i]);
		ck_assert_int_eq(io_proxy_flush(&wio), 0);
		,
		char* buf2 = (char*) cf_malloc(SIZE + 10);
		for (uint64_t i = 0; i < SIZE; i++)
			ck_assert_int_eq(io_proxy_getc_unlocked(&rio), buf[i]);
		ck_assert_int_eq(io_proxy_getc_unlocked(&rio), EOF);
		cf_free(buf2);
		cf_free(buf);
		);


Suite* io_proxy_suite()
{
	Suite* s;
	TCase* tc_init;
	TCase* tc_rw;
	TCase* tc_cmp;
	TCase* tc_enc;
	TCase* tc_large;

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

	return s;
}

