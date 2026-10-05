
#include <check.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <backup.h>
#include <conf.h>
#include <restore.h>

#include "backup_tests.h"


#define WORKING_DIR "test/unit"
#define PW_FILE WORKING_DIR "/tmp_password_file"
#define CONF_FILE WORKING_DIR "/tmp_password.conf"
#define STDERR_FILE WORKING_DIR "/tmp_password_stderr"
#define PW_ENV "ASB_UT_PASSWORD"
#define PW_ENV_UNSET "ASB_UT_PASSWORD_UNSET"

static int saved_stderr = -1;


static void
password_setup(void)
{
	unsetenv(PW_ENV);
	unsetenv(PW_ENV_UNSET);
}

static void
password_teardown(void)
{
	unsetenv(PW_ENV);
	remove(PW_FILE);
	remove(CONF_FILE);
	remove(STDERR_FILE);
}

static void
write_file(const char* path, const char* data, size_t len)
{
	FILE* f = fopen(path, "wb");
	ck_assert(f != NULL);
	ck_assert_uint_eq(fwrite(data, 1, len, f), len);
	fclose(f);
}

static void
capture_stderr(void)
{
	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	int fd = open(STDERR_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ck_assert_int_ge(fd, 0);
	dup2(fd, STDERR_FILENO);
	close(fd);
}

static char*
release_stderr(void)
{
	static char buf[4096];

	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);
	saved_stderr = -1;

	FILE* f = fopen(STDERR_FILE, "rb");
	ck_assert(f != NULL);
	size_t len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[len] = '\0';
	return buf;
}

static void
assert_resolves(const char* input, const char* expected)
{
	char* value = strdup(input);
	ck_assert(resolve_password("--password", &value));
	ck_assert_str_eq(value, expected);
	cf_free(value);
}

static void
assert_literal(const char* input)
{
	char* value = strdup(input);
	char* orig = value;
	ck_assert(resolve_password("--password", &value));
	ck_assert_ptr_eq(value, orig);
	ck_assert_str_eq(value, input);
	cf_free(value);
}

static char*
assert_fails(const char* opt_name, const char* input)
{
	char* value = strdup(input);
	capture_stderr();
	bool ok = resolve_password(opt_name, &value);
	char* output = release_stderr();
	ck_assert(!ok);
	ck_assert_str_eq(value, input);
	cf_free(value);
	return output;
}


START_TEST(test_literal)
{
	assert_literal("s3cret");
	assert_literal("");
	assert_literal("env");
	assert_literal("ENV:" PW_ENV);
	assert_literal("Env:" PW_ENV);
	assert_literal("FILE:/nonexistent");
	assert_literal("B64:czNjcmV0");
	assert_literal("env-B64:" PW_ENV);
	assert_literal(" env:" PW_ENV);
	assert_literal("secrets:resource:name");
	assert_literal(DEFAULT_PASSWORD);
}
END_TEST

START_TEST(test_null)
{
	char* value = NULL;
	ck_assert(resolve_password("--password", &value));
	ck_assert_ptr_eq(value, NULL);
}
END_TEST

START_TEST(test_env)
{
	setenv(PW_ENV, "s3cret", 1);
	assert_resolves("env:" PW_ENV, "s3cret");

	setenv(PW_ENV, "s3cret\n", 1);
	assert_resolves("env:" PW_ENV, "s3cret\n");
}
END_TEST

START_TEST(test_env_unset)
{
	char* out = assert_fails("--password", "env:" PW_ENV_UNSET);
	ck_assert_ptr_ne(strstr(out, "--password: environment variable " PW_ENV_UNSET
				" is not set or empty\n"), NULL);
}
END_TEST

START_TEST(test_env_empty)
{
	setenv(PW_ENV, "", 1);
	char* out = assert_fails("--password", "env:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "environment variable " PW_ENV
				" is not set or empty"), NULL);
}
END_TEST

START_TEST(test_env_b64)
{
	setenv(PW_ENV, "czNjcmV0", 1);
	assert_resolves("env-b64:" PW_ENV, "s3cret");

	setenv(PW_ENV, "czNjcmV0Cg==", 1);
	assert_resolves("env-b64:" PW_ENV, "s3cret");

	setenv(PW_ENV, "czNjcmV0Cg==\n", 1);
	assert_resolves("env-b64:" PW_ENV, "s3cret");
}
END_TEST

START_TEST(test_env_b64_unset)
{
	char* out = assert_fails("--tls-keyfile-password", "env-b64:" PW_ENV_UNSET);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
				PW_ENV_UNSET " is not set or empty"), NULL);

	setenv(PW_ENV, "", 1);
	assert_fails("--password", "env-b64:" PW_ENV);
}
END_TEST

START_TEST(test_env_b64_invalid)
{
	setenv(PW_ENV, "czNjcmV0!!!!", 1);
	char* out = assert_fails("--tls-keyfile-password", "env-b64:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: invalid base64 in "
				"environment variable " PW_ENV), NULL);
	ck_assert_ptr_eq(strstr(out, "czNjcmV0"), NULL);
}
END_TEST

START_TEST(test_env_b64_empty)
{
	setenv(PW_ENV, "Cg==", 1);
	char* out = assert_fails("--password", "env-b64:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "--password: empty password from "
				"environment variable " PW_ENV), NULL);
}
END_TEST

START_TEST(test_b64)
{
	assert_resolves("b64:czNjcmV0", "s3cret");
	assert_resolves("b64:czNjcmV0Cg==", "s3cret");
	assert_resolves("b64:czNjcmV0Cgo=", "s3cret\n");
	assert_resolves("b64:czNj\r\ncmV0", "s3cret");
	assert_resolves("b64:c3BhY2UgcGFzcw==", "space pass");
}
END_TEST

START_TEST(test_b64_invalid)
{
	char* out = assert_fails("--password", "b64:czNjcmV0!");
	ck_assert_ptr_ne(strstr(out, "--password: invalid base64 in b64: value"), NULL);
	ck_assert_ptr_eq(strstr(out, "czNjcmV0"), NULL);

	out = assert_fails("--password", "b64:czNjcmV");
	ck_assert_ptr_ne(strstr(out, "--password: invalid base64 in b64: value"), NULL);
	ck_assert_ptr_eq(strstr(out, "czNjcmV"), NULL);

	assert_fails("--password", "b64:czNjcmV0===");
	assert_fails("--password", "b64:====");
}
END_TEST

START_TEST(test_b64_empty)
{
	char* out = assert_fails("--password", "b64:");
	ck_assert_ptr_ne(strstr(out, "--password: empty password from b64: value"), NULL);

	assert_fails("--password", "b64:Cg==");
}
END_TEST

START_TEST(test_b64_nul)
{
	char* out = assert_fails("--password", "b64:czNjAHJldA==");
	ck_assert_ptr_ne(strstr(out, "--password: password from b64: value contains "
				"a NUL byte"), NULL);
}
END_TEST

START_TEST(test_file)
{
	write_file(PW_FILE, "s3cret\n", 7);
	assert_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\r\n", 8);
	assert_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret", 6);
	assert_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\n\n", 8);
	assert_resolves("file:" PW_FILE, "s3cret\n");

	write_file(PW_FILE, "line one\nline two\n", 18);
	assert_resolves("file:" PW_FILE, "line one\nline two");

	write_file(PW_FILE, " s3cret \n", 9);
	assert_resolves("file:" PW_FILE, " s3cret ");
}
END_TEST

START_TEST(test_file_missing)
{
	char* out = assert_fails("--password", "file:" WORKING_DIR "/does_not_exist");
	ck_assert_ptr_ne(strstr(out, "--password: cannot read file " WORKING_DIR
				"/does_not_exist: No such file or directory"), NULL);
}
END_TEST

START_TEST(test_file_directory)
{
	char* out = assert_fails("--password", "file:" WORKING_DIR);
	ck_assert_ptr_ne(strstr(out, "--password: cannot read file " WORKING_DIR), NULL);
}
END_TEST

START_TEST(test_file_empty)
{
	write_file(PW_FILE, "", 0);
	char* out = assert_fails("--password", "file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--password: empty password from file " PW_FILE),
			NULL);

	write_file(PW_FILE, "\n", 1);
	assert_fails("--password", "file:" PW_FILE);

	write_file(PW_FILE, "\r\n", 2);
	assert_fails("--password", "file:" PW_FILE);
}
END_TEST

START_TEST(test_file_nul)
{
	write_file(PW_FILE, "s3c\0ret\n", 8);
	char* out = assert_fails("--password", "file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "contains a NUL byte"), NULL);
	ck_assert_ptr_eq(strstr(out, "s3c"), NULL);
}
END_TEST

START_TEST(test_file_too_large)
{
	size_t len = 64 * 1024 + 1;
	char* data = test_malloc(len);
	memset(data, 'a', len);
	write_file(PW_FILE, data, len);
	cf_free(data);

	char* out = assert_fails("--password", "file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--password: file " PW_FILE " is larger than"),
			NULL);
}
END_TEST

START_TEST(test_resolved_not_reparsed)
{
	setenv(PW_ENV, "file:" WORKING_DIR "/does_not_exist", 1);
	assert_resolves("env:" PW_ENV, "file:" WORKING_DIR "/does_not_exist");

	write_file(PW_FILE, "env:" PW_ENV_UNSET "\n", strlen("env:" PW_ENV_UNSET "\n"));
	assert_resolves("file:" PW_FILE, "env:" PW_ENV_UNSET);

	// "env:ASB_UT_PASSWORD_UNSET"
	assert_resolves("b64:ZW52OkFTQl9VVF9QQVNTV09SRF9VTlNFVA==",
			"env:" PW_ENV_UNSET);

	// "b64:czNjcmV0"
	setenv(PW_ENV, "YjY0OmN6TmpjbVYw", 1);
	assert_resolves("env-b64:" PW_ENV, "b64:czNjcmV0");
}
END_TEST


#define ARGV(...) \
	char* argv[] = { __VA_ARGS__ }; \
	int argc = (int) (sizeof(argv) / sizeof(argv[0]))

START_TEST(test_backup_cli_env)
{
	setenv(PW_ENV, "s3cret", 1);
	backup_config_t conf;

	{
		ARGV("asbackup", "--no-config-file", "-P", "env:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert(!conf.password_is_secret);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "--password=env:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-Penv:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "--tls-keyfile-password",
				"env:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.tls.keyfile_pw, "s3cret");
		ck_assert(!conf.tls_keyfile_pw_is_secret);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "--tls-keyfile-password=b64:czNjcmV0");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.tls.keyfile_pw, "s3cret");
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_cli_prompt)
{
	backup_config_t conf;

	{
		ARGV("asbackup", "--no-config-file", "-U", "user", "-P");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-P", "-U", "user",
				"--tls-keyfile-password");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);
		ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);
		ck_assert_str_eq(conf.user, "user");
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_cli_errors)
{
	backup_config_t conf;

	{
		ARGV("asbackup", "--no-config-file", "-P", "env:" PW_ENV_UNSET);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: environment variable "
					PW_ENV_UNSET), NULL);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "--tls-keyfile-password",
				"file:" WORKING_DIR "/does_not_exist");
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: cannot read file "
					WORKING_DIR "/does_not_exist"), NULL);
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_config_file)
{
	setenv(PW_ENV, "czNjcmV0", 1);
	write_file(PW_FILE, "file pass\n", 10);

	const char contents[] =
		"[cluster]\n"
		"password = \"file:" PW_FILE "\"\n"
		"tls-keyfile-password = \"env-b64:" PW_ENV "\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	backup_config_t conf;
	backup_config_init(&conf);
	ck_assert(config_from_file(&conf, NULL, CONF_FILE, 0, true));
	ck_assert_str_eq(conf.password, "file:" PW_FILE);
	ck_assert(!conf.password_is_secret);
	ck_assert_str_eq(conf.tls.keyfile_pw, "env-b64:" PW_ENV);
	ck_assert(!conf.tls_keyfile_pw_is_secret);
	backup_config_destroy(&conf);

	ARGV("asbackup", "--only-config-file", CONF_FILE);
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.password, "file pass");
	ck_assert_str_eq(conf.tls.keyfile_pw, "s3cret");
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_backup_cli_overrides_config_file)
{
	const char contents[] =
		"[cluster]\n"
		"password = \"env:" PW_ENV_UNSET "\"\n"
		"tls-keyfile-password = \"file:" WORKING_DIR "/does_not_exist\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	backup_config_t conf;

	{
		ARGV("asbackup", "--only-config-file", CONF_FILE, "-P", "literal",
				"--tls-keyfile-password=b64:czNjcmV0");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "literal");
		ck_assert_str_eq(conf.tls.keyfile_pw, "s3cret");
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "-P", "--only-config-file", CONF_FILE,
				"--tls-keyfile-password");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);
		ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--only-config-file", CONF_FILE, "-P", "literal");
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: cannot read file"),
				NULL);
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_restore_cli_env)
{
	setenv(PW_ENV, "s3cret", 1);
	restore_config_t conf;

	{
		ARGV("asrestore", "--no-config-file", "-P", "env:" PW_ENV);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert(!conf.password_is_secret);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--no-config-file", "--password=b64:czNjcmV0",
				"--tls-keyfile-password", "env:" PW_ENV);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert_str_eq(conf.tls.keyfile_pw, "s3cret");
		ck_assert(!conf.tls_keyfile_pw_is_secret);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--no-config-file", "-U", "user", "-P",
				"--tls-keyfile-password");
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);
		ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_restore_cli_errors)
{
	restore_config_t conf;

	{
		ARGV("asrestore", "--no-config-file", "-P", "b64:not-base64");
		capture_stderr();
		int res = restore_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: invalid base64 in b64: value"),
				NULL);
		ck_assert_ptr_eq(strstr(out, "not-base64"), NULL);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--no-config-file", "--tls-keyfile-password=env:"
				PW_ENV_UNSET);
		capture_stderr();
		int res = restore_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
					PW_ENV_UNSET " is not set or empty"), NULL);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_restore_config_file)
{
	setenv(PW_ENV, "s3cret", 1);

	const char contents[] =
		"[cluster]\n"
		"password = \"env:" PW_ENV "\"\n"
		"tls-keyfile-password = \"env:" PW_ENV_UNSET "\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	restore_config_t conf;

	{
		ARGV("asrestore", "--only-config-file", CONF_FILE,
				"--tls-keyfile-password", "literal");
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert_str_eq(conf.tls.keyfile_pw, "literal");
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--only-config-file", CONF_FILE);
		capture_stderr();
		int res = restore_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
					PW_ENV_UNSET), NULL);
		restore_config_destroy(&conf);
	}
}
END_TEST

#undef ARGV


Suite* password_suite()
{
	Suite* s;
	TCase* tc_resolve;
	TCase* tc_config;

	s = suite_create("Password sources");

	tc_resolve = tcase_create("Resolve");
	tcase_add_checked_fixture(tc_resolve, password_setup, password_teardown);
	tcase_add_test(tc_resolve, test_literal);
	tcase_add_test(tc_resolve, test_null);
	tcase_add_test(tc_resolve, test_env);
	tcase_add_test(tc_resolve, test_env_unset);
	tcase_add_test(tc_resolve, test_env_empty);
	tcase_add_test(tc_resolve, test_env_b64);
	tcase_add_test(tc_resolve, test_env_b64_unset);
	tcase_add_test(tc_resolve, test_env_b64_invalid);
	tcase_add_test(tc_resolve, test_env_b64_empty);
	tcase_add_test(tc_resolve, test_b64);
	tcase_add_test(tc_resolve, test_b64_invalid);
	tcase_add_test(tc_resolve, test_b64_empty);
	tcase_add_test(tc_resolve, test_b64_nul);
	tcase_add_test(tc_resolve, test_file);
	tcase_add_test(tc_resolve, test_file_missing);
	tcase_add_test(tc_resolve, test_file_directory);
	tcase_add_test(tc_resolve, test_file_empty);
	tcase_add_test(tc_resolve, test_file_nul);
	tcase_add_test(tc_resolve, test_file_too_large);
	tcase_add_test(tc_resolve, test_resolved_not_reparsed);
	suite_add_tcase(s, tc_resolve);

	tc_config = tcase_create("Config");
	tcase_add_checked_fixture(tc_config, password_setup, password_teardown);
	tcase_add_test(tc_config, test_backup_cli_env);
	tcase_add_test(tc_config, test_backup_cli_prompt);
	tcase_add_test(tc_config, test_backup_cli_errors);
	tcase_add_test(tc_config, test_backup_config_file);
	tcase_add_test(tc_config, test_backup_cli_overrides_config_file);
	tcase_add_test(tc_config, test_restore_cli_env);
	tcase_add_test(tc_config, test_restore_cli_errors);
	tcase_add_test(tc_config, test_restore_config_file);
	suite_add_tcase(s, tc_config);

	return s;
}

