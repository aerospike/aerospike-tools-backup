
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
#define KEY_FILE "test/test_key.pem"

static int saved_stderr = -1;
static int saved_fd = -1;
static const char* getpass_reply = "";
static int getpass_calls = 0;


char*
getpass(const char* prompt)
{
	static char buf[256];

	(void) prompt;
	getpass_calls++;
	snprintf(buf, sizeof(buf), "%s", getpass_reply);
	return buf;
}

static void
password_setup(void)
{
	unsetenv(PW_ENV);
	unsetenv(PW_ENV_UNSET);
	getpass_reply = "";
	getpass_calls = 0;
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
capture_stdout(void)
{
	fflush(stdout);
	saved_fd = dup(STDOUT_FILENO);
	int fd = open(STDERR_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ck_assert_int_ge(fd, 0);
	dup2(fd, STDOUT_FILENO);
	close(fd);
}

static char*
release_stdout(void)
{
	static char buf[64 * 1024];

	fflush(stdout);
	dup2(saved_fd, STDOUT_FILENO);
	close(saved_fd);
	saved_fd = -1;

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
	ck_assert(resolve_password("--password", &value, 0, false));
	ck_assert_str_eq(value, expected);
	cf_free(value);
}

static void
assert_literal(const char* input)
{
	char* value = strdup(input);
	char* orig = value;
	ck_assert(resolve_password("--password", &value, 0, false));
	ck_assert_ptr_eq(value, orig);
	ck_assert_str_eq(value, input);
	cf_free(value);
}

static char*
assert_fails(const char* opt_name, const char* input)
{
	char* value = strdup(input);
	capture_stderr();
	bool ok = resolve_password(opt_name, &value, 0, false);
	char* output = release_stderr();
	ck_assert(!ok);
	ck_assert_str_eq(value, input);
	cf_free(value);
	return output;
}

static void
assert_keyfile_resolves(const char* input, const char* expected)
{
	char* value = NULL;
	ck_assert(tls_read_password(TLS_KEYFILE_PASSWORD_OPT, input, &value));
	ck_assert_str_eq(value, expected);
	cf_free(value);
}

static char*
assert_keyfile_fails(const char* input)
{
	char* value = NULL;
	capture_stderr();
	bool ok = tls_read_password(TLS_KEYFILE_PASSWORD_OPT, input, &value);
	char* output = release_stderr();
	ck_assert(!ok);
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
	ck_assert(resolve_password("--password", &value, 0, false));
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
	ck_assert_ptr_ne(strstr(out, "--password: password from environment variable "
				PW_ENV " is empty"), NULL);
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
	ck_assert_ptr_ne(strstr(out, "--password: password from b64: value is empty"),
			NULL);

	assert_fails("--password", "b64:Cg==");
}
END_TEST

START_TEST(test_b64_nul)
{
	char* out = assert_fails("--password", "b64:czNjAHJldA==");
	ck_assert_ptr_ne(strstr(out, "--password: b64: value decodes to a value "
				"containing a NUL byte"), NULL);
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
	ck_assert_ptr_ne(strstr(out, "--password: password from file " PW_FILE
				" is empty"), NULL);

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
	ck_assert_ptr_ne(strstr(out, "--password: value from file " PW_FILE
				" is longer than 4999 bytes"), NULL);
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

START_TEST(test_keyfile_sources)
{
	assert_keyfile_resolves("s3cret", "s3cret");
	assert_keyfile_resolves(DEFAULT_PASSWORD, DEFAULT_PASSWORD);
	assert_keyfile_resolves("b64:czNjcmV0", "s3cret");

	setenv(PW_ENV, "s3cret", 1);
	assert_keyfile_resolves("env:" PW_ENV, "s3cret");

	setenv(PW_ENV, "czNjcmV0", 1);
	assert_keyfile_resolves("env-b64:" PW_ENV, "s3cret");

	char* out = assert_keyfile_fails("env:" PW_ENV_UNSET);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
				PW_ENV_UNSET " is not set or empty"), NULL);
}
END_TEST

START_TEST(test_keyfile_file_first_line)
{
	write_file(PW_FILE, "s3cret", 6);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\n", 7);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\n\n", 8);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\r", 7);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\nx", 8);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, "s3cret\r\n\r\n", 10);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	write_file(PW_FILE, " s3cret \n", 9);
	assert_keyfile_resolves("file:" PW_FILE, " s3cret ");
}
END_TEST

START_TEST(test_keyfile_file_nul)
{
	write_file(PW_FILE, "s3c\0ret\nmore\n", 13);
	char* out = assert_keyfile_fails("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: file " PW_FILE
				" contains a NUL byte"), NULL);
	ck_assert_ptr_eq(strstr(out, "s3c"), NULL);
}
END_TEST

START_TEST(test_file_dev_zero)
{
	char* out = assert_fails("--password", "file:/dev/zero");
	ck_assert_ptr_ne(strstr(out, "--password: file /dev/zero contains a NUL byte"),
			NULL);

	out = assert_keyfile_fails("file:/dev/zero");
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: file /dev/zero contains "
				"a NUL byte"), NULL);
}
END_TEST

static char*
assert_too_long(const char* input)
{
	char* value = strdup(input);
	capture_stderr();
	bool ok = resolve_password("--password", &value, 63, false);
	char* output = release_stderr();
	ck_assert(!ok);
	ck_assert_str_eq(value, input);
	cf_free(value);
	return output;
}

START_TEST(test_max_len)
{
	char longest[64];
	char too_long[65];
	char* value;

	memset(longest, 'x', 63);
	longest[63] = '\0';
	memset(too_long, 'x', 64);
	too_long[64] = '\0';

	setenv(PW_ENV, longest, 1);
	value = strdup("env:" PW_ENV);
	ck_assert(resolve_password("--password", &value, 63, false));
	ck_assert_str_eq(value, longest);
	cf_free(value);

	setenv(PW_ENV, too_long, 1);
	char* out = assert_too_long("env:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "--password: value from environment variable "
				PW_ENV " is longer than 63 bytes"), NULL);
	ck_assert_ptr_eq(strstr(out, too_long), NULL);

	write_file(PW_FILE, too_long, 64);
	out = assert_too_long("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--password: value from file " PW_FILE
				" is longer than 63 bytes"), NULL);

	char big[200];
	memset(big, 'x', sizeof(big));
	write_file(PW_FILE, big, sizeof(big));
	out = assert_too_long("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--password: value from file " PW_FILE
				" is longer than 63 bytes"), NULL);

	// 64 bytes of 'x'
	out = assert_too_long("b64:eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
			"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==");
	ck_assert_ptr_ne(strstr(out, "--password: decoded b64: value is longer than "
				"63 bytes"), NULL);

	setenv(PW_ENV, "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
			"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==", 1);
	out = assert_too_long("env-b64:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "--password: decoded value from environment "
				"variable " PW_ENV " is longer than 63 bytes"), NULL);

	out = assert_too_long(too_long);
	ck_assert_ptr_ne(strstr(out, "--password: password is longer than 63 bytes"),
			NULL);
	ck_assert_ptr_eq(strstr(out, too_long), NULL);

	value = strdup(longest);
	ck_assert(resolve_password("--password", &value, 63, false));
	ck_assert_str_eq(value, longest);
	cf_free(value);
}
END_TEST

START_TEST(test_empty_name)
{
	char* out = assert_fails("--password", "env:");
	ck_assert_ptr_ne(strstr(out, "--password: env: requires a variable name"),
			NULL);

	out = assert_fails("--password", "env-b64:");
	ck_assert_ptr_ne(strstr(out, "--password: env-b64: requires a variable name"),
			NULL);

	out = assert_fails("--password", "file:");
	ck_assert_ptr_ne(strstr(out, "--password: file: requires a path"), NULL);

	out = assert_keyfile_fails("env:");
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: env: requires a "
				"variable name"), NULL);
}
END_TEST

START_TEST(test_keyfile_max_len)
{
	char longest[TLS_KEYFILE_PASSWORD_MAX_LEN + 1];
	char too_long[TLS_KEYFILE_PASSWORD_MAX_LEN + 2];

	memset(longest, 'k', TLS_KEYFILE_PASSWORD_MAX_LEN);
	longest[TLS_KEYFILE_PASSWORD_MAX_LEN] = '\0';
	memset(too_long, 'k', TLS_KEYFILE_PASSWORD_MAX_LEN + 1);
	too_long[TLS_KEYFILE_PASSWORD_MAX_LEN + 1] = '\0';

	assert_keyfile_resolves(longest, longest);

	char* out = assert_keyfile_fails(too_long);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: password is longer "
				"than 1024 bytes"), NULL);

	setenv(PW_ENV, longest, 1);
	assert_keyfile_resolves("env:" PW_ENV, longest);

	setenv(PW_ENV, too_long, 1);
	out = assert_keyfile_fails("env:" PW_ENV);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: value from environment "
				"variable " PW_ENV " is longer than 1024 bytes"), NULL);
}
END_TEST

START_TEST(test_keyfile_file_empty_first_line)
{
	write_file(PW_FILE, "\ns3cret", 7);
	char* out = assert_keyfile_fails("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: password from first "
				"line of file " PW_FILE " is empty"), NULL);
	ck_assert_ptr_eq(strstr(out, "s3cret"), NULL);

	write_file(PW_FILE, "", 0);
	out = assert_keyfile_fails("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: password from file "
				PW_FILE " is empty"), NULL);

	write_file(PW_FILE, "\r\nx", 3);
	assert_keyfile_fails("file:" PW_FILE);

	out = assert_keyfile_fails("file:" WORKING_DIR "/does_not_exist");
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: cannot read file "
				WORKING_DIR "/does_not_exist"), NULL);
}
END_TEST

START_TEST(test_keyfile_file_large)
{
	size_t len = 64 * 1024 + 16;
	char* data = test_malloc(len);

	memset(data, 'a', len);
	memcpy(data, "s3cret\n", 7);
	write_file(PW_FILE, data, len);
	assert_keyfile_resolves("file:" PW_FILE, "s3cret");

	memset(data, 'a', len);
	data[1024] = '\n';
	write_file(PW_FILE, data, len);
	data[1024] = '\0';
	assert_keyfile_resolves("file:" PW_FILE, data);

	memset(data, 'a', len);
	data[1025] = '\n';
	write_file(PW_FILE, data, len);
	cf_free(data);

	char* out = assert_keyfile_fails("file:" PW_FILE);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: value from file "
				PW_FILE " is longer than 1024 bytes"), NULL);
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
		ARGV("asbackup", "--no-config-file", "-U", "user", "-P", "env:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert(!conf.password_from_secret_agent);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-U", "user",
				"--password=env:" PW_ENV);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-Penv:" PW_ENV, "-U", "user");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
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

	ARGV("asbackup", "--no-config-file", "-U", "user", "-P", "env:" PW_ENV_UNSET);
	capture_stderr();
	int res = backup_config_set(argc, argv, &conf);
	char* out = release_stderr();
	ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
	ck_assert_ptr_ne(strstr(out, "--password: environment variable "
				PW_ENV_UNSET), NULL);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_cli_password_too_long)
{
	char too_long[65];
	memset(too_long, 'x', 64);
	too_long[64] = '\0';
	setenv(PW_ENV, too_long, 1);

	{
		backup_config_t conf;
		ARGV("asbackup", "--no-config-file", "-U", "user", "-P", "env:" PW_ENV);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: value from environment "
					"variable " PW_ENV " is longer than 63 bytes"), NULL);
		backup_config_destroy(&conf);
	}

	{
		restore_config_t conf;
		ARGV("asrestore", "--no-config-file", "-U", "user", "-P", "env:" PW_ENV);
		capture_stderr();
		int res = restore_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: value from environment "
					"variable " PW_ENV " is longer than 63 bytes"), NULL);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_unused_passwords)
{
	backup_config_t conf;

	{
		ARGV("asbackup", "--no-config-file", "-P", "env:" PW_ENV_UNSET,
				"--tls-keyfile-password", "env:" PW_ENV_UNSET);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, 0);
		ck_assert_ptr_ne(strstr(out, "Warning: --password: ignored because no user "
					"is set"),
				NULL);
		ck_assert_str_eq(conf.password, "env:" PW_ENV_UNSET);
		ck_assert_str_eq(conf.tls.keyfile_pw, "env:" PW_ENV_UNSET);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-P", "literal");
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, 0);
		ck_assert_ptr_eq(strstr(out, "ignored because no user is set"), NULL);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-U", "user", "-A", "PKI", "-P",
				"env:" PW_ENV_UNSET);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, 0);
		ck_assert_ptr_eq(strstr(out, "--password"), NULL);
		ck_assert_str_eq(conf.password, "env:" PW_ENV_UNSET);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "-U", "user", "-P",
				"env:" PW_ENV_UNSET, "--remove-artifacts");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "env:" PW_ENV_UNSET);
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
		"user = \"user\"\n"
		"password = \"file:" PW_FILE "\"\n"
		"tls-keyfile-password = \"env-b64:" PW_ENV "\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	backup_config_t conf;
	backup_config_init(&conf);
	ck_assert(config_from_file(&conf, NULL, CONF_FILE, 0, true));
	ck_assert_str_eq(conf.password, "file:" PW_FILE);
	ck_assert(!conf.password_from_secret_agent);
	ck_assert_str_eq(conf.tls.keyfile_pw, "env-b64:" PW_ENV);
	backup_config_destroy(&conf);

	ARGV("asbackup", "--only-config-file", CONF_FILE);
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.password, "file pass");
	ck_assert_str_eq(conf.tls.keyfile_pw, "env-b64:" PW_ENV);
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
		ARGV("asbackup", "--only-config-file", CONF_FILE, "-U", "user",
				"-P", "literal", "--tls-keyfile-password=b64:czNjcmV0");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "literal");
		ck_assert_str_eq(conf.tls.keyfile_pw, "b64:czNjcmV0");
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "-P", "--only-config-file", CONF_FILE, "-U", "user",
				"--tls-keyfile-password");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);
		ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--only-config-file", CONF_FILE, "-U", "user");
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "password in config file: environment "
					"variable " PW_ENV_UNSET " is not set or empty"), NULL);
		ck_assert_ptr_eq(strstr(out, "--password"), NULL);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--only-config-file", CONF_FILE, "-U", "user", "-P",
				"env:" PW_ENV_UNSET);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: environment variable "
					PW_ENV_UNSET " is not set or empty"), NULL);
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_cli_literal_too_long)
{
	char too_long[65];
	memset(too_long, 'x', 64);
	too_long[64] = '\0';

	{
		backup_config_t conf;
		ARGV("asbackup", "--no-config-file", "-U", "user", "-P", too_long);
		capture_stderr();
		int res = backup_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: password is longer than 63 "
					"bytes"), NULL);
		ck_assert_ptr_eq(strstr(out, too_long), NULL);
		backup_config_destroy(&conf);
	}

	{
		restore_config_t conf;
		ARGV("asrestore", "--no-config-file", "-U", "user", "-P", too_long);
		capture_stderr();
		int res = restore_config_set(argc, argv, &conf);
		char* out = release_stderr();
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
		ck_assert_ptr_ne(strstr(out, "--password: password is longer than 63 "
					"bytes"), NULL);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_instance_config_file)
{
	setenv(PW_ENV, "instance pass", 1);

	const char contents[] =
		"[cluster]\n"
		"user = \"default-user\"\n"
		"password = \"env:" PW_ENV_UNSET "\"\n"
		"[cluster_x]\n"
		"user = \"x-user\"\n"
		"password = \"env:" PW_ENV "\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	backup_config_t conf;
	ARGV("asbackup", "--only-config-file", CONF_FILE, "--instance", "x");
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.user, "x-user");
	ck_assert_str_eq(conf.password, "instance pass");
	ck_assert(conf.password_from_config_file);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_cli_env)
{
	setenv(PW_ENV, "s3cret", 1);
	restore_config_t conf;

	{
		ARGV("asrestore", "--no-config-file", "-U", "user", "-P", "env:" PW_ENV);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert(!conf.password_from_secret_agent);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--no-config-file", "-U", "user",
				"--password=b64:czNjcmV0", "--tls-keyfile-password", "env:" PW_ENV);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert_str_eq(conf.tls.keyfile_pw, "env:" PW_ENV);
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

	ARGV("asrestore", "--no-config-file", "-U", "user", "-P", "b64:not-base64");
	capture_stderr();
	int res = restore_config_set(argc, argv, &conf);
	char* out = release_stderr();
	ck_assert_int_eq(res, RESTORE_CONFIG_INIT_FAILURE);
	ck_assert_ptr_ne(strstr(out, "--password: invalid base64 in b64: value"),
			NULL);
	ck_assert_ptr_eq(strstr(out, "not-base64"), NULL);
	restore_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_unused_passwords)
{
	restore_config_t conf;

	{
		ARGV("asrestore", "--no-config-file", "-P", "b64:not-base64",
				"--tls-keyfile-password=env:" PW_ENV_UNSET);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "b64:not-base64");
		ck_assert_str_eq(conf.tls.keyfile_pw, "env:" PW_ENV_UNSET);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--no-config-file", "--validate", "-U", "user", "-P",
				"env:" PW_ENV_UNSET, "--tls-keyfile", KEY_FILE,
				"--tls-keyfile-password", "env:" PW_ENV_UNSET);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "env:" PW_ENV_UNSET);

		restore_status_t status;
		ck_assert(restore_status_init(&status, &conf));
		restore_status_destroy(&status);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_restore_config_file)
{
	setenv(PW_ENV, "s3cret", 1);

	const char contents[] =
		"[cluster]\n"
		"user = \"user\"\n"
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
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert_str_eq(conf.password, "s3cret");
		ck_assert_str_eq(conf.tls.keyfile_pw, "env:" PW_ENV_UNSET);
		restore_config_destroy(&conf);
	}
}
END_TEST

static char*
backup_status_init_fails(backup_config_t* conf)
{
	backup_status_t status;
	capture_stderr();
	bool ok = backup_status_init(&status, conf);
	char* output = release_stderr();
	ck_assert(!ok);
	cf_free(status.policy);
	return output;
}

static char*
restore_status_init_fails(restore_config_t* conf)
{
	restore_status_t status;
	capture_stderr();
	bool ok = restore_status_init(&status, conf);
	char* output = release_stderr();
	ck_assert(!ok);
	return output;
}

START_TEST(test_backup_keyfile_pw_at_connect)
{
	write_file(PW_FILE, "\ns3cret\n", 8);
	backup_config_t conf;

	ARGV("asbackup", "--no-config-file", "--tls-keyfile", KEY_FILE,
			"--tls-keyfile-password", "file:" PW_FILE);
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.tls.keyfile_pw, "file:" PW_FILE);

	char* out = backup_status_init_fails(&conf);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: password from first "
				"line of file " PW_FILE " is empty"), NULL);
	ck_assert_int_eq(getpass_calls, 0);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_backup_prompted_keyfile_pw)
{
	backup_config_t conf;

	ARGV("asbackup", "--no-config-file", "--tls-keyfile", KEY_FILE,
			"--tls-keyfile-password");
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);

	getpass_reply = "env:" PW_ENV_UNSET;
	char* out = backup_status_init_fails(&conf);
	ck_assert_int_eq(getpass_calls, 1);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
				PW_ENV_UNSET " is not set or empty"), NULL);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_keyfile_pw_at_connect)
{
	restore_config_t conf;

	ARGV("asrestore", "--no-config-file", "--tls-keyfile", KEY_FILE,
			"--tls-keyfile-password", "env:" PW_ENV_UNSET);
	ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.tls.keyfile_pw, "env:" PW_ENV_UNSET);

	char* out = restore_status_init_fails(&conf);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment variable "
				PW_ENV_UNSET " is not set or empty"), NULL);
	ck_assert_int_eq(getpass_calls, 0);
	restore_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_prompted_keyfile_pw)
{
	restore_config_t conf;

	ARGV("asrestore", "--no-config-file", "--tls-keyfile", KEY_FILE,
			"--tls-keyfile-password");
	ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.tls.keyfile_pw, DEFAULT_PASSWORD);

	getpass_reply = "file:" WORKING_DIR "/does_not_exist";
	char* out = restore_status_init_fails(&conf);
	ck_assert_int_eq(getpass_calls, 1);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: cannot read file "
				WORKING_DIR "/does_not_exist"), NULL);
	restore_config_destroy(&conf);
}
END_TEST

START_TEST(test_backup_keyfile_pw_from_secret_agent)
{
	backup_config_t conf;

	ARGV("asbackup", "--no-config-file", "-h", "127.0.0.1", "-p", "1",
			"--tls-keyfile", KEY_FILE, "--tls-keyfile-password",
			"env:" PW_ENV_UNSET);
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert(!conf.tls_keyfile_pw_from_secret_agent);
	conf.tls_keyfile_pw_from_secret_agent = true;

	char* out = backup_status_init_fails(&conf);
	ck_assert_ptr_eq(strstr(out, "--tls-keyfile-password:"), NULL);
	ck_assert_ptr_ne(strstr(out, "Error while connecting"), NULL);
	ck_assert_int_eq(getpass_calls, 0);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_keyfile_pw_from_secret_agent)
{
	restore_config_t conf;

	ARGV("asrestore", "--no-config-file", "-h", "127.0.0.1", "-p", "1",
			"--tls-keyfile", KEY_FILE, "--tls-keyfile-password",
			"file:" WORKING_DIR "/does_not_exist");
	ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
	ck_assert(!conf.tls_keyfile_pw_from_secret_agent);
	conf.tls_keyfile_pw_from_secret_agent = true;

	char* out = restore_status_init_fails(&conf);
	ck_assert_ptr_eq(strstr(out, "--tls-keyfile-password:"), NULL);
	ck_assert_ptr_ne(strstr(out, "Error while connecting"), NULL);
	ck_assert_int_eq(getpass_calls, 0);
	restore_config_destroy(&conf);
}
END_TEST

START_TEST(test_backup_typed_password_is_literal)
{
	backup_config_t conf;

	ARGV("asbackup", "--no-config-file", "-h", "127.0.0.1", "-p", "1",
			"-U", "user", "-P");
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	ck_assert_str_eq(conf.password, DEFAULT_PASSWORD);

	getpass_reply = "env:" PW_ENV_UNSET;
	char* out = backup_status_init_fails(&conf);
	ck_assert_int_eq(getpass_calls, 1);
	ck_assert_ptr_eq(strstr(out, "--password:"), NULL);
	ck_assert_ptr_ne(strstr(out, "Error while connecting"), NULL);
	backup_config_destroy(&conf);
}
END_TEST

START_TEST(test_restore_typed_password_too_long)
{
	char too_long[65];
	memset(too_long, 'x', 64);
	too_long[64] = '\0';

	restore_config_t conf;

	ARGV("asrestore", "--no-config-file", "-h", "127.0.0.1", "-p", "1",
			"-U", "user", "-P");
	ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);

	getpass_reply = too_long;
	char* out = restore_status_init_fails(&conf);
	ck_assert_int_eq(getpass_calls, 1);
	ck_assert_ptr_ne(strstr(out, "--password: password is longer than 63 bytes"),
			NULL);
	ck_assert_ptr_eq(strstr(out, too_long), NULL);
	restore_config_destroy(&conf);
}
END_TEST

START_TEST(test_backup_keystring_keyfile_pw)
{
	backup_config_t conf;

	{
		ARGV("asbackup", "--no-config-file", "--tls-keyfile-password",
				"env:" PW_ENV_UNSET);
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		conf.tls.keystring = cf_strdup("key fetched with secrets:");

		char* out = backup_status_init_fails(&conf);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment "
					"variable " PW_ENV_UNSET " is not set or empty"), NULL);
		backup_config_destroy(&conf);
	}

	{
		ARGV("asbackup", "--no-config-file", "--tls-keyfile-password");
		ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
		conf.tls.keystring = cf_strdup("key fetched with secrets:");

		getpass_reply = "env:" PW_ENV_UNSET;
		char* out = backup_status_init_fails(&conf);
		ck_assert_int_eq(getpass_calls, 1);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: environment "
					"variable " PW_ENV_UNSET), NULL);
		backup_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_restore_keyfile_pw_config_file_label)
{
	const char contents[] =
		"[cluster]\n"
		"tls-keyfile = \"" KEY_FILE "\"\n"
		"tls-keyfile-password = \"env:" PW_ENV_UNSET "\"\n";
	write_file(CONF_FILE, contents, sizeof(contents) - 1);

	restore_config_t conf;

	{
		ARGV("asrestore", "--only-config-file", CONF_FILE);
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert(conf.tls_keyfile_pw_from_config_file);

		char* out = restore_status_init_fails(&conf);
		ck_assert_ptr_ne(strstr(out, "tls-keyfile-password in config file: "
					"environment variable " PW_ENV_UNSET), NULL);
		ck_assert_ptr_eq(strstr(out, "--tls-keyfile-password"), NULL);
		restore_config_destroy(&conf);
	}

	{
		ARGV("asrestore", "--only-config-file", CONF_FILE,
				"--tls-keyfile-password", "file:");
		ck_assert_int_eq(restore_config_set(argc, argv, &conf), 0);
		ck_assert(!conf.tls_keyfile_pw_from_config_file);

		char* out = restore_status_init_fails(&conf);
		ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: file: requires a "
					"path"), NULL);
		restore_config_destroy(&conf);
	}
}
END_TEST

START_TEST(test_backup_secret_agent_keyfile_pw_too_long)
{
	char too_long[TLS_KEYFILE_PASSWORD_MAX_LEN + 2];
	memset(too_long, 'k', TLS_KEYFILE_PASSWORD_MAX_LEN + 1);
	too_long[TLS_KEYFILE_PASSWORD_MAX_LEN + 1] = '\0';

	backup_config_t conf;

	ARGV("asbackup", "--no-config-file", "--tls-keyfile", KEY_FILE,
			"--tls-keyfile-password", too_long);
	ck_assert_int_eq(backup_config_set(argc, argv, &conf), 0);
	conf.tls_keyfile_pw_from_secret_agent = true;

	char* out = backup_status_init_fails(&conf);
	ck_assert_ptr_ne(strstr(out, "--tls-keyfile-password: password is longer "
				"than 1024 bytes"), NULL);
	backup_config_destroy(&conf);
}
END_TEST

static void
assert_help(const char* out)
{
	ck_assert_ptr_ne(strstr(out,
				"1) Environment variable: 'env:<VAR>', used exactly as set\n"), NULL);
	ck_assert_ptr_ne(strstr(out,
				"4) File: 'file:<PATH>', the whole file less one trailing '\\n' or\n"),
			NULL);
	ck_assert_ptr_ne(strstr(out,
				"'file:' must be given as 'b64:' or typed at the prompt.\n"), NULL);
	ck_assert_ptr_ne(strstr(out, "not PKI. It must be at most 63 bytes.\n"), NULL);
	ck_assert_ptr_ne(strstr(out,
				"4) File: 'file:<PATH>', the first line of the file\n"), NULL);
	ck_assert_ptr_ne(strstr(out, "most 1024 bytes.\n"
				"                      Default: none\n"
				"                      A value fetched with 'secrets:' is used as-is.\n"
				"                      User will be prompted"), NULL);
	ck_assert_ptr_eq(strstr(out, "4999"), NULL);
}

START_TEST(test_help_text)
{
	{
		backup_config_t conf;
		ARGV("asbackup", "--help");
		capture_stdout();
		int res = backup_config_set(argc, argv, &conf);
		assert_help(release_stdout());
		ck_assert_int_eq(res, BACKUP_CONFIG_INIT_EXIT);
	}

	{
		restore_config_t conf;
		ARGV("asrestore", "--help");
		capture_stdout();
		int res = restore_config_set(argc, argv, &conf);
		assert_help(release_stdout());
		ck_assert_int_eq(res, RESTORE_CONFIG_INIT_EXIT);
	}
}
END_TEST

#undef ARGV


Suite* password_suite()
{
	Suite* s;
	TCase* tc_resolve;
	TCase* tc_config;
	TCase* tc_connect;

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
	tcase_add_test(tc_resolve, test_keyfile_sources);
	tcase_add_test(tc_resolve, test_keyfile_file_first_line);
	tcase_add_test(tc_resolve, test_keyfile_file_empty_first_line);
	tcase_add_test(tc_resolve, test_keyfile_file_large);
	tcase_add_test(tc_resolve, test_keyfile_file_nul);
	tcase_add_test(tc_resolve, test_file_dev_zero);
	tcase_add_test(tc_resolve, test_max_len);
	tcase_add_test(tc_resolve, test_empty_name);
	tcase_add_test(tc_resolve, test_keyfile_max_len);
	suite_add_tcase(s, tc_resolve);

	tc_config = tcase_create("Config");
	tcase_add_checked_fixture(tc_config, password_setup, password_teardown);
	tcase_add_test(tc_config, test_backup_cli_env);
	tcase_add_test(tc_config, test_backup_cli_prompt);
	tcase_add_test(tc_config, test_backup_cli_errors);
	tcase_add_test(tc_config, test_cli_password_too_long);
	tcase_add_test(tc_config, test_backup_unused_passwords);
	tcase_add_test(tc_config, test_backup_config_file);
	tcase_add_test(tc_config, test_backup_cli_overrides_config_file);
	tcase_add_test(tc_config, test_restore_cli_env);
	tcase_add_test(tc_config, test_restore_cli_errors);
	tcase_add_test(tc_config, test_restore_unused_passwords);
	tcase_add_test(tc_config, test_restore_config_file);
	tcase_add_test(tc_config, test_cli_literal_too_long);
	tcase_add_test(tc_config, test_backup_instance_config_file);
	tcase_add_test(tc_config, test_help_text);
	suite_add_tcase(s, tc_config);

	tc_connect = tcase_create("Connect");
	tcase_add_checked_fixture(tc_connect, password_setup, password_teardown);
	tcase_add_test(tc_connect, test_backup_keyfile_pw_at_connect);
	tcase_add_test(tc_connect, test_backup_prompted_keyfile_pw);
	tcase_add_test(tc_connect, test_restore_keyfile_pw_at_connect);
	tcase_add_test(tc_connect, test_restore_prompted_keyfile_pw);
	tcase_add_test(tc_connect, test_backup_keyfile_pw_from_secret_agent);
	tcase_add_test(tc_connect, test_restore_keyfile_pw_from_secret_agent);
	tcase_add_test(tc_connect, test_backup_typed_password_is_literal);
	tcase_add_test(tc_connect, test_restore_typed_password_too_long);
	tcase_add_test(tc_connect, test_backup_keystring_keyfile_pw);
	tcase_add_test(tc_connect, test_restore_keyfile_pw_config_file_label);
	tcase_add_test(tc_connect, test_backup_secret_agent_keyfile_pw_too_long);
	suite_add_tcase(s, tc_connect);

	return s;
}
