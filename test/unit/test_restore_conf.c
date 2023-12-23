
#include <check.h>
#include <stdlib.h>
#include <unistd.h>

#include <conf.h>
#include <restore.h>

#include "backup_tests.h"


#define WORKING_DIR "test/unit"
#define TMP_FILE_NAME "tmp_file.conf"

// initialized to all 0's
static char file_name[128] = { '\0' };


static void
tmp_file_setup(void)
{}

static void
tmp_file_init(const char* cluster_args, const char* backup_args,
		const char* asadm_args, const char* secret_agent_args)
{
	snprintf(file_name, sizeof(file_name), WORKING_DIR "/" TMP_FILE_NAME);
	FILE* f = fopen(file_name, "w+");
	ck_assert(f != NULL);

	char *file_contents_buf;
	const char file_contents[] =
		"[cluster]\n"
		"%s\n"
		"[asrestore]\n"
		"%s\n"
		"[asadmin]\n"
		"%s\n"
		"[secret-agent]\n"
		"%s\n";
	// add 1 to include the null terminator
	size_t n_bytes = (size_t) snprintf(NULL, 0, file_contents, cluster_args,
			backup_args, asadm_args, secret_agent_args) + 1;
	file_contents_buf = test_malloc(n_bytes);
	snprintf(file_contents_buf, n_bytes, file_contents, cluster_args,
			backup_args, asadm_args, secret_agent_args);
	fwrite(file_contents_buf, 1, n_bytes, f);
	cf_free(file_contents_buf);
	fclose(f);
}

static void
tmp_file_teardown(void)
{
	if (file_name[0] != '\0') {
		ck_assert_int_eq(remove(file_name), 0);
		file_name[0] = '\0';
	}
}

#define CMP_INT_FIELD(f1, f2) \
	ck_assert_int_eq((f1), (f2))

#define CMP_PTR_FIELD(f1, f2) \
	ck_assert_ptr_eq((f1), (f2))

#define CMP_STR_FIELD(f1, f2) \
	if ((f1) != NULL || (f2) != NULL) { \
		ck_assert_str_eq((f1), (f2)); \
	}

#define CMP_BLB_FIELD(f1, f2, len) \
	if ((f1) != NULL || (f2) != NULL) { \
		ck_assert_mem_eq((f1), (f2), (len)); \
	}

#define CMP_STR_VEC_FIELD(f1, f2) \
	ck_assert_int_eq((f1)->size, (f2)->size); \
	for (uint32_t i = 0; i < (f1)->size; i++) { \
		ck_assert_str_eq((char*) as_vector_get((f1), i), \
				(char*) as_vector_get((f2), i)); \
	}

static void
assert_restore_config_eq(restore_config_t *c1, restore_config_t *c2)
{
	CMP_STR_FIELD(c1->host, c2->host);
	CMP_INT_FIELD(c1->port, c2->port);
	CMP_INT_FIELD(c1->use_services_alternate, c2->use_services_alternate);
	CMP_STR_FIELD(c1->user, c2->user);
	CMP_STR_FIELD(c1->password, c2->password);
	CMP_STR_FIELD(c1->auth_mode, c2->auth_mode);

	CMP_INT_FIELD(c1->tls.enable, c2->tls.enable);
	CMP_STR_FIELD(c1->tls.cafile, c2->tls.cafile);
	CMP_STR_FIELD(c1->tls.capath, c2->tls.capath);
	CMP_STR_FIELD(c1->tls.protocols, c2->tls.protocols);
	CMP_STR_FIELD(c1->tls.cipher_suite, c2->tls.cipher_suite);
	CMP_STR_FIELD(c1->tls.keyfile, c2->tls.keyfile);
	CMP_STR_FIELD(c1->tls.keyfile_pw, c2->tls.keyfile_pw);
	CMP_STR_FIELD(c1->tls.certfile, c2->tls.certfile);
	CMP_INT_FIELD(c1->tls.crl_check, c2->tls.crl_check);
	CMP_INT_FIELD(c1->tls.crl_check_all, c2->tls.crl_check_all);
	CMP_INT_FIELD(c1->tls.log_session_info, c2->tls.log_session_info);
	CMP_INT_FIELD(c1->tls.for_login_only, c2->tls.for_login_only);

	CMP_INT_FIELD(c1->parallel, c2->parallel);
	CMP_STR_FIELD(c1->nice_list, c2->nice_list);
	CMP_INT_FIELD(c1->no_records, c2->no_records);
	CMP_INT_FIELD(c1->no_indexes, c2->no_indexes);
	CMP_INT_FIELD(c1->indexes_last, c2->indexes_last);
	CMP_INT_FIELD(c1->no_udfs, c2->no_udfs);
	CMP_INT_FIELD(c1->wait, c2->wait);
	CMP_INT_FIELD(c1->timeout, c2->timeout);

	CMP_STR_FIELD(c1->ns_list, c2->ns_list);
	CMP_STR_FIELD(c1->set_list, c2->set_list);
	CMP_STR_FIELD(c1->bin_list, c2->bin_list);

	CMP_STR_FIELD(c1->directory, c2->directory);
	CMP_STR_FIELD(c1->directory_list, c2->directory_list);
	CMP_STR_FIELD(c1->parent_directory, c2->parent_directory);
	CMP_STR_FIELD(c1->input_file, c2->input_file);
	CMP_STR_FIELD(c1->machine, c2->machine);
	CMP_INT_FIELD(c1->compress_mode, c2->compress_mode);
	CMP_INT_FIELD(c1->encrypt_mode, c2->encrypt_mode);

	if (c1->pkey != NULL || c2->pkey != NULL) {
		ck_assert(c1->pkey != NULL && c2->pkey != NULL);

		CMP_INT_FIELD((int64_t) c1->pkey->len, (int64_t) c2->pkey->len);
		CMP_BLB_FIELD(c1->pkey->data, c2->pkey->data, c1->pkey->len);
	}

	CMP_INT_FIELD(c1->unique, c2->unique);
	CMP_INT_FIELD(c1->replace, c2->replace);
	CMP_INT_FIELD(c1->ignore_rec_error, c2->ignore_rec_error);
	CMP_INT_FIELD(c1->no_generation, c2->no_generation);
	CMP_INT_FIELD(c1->extra_ttl, c2->extra_ttl);
	CMP_INT_FIELD((int64_t) c1->bandwidth, (int64_t) c2->bandwidth);
	CMP_INT_FIELD(c1->tps, c2->tps);

	CMP_STR_FIELD(c1->s3_region, c2->s3_region);
	CMP_STR_FIELD(c1->s3_profile, c2->s3_profile);
	CMP_STR_FIELD(c1->s3_endpoint_override, c2->s3_endpoint_override);
	CMP_INT_FIELD(c1->s3_max_async_downloads, c2->s3_max_async_downloads);
	CMP_INT_FIELD(c1->s3_connect_timeout, c2->s3_connect_timeout);
	CMP_INT_FIELD(c1->s3_log_level, c2->s3_log_level);

	CMP_STR_FIELD(c1->secret_cfg.addr, c2->secret_cfg.addr);
	CMP_STR_FIELD(c1->secret_cfg.port, c2->secret_cfg.port);
	CMP_INT_FIELD(c1->secret_cfg.timeout, c2->secret_cfg.timeout);
	CMP_STR_FIELD(c1->secret_cfg.tls.ca_string, c2->secret_cfg.tls.ca_string);
	CMP_INT_FIELD(c1->secret_cfg.tls.enabled, c2->secret_cfg.tls.enabled);
}


START_TEST(test_init_empty)
{
	tmp_file_init("", "", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

#define DEFINE_BOOL_TEST(test_name, str_name, field_name) \
START_TEST(test_name) \
{ \
	tmp_file_init(str_name "=true\n", "", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	c2.field_name = true; \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

/*
 * some fields are scaled in parsing, so call this directly to scale the field
 * by mult before comparing to the parsed restore_config
 */
#define DEFINE_INT_TEST_MULT(test_name, str_name, field_name, mult) \
START_TEST(test_name) \
{ \
	tmp_file_init(str_name "=314159\n", "", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	c2.field_name = 314159lu * (mult); \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

#define DEFINE_INT_TEST(test_name, str_name, field_name) \
	DEFINE_INT_TEST_MULT(test_name, str_name, field_name, 1)

#define DEFINE_STR_TEST(test_name, str_name, field_name, str_val) \
START_TEST(test_name) \
{ \
	tmp_file_init(str_name "=\"" str_val "\"\n", "", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	cf_free(c2.field_name); \
	c2.field_name = strdup(str_val); \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST


DEFINE_STR_TEST(test_init_host, "host", host, "localhost:3000");
DEFINE_INT_TEST(test_init_port, "port", port);
DEFINE_BOOL_TEST(test_init_services_alternate, "use-services-alternate", use_services_alternate);
DEFINE_STR_TEST(test_init_user, "user", user, "claytdog");
DEFINE_STR_TEST(test_init_passwd, "password", password, "this is a bad password");
DEFINE_STR_TEST(test_init_auth_mode, "auth", auth_mode, "none");

DEFINE_BOOL_TEST(test_init_tls_enable, "tls-enable", tls.enable);
DEFINE_STR_TEST(test_init_tls_protocols, "tls-protocols", tls.protocols, "TLSv1.2");
DEFINE_STR_TEST(test_init_tls_cipher_suite, "tls-cipher-suite", tls.cipher_suite, "NULL-MD5");
DEFINE_BOOL_TEST(test_init_tls_crl_check, "tls-crl-check", tls.crl_check);
DEFINE_BOOL_TEST(test_init_tls_crl_check_all, "tls-crl-check-all", tls.crl_check_all);
DEFINE_STR_TEST(test_init_tls_keyfile, "tls-keyfile", tls.keyfile, "test_key.pem");
DEFINE_STR_TEST(test_init_tls_keyfile_pw, "tls-keyfile-password", tls.keyfile_pw, "test_key_pw.pem");
DEFINE_STR_TEST(test_init_tls_cafile, "tls-cafile", tls.cafile, "cafile.ca");
DEFINE_STR_TEST(test_init_tls_capath, "tls-capath", tls.capath, "/opt/aerospike");
DEFINE_STR_TEST(test_init_tls_certfile, "tls-certfile", tls.certfile, "certfile.pem");
DEFINE_STR_TEST(test_init_tls_cert_blacklist, "tls-cert-blacklist", tls.cert_blacklist,
		"blacklist.txt");

#undef DEFINE_BOOL_TEST
#undef DEFINE_INT_TEST_MULT
#undef DEFINE_INT_TEST
#undef DEFINE_STR_TEST


START_TEST(test_init_set_list)
{
	tmp_file_init("", "set-list=\"set-1,set-2,set-3\"", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.set_list = strdup("set-1,set-2,set-3");

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_bin_list)
{
	tmp_file_init("", "bin-list=\"bin-1,bin-2,bin-3\"", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.bin_list = strdup("bin-1,bin-2,bin-3");

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_ns_list)
{
	tmp_file_init("", "namespace=\"test\"", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.ns_list = strdup("test");

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_s3_log_level)
{
	tmp_file_init("", "s3-log-level=\"Debug\"\n", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.s3_log_level = Debug;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_compress_mode)
{
	tmp_file_init("", "compress=\"zstd\"\n", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.compress_mode = IO_PROXY_COMPRESS_ZSTD;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_encryption_mode)
{
	tmp_file_init("", "encrypt=\"aes128\"\n", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.encrypt_mode = IO_PROXY_ENCRYPT_AES128;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_encrypt_key_file)
{
	// decoding of test/test_key.pem
	static uint8_t data[] = {
		0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02,
		0x82, 0x01, 0x01, 0x00, 0xbc, 0x51, 0x9d, 0x1d,
		0x06, 0xae, 0x46, 0x18, 0xc3, 0x95, 0xe0, 0xd8,
		0xff, 0x49, 0x40, 0x56, 0x2e, 0xce, 0x7e, 0x9c,
		0xee, 0x51, 0x4a, 0x44, 0x6d, 0xa4, 0x19, 0x21,
		0x0f, 0x7a, 0xea, 0xab, 0x36, 0x9d, 0x70, 0x98,
		0x08, 0x06, 0x19, 0xc2, 0x73, 0xbb, 0x56, 0x44,
		0x78, 0xa2, 0x85, 0x0a, 0xa1, 0xf9, 0xac, 0xe2,
		0xb8, 0x06, 0xbf, 0xbc, 0x26, 0x67, 0x3c, 0xd7,
		0x60, 0x65, 0xea, 0x42, 0xe8, 0x62, 0x11, 0xc1,
		0x9d, 0xf8, 0x37, 0x94, 0x9d, 0xab, 0x2a, 0xeb,
		0xe7, 0x20, 0xa9, 0x69, 0x54, 0x1a, 0xa6, 0x30,
		0x23, 0xae, 0xe2, 0x58, 0x88, 0xf3, 0x25, 0x35,
		0x8e, 0xa0, 0xc0, 0xbb, 0x8c, 0x26, 0xe9, 0x84,
		0x1b, 0x23, 0x1c, 0xb6, 0xff, 0x72, 0x42, 0x78,
		0xa6, 0x23, 0x49, 0x53, 0x15, 0x47, 0xff, 0xd1,
		0x4f, 0x75, 0x8a, 0x10, 0x2c, 0x2a, 0x39, 0x27,
		0x78, 0x13, 0xbd, 0xa7, 0xb9, 0x21, 0x9c, 0x2b,
		0x7b, 0x30, 0x7c, 0xf2, 0xe7, 0x3d, 0x25, 0x46,
		0x05, 0xb9, 0x70, 0xd6, 0xc1, 0x3b, 0xb4, 0xc9,
		0x3c, 0xf3, 0x66, 0xeb, 0x5e, 0x2c, 0xc4, 0xc6,
		0xd4, 0x06, 0xfa, 0x64, 0xc4, 0xd1, 0xeb, 0x06,
		0xf8, 0xc7, 0x8b, 0xd4, 0xe3, 0x22, 0x5f, 0x4f,
		0x28, 0x9c, 0xb4, 0x94, 0x5c, 0x3b, 0xa6, 0x9d,
		0x89, 0xd5, 0xcf, 0x3a, 0xb1, 0x2a, 0x6c, 0x59,
		0x3f, 0x03, 0x33, 0x9e, 0x83, 0x31, 0xd2, 0x54,
		0x4b, 0xcf, 0x47, 0x0c, 0x1b, 0x7d, 0xb1, 0xd8,
		0x23, 0x4f, 0x02, 0xc9, 0x85, 0xc9, 0xdd, 0x13,
		0xbd, 0x85, 0x3a, 0xef, 0xe8, 0xc7, 0x4f, 0xaa,
		0xd2, 0x3e, 0x8f, 0x3e, 0xae, 0x3c, 0x54, 0x65,
		0x8a, 0x51, 0xc2, 0x22, 0x54, 0x3d, 0x70, 0x98,
		0xda, 0xa4, 0xd2, 0xc9, 0x16, 0x71, 0x89, 0x7f,
		0x3b, 0xfa, 0x82, 0xe4, 0xc8, 0x0a, 0x46, 0xb1,
		0x51, 0x39, 0xe1, 0x4f, 0x02, 0x03, 0x01, 0x00,
		0x01, 0x02, 0x82, 0x01, 0x00, 0x2e, 0xd5, 0xb1,
		0x58, 0x65, 0xaf, 0xf3, 0xf8, 0xf6, 0xb3, 0x90,
		0xbf, 0x07, 0x06, 0x85, 0xbc, 0xa9, 0x59, 0x6b,
		0xbd, 0xc5, 0xbb, 0x6b, 0xd8, 0x06, 0xd8, 0x97,
		0xf3, 0x53, 0xf1, 0x42, 0xe9, 0x9f, 0xe4, 0x99,
		0xfb, 0x05, 0x8b, 0xd6, 0xde, 0x38, 0x80, 0x2f,
		0xdd, 0x49, 0x8f, 0x49, 0xbd, 0x32, 0x39, 0x71,
		0x18, 0xd5, 0xa1, 0xc0, 0x0f, 0xa0, 0x11, 0x6e,
		0xdd, 0x35, 0xb9, 0x43, 0x00, 0xae, 0xe0, 0xac,
		0xff, 0xd5, 0x34, 0xc5, 0x45, 0xed, 0xcc, 0x83,
		0x19, 0x36, 0x5b, 0x36, 0x26, 0xde, 0xe6, 0xdd,
		0xcb, 0xfd, 0x23, 0xe2, 0x61, 0x18, 0x76, 0x38,
		0x1b, 0xd0, 0xc4, 0x04, 0x0a, 0xe0, 0xb9, 0x50,
		0xbc, 0x2d, 0x2f, 0x97, 0x55, 0x9f, 0xc4, 0x1f,
		0xe9, 0xf7, 0x8f, 0xb1, 0x0d, 0xbb, 0xae, 0x33,
		0x5e, 0x2f, 0xff, 0xd0, 0x7d, 0x63, 0x2e, 0x81,
		0x16, 0x62, 0xd3, 0xae, 0x07, 0xda, 0x54, 0x23,
		0x23, 0x6e, 0xff, 0xc7, 0x9b, 0x8f, 0x46, 0xf9,
		0x0f, 0x33, 0x4c, 0xa3, 0x8a, 0x3a, 0x8c, 0x95,
		0x30, 0x3f, 0xd1, 0x75, 0x40, 0xd1, 0xa3, 0xbd,
		0x51, 0x63, 0x24, 0x10, 0x01, 0xf9, 0x8b, 0x05,
		0x2c, 0x94, 0x08, 0x44, 0xfb, 0x43, 0x09, 0x79,
		0xb1, 0x59, 0x03, 0xbd, 0x38, 0x36, 0x8f, 0xbd,
		0xf1, 0x5a, 0xdc, 0x4a, 0x1c, 0x67, 0xcc, 0x47,
		0xc4, 0x32, 0xab, 0x40, 0xb6, 0x97, 0x42, 0xa5,
		0xc0, 0x35, 0xf4, 0xd7, 0xaf, 0xe5, 0x3b, 0x19,
		0x0e, 0xf8, 0x6f, 0x38, 0x3c, 0xf0, 0xe3, 0x16,
		0x1d, 0x1d, 0xf1, 0x01, 0x94, 0xf4, 0x4e, 0xed,
		0x25, 0x57, 0xc0, 0x2e, 0x0d, 0x07, 0x16, 0x59,
		0xcb, 0x6a, 0x1c, 0x82, 0x5c, 0x07, 0x54, 0xdd,
		0xeb, 0x77, 0xa8, 0x1f, 0x6b, 0x72, 0x1f, 0x17,
		0x83, 0xae, 0x1a, 0xcd, 0x77, 0xcb, 0xa3, 0xbe,
		0x8c, 0x0c, 0xbd, 0x97, 0x71, 0x02, 0x81, 0x81,
		0x00, 0xdf, 0xd6, 0x86, 0xa2, 0x84, 0xf8, 0x53,
		0x9d, 0x11, 0x45, 0xe1, 0x95, 0xb1, 0x17, 0xf8,
		0xf3, 0x74, 0x5f, 0xe1, 0xbd, 0x80, 0x8e, 0x49,
		0xba, 0x0e, 0x2d, 0xbd, 0x43, 0x0d, 0xa2, 0x97,
		0x42, 0xdc, 0x19, 0x37, 0x39, 0x3c, 0x6e, 0xac,
		0x2e, 0x30, 0x36, 0x75, 0x7d, 0x6e, 0x6f, 0x3a,
		0x75, 0x8c, 0x1b, 0x18, 0xfc, 0xfd, 0xad, 0xa6,
		0x03, 0xc1, 0x8e, 0xb7, 0x8e, 0x63, 0xc9, 0x40,
		0xe6, 0xd1, 0x1c, 0x15, 0x81, 0xcb, 0x7f, 0x03,
		0x01, 0x5d, 0x82, 0xc5, 0x1b, 0xb1, 0x81, 0x72,
		0x06, 0x33, 0xc0, 0x3a, 0x72, 0x1f, 0x8d, 0x36,
		0xe5, 0xd3, 0xcc, 0x27, 0x30, 0x04, 0xc3, 0x00,
		0x14, 0xb1, 0xf2, 0xa4, 0x65, 0x27, 0x6a, 0x7e,
		0xe7, 0x4d, 0x06, 0xf5, 0x08, 0x3d, 0x9e, 0x26,
		0x7f, 0x68, 0xf6, 0x5e, 0x38, 0xbd, 0xb4, 0xe1,
		0x7e, 0x63, 0xe5, 0xf6, 0x2c, 0xb2, 0xa6, 0xd6,
		0xb9, 0x02, 0x81, 0x81, 0x00, 0xd7, 0x60, 0x94,
		0x36, 0xec, 0xb6, 0xae, 0xf1, 0xed, 0xbc, 0xb4,
		0x91, 0x8e, 0x52, 0xbb, 0xf6, 0x3d, 0xa8, 0x63,
		0xc8, 0xa3, 0x40, 0xe4, 0xcd, 0x4f, 0x9c, 0x48,
		0x89, 0xa0, 0x54, 0x08, 0xd1, 0xd0, 0x24, 0x13,
		0x8a, 0x7e, 0x36, 0xf6, 0x8e, 0xff, 0x5e, 0x7f,
		0x14, 0xac, 0x42, 0xa5, 0x4c, 0x59, 0x7b, 0x27,
		0xf1, 0x1b, 0xf0, 0x8b, 0x76, 0xa4, 0x95, 0x52,
		0x0d, 0xce, 0x67, 0x1d, 0x2c, 0xb5, 0x99, 0x73,
		0xb5, 0xf7, 0x96, 0x76, 0xb3, 0x11, 0xde, 0x5d,
		0xa6, 0x22, 0x33, 0x14, 0xe6, 0x2b, 0xd2, 0xc5,
		0xc3, 0x76, 0xb3, 0x5e, 0xc6, 0xbf, 0xfe, 0xc3,
		0x73, 0x8c, 0x42, 0xd8, 0xa2, 0xbc, 0x1a, 0xee,
		0x60, 0x2a, 0x7c, 0xa3, 0xbd, 0x0d, 0x22, 0xc4,
		0x5f, 0xfa, 0x1f, 0xf5, 0x90, 0xb9, 0xad, 0x37,
		0x33, 0x3e, 0x3a, 0xa4, 0x84, 0x23, 0x37, 0xed,
		0xd2, 0x5c, 0xac, 0xf4, 0x47, 0x02, 0x81, 0x80,
		0x5f, 0xdb, 0x9d, 0x38, 0xc8, 0x3d, 0x18, 0x81,
		0xb1, 0x3d, 0xfe, 0x07, 0x7f, 0x19, 0xc7, 0x11,
		0x6b, 0x8b, 0x0c, 0x3f, 0x7d, 0x68, 0x72, 0x06,
		0x6d, 0xc0, 0x04, 0xc7, 0x4c, 0x75, 0x8e, 0xd5,
		0xa1, 0x30, 0x63, 0x47, 0xed, 0xab, 0x6f, 0xad,
		0x30, 0x14, 0x82, 0x68, 0x3e, 0xfc, 0xff, 0x4a,
		0x0b, 0xc0, 0x27, 0x09, 0x61, 0x12, 0x16, 0x80,
		0x91, 0x49, 0xaf, 0x2e, 0x19, 0x69, 0xbc, 0x93,
		0x9c, 0x85, 0xac, 0x68, 0x33, 0x5f, 0xa7, 0x47,
		0xd4, 0x66, 0x06, 0x47, 0x7f, 0xd2, 0xf1, 0xa3,
		0xda, 0x51, 0xbe, 0x35, 0xd5, 0x71, 0x42, 0x4b,
		0x56, 0x52, 0x9d, 0x8d, 0xa0, 0xdc, 0x69, 0x92,
		0x73, 0x4a, 0x78, 0x40, 0xa1, 0x8a, 0xa7, 0xe2,
		0x22, 0x48, 0x92, 0x72, 0xff, 0x00, 0x55, 0x78,
		0x46, 0xd9, 0x0b, 0x2c, 0xbd, 0x81, 0x52, 0xf8,
		0x2f, 0x8b, 0xf1, 0xca, 0xde, 0x8f, 0x38, 0x71,
		0x02, 0x81, 0x80, 0x5d, 0x94, 0xfd, 0x51, 0x90,
		0x31, 0x20, 0x7a, 0xc6, 0x4d, 0xc4, 0x37, 0xaa,
		0x9b, 0x90, 0x48, 0x42, 0x2a, 0x34, 0x91, 0x2d,
		0x3e, 0x39, 0x2c, 0x6c, 0x76, 0xff, 0x9d, 0xad,
		0x28, 0x56, 0x5c, 0xb4, 0x0f, 0xb8, 0xdd, 0xe8,
		0x51, 0x81, 0x78, 0x48, 0xc5, 0x8a, 0x7a, 0x35,
		0x0f, 0x10, 0x3b, 0xc8, 0x75, 0x96, 0xb9, 0x50,
		0xe6, 0x87, 0xf2, 0x99, 0x38, 0xb8, 0x5a, 0x7f,
		0x60, 0x96, 0x70, 0xa2, 0xc7, 0x76, 0x5b, 0x8e,
		0xa4, 0xb6, 0x16, 0xc0, 0xa0, 0xda, 0x18, 0x21,
		0xac, 0x08, 0x5c, 0xaa, 0x95, 0xfe, 0x90, 0x1b,
		0xb7, 0x7c, 0x6a, 0xe7, 0x69, 0x8f, 0x0b, 0x59,
		0xda, 0x81, 0xbe, 0xd3, 0xf4, 0xef, 0xb6, 0xa1,
		0x3f, 0x5e, 0xf5, 0xfa, 0x0b, 0x2d, 0x40, 0x76,
		0xb2, 0x04, 0x45, 0x4a, 0x28, 0x55, 0x5f, 0xd2,
		0x9e, 0x30, 0x75, 0xa9, 0xc7, 0xd7, 0x72, 0x1c,
		0x0a, 0x9a, 0x69, 0x02, 0x81, 0x80, 0x3b, 0x30,
		0xb7, 0x15, 0x84, 0x5b, 0xdc, 0x2d, 0xd1, 0x84,
		0x03, 0x1d, 0x74, 0xf4, 0x37, 0x91, 0x9d, 0x95,
		0x5a, 0x4f, 0x57, 0x60, 0xec, 0x1e, 0xf4, 0xa0,
		0xd9, 0xb5, 0xd8, 0xc6, 0xbe, 0x6c, 0xa1, 0x04,
		0x7b, 0x91, 0x96, 0x4c, 0x36, 0xfa, 0x75, 0xf8,
		0x1a, 0xad, 0x77, 0x18, 0x29, 0xf6, 0xba, 0x05,
		0x8d, 0xaf, 0x22, 0x0f, 0xce, 0xaf, 0xb6, 0xba,
		0xaa, 0x20, 0x9d, 0xbf, 0x59, 0xfa, 0x67, 0x54,
		0x4f, 0x07, 0x34, 0x0c, 0x1a, 0x08, 0x59, 0xa2,
		0x89, 0x6d, 0xfe, 0xc2, 0x47, 0x1a, 0xda, 0x0f,
		0x62, 0x8e, 0xca, 0x6d, 0x23, 0x53, 0x79, 0xe7,
		0xed, 0x00, 0x10, 0xb0, 0x63, 0x2b, 0x01, 0xbc,
		0xbf, 0xcd, 0xe4, 0xfe, 0xa5, 0x04, 0x5b, 0x41,
		0x10, 0x62, 0x9b, 0xa3, 0xc0, 0x7e, 0x94, 0x68,
		0x3e, 0x27, 0x03, 0x6b, 0xd3, 0xd9, 0x36, 0x1e,
		0xe8, 0xae, 0x43, 0xf1, 0x68, 0xbd
	};

	tmp_file_init("", "encryption-key-file=\"test/test_key.pem\"\n", "", "");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.pkey = (encryption_key_t*) test_malloc(sizeof(encryption_key_t));
	c2.pkey->data = cf_malloc(sizeof(data));
	memcpy(c2.pkey->data, data, sizeof(data));
	c2.pkey->len = 1190;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_encryption_key_env)
{
	static uint8_t data[] = {
		0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
		0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89
	};

	setenv("TEST_ENCRYPT_KEY_ENV_VAR", "MUFZJlNYl5Orze8BI0VniQ==", true);
	tmp_file_init("", "encryption-key-env=\"TEST_ENCRYPT_KEY_ENV_VAR\"\n", "", "");

	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);
	unsetenv("TEST_ENCRYPT_KEY_ENV_VAR");

	c2.pkey = (encryption_key_t*) test_malloc(sizeof(encryption_key_t));
	c2.pkey->data = cf_malloc(sizeof(data));
	memcpy(c2.pkey->data, data, sizeof(data));
	c2.pkey->len = 16;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

START_TEST(test_init_sa_ca_file)
{
	// decoding of test/test_key.pem
	static char data[] = "-----BEGIN RSA PRIVATE KEY-----\n"
			"MIIEogIBAAKCAQEAvFGdHQauRhjDleDY/0lAVi7OfpzuUUpEbaQZIQ966qs2nXCY\n"
			"CAYZwnO7VkR4ooUKofms4rgGv7wmZzzXYGXqQuhiEcGd+DeUnasq6+cgqWlUGqYw\n"
			"I67iWIjzJTWOoMC7jCbphBsjHLb/ckJ4piNJUxVH/9FPdYoQLCo5J3gTvae5IZwr\n"
			"ezB88uc9JUYFuXDWwTu0yTzzZuteLMTG1Ab6ZMTR6wb4x4vU4yJfTyictJRcO6ad\n"
			"idXPOrEqbFk/AzOegzHSVEvPRwwbfbHYI08CyYXJ3RO9hTrv6MdPqtI+jz6uPFRl\n"
			"ilHCIlQ9cJjapNLJFnGJfzv6guTICkaxUTnhTwIDAQABAoIBAC7VsVhlr/P49rOQ\n"
			"vwcGhbypWWu9xbtr2AbYl/NT8ULpn+SZ+wWL1t44gC/dSY9JvTI5cRjVocAPoBFu\n"
			"3TW5QwCu4Kz/1TTFRe3Mgxk2WzYm3ubdy/0j4mEYdjgb0MQECuC5ULwtL5dVn8Qf\n"
			"6fePsQ27rjNeL//QfWMugRZi064H2lQjI27/x5uPRvkPM0yjijqMlTA/0XVA0aO9\n"
			"UWMkEAH5iwUslAhE+0MJebFZA704No+98VrcShxnzEfEMqtAtpdCpcA19Nev5TsZ\n"
			"DvhvODzw4xYdHfEBlPRO7SVXwC4NBxZZy2ocglwHVN3rd6gfa3IfF4OuGs13y6O+\n"
			"jAy9l3ECgYEA39aGooT4U50RReGVsRf483Rf4b2Ajkm6Di29Qw2il0LcGTc5PG6s\n"
			"LjA2dX1ubzp1jBsY/P2tpgPBjreOY8lA5tEcFYHLfwMBXYLFG7GBcgYzwDpyH402\n"
			"5dPMJzAEwwAUsfKkZSdqfudNBvUIPZ4mf2j2Xji9tOF+Y+X2LLKm1rkCgYEA12CU\n"
			"Nuy2rvHtvLSRjlK79j2oY8ijQOTNT5xIiaBUCNHQJBOKfjb2jv9efxSsQqVMWXsn\n"
			"8Rvwi3aklVINzmcdLLWZc7X3lnazEd5dpiIzFOYr0sXDdrNexr/+w3OMQtiivBru\n"
			"YCp8o70NIsRf+h/1kLmtNzM+OqSEIzft0lys9EcCgYBf2504yD0YgbE9/gd/GccR\n"
			"a4sMP31ocgZtwATHTHWO1aEwY0ftq2+tMBSCaD78/0oLwCcJYRIWgJFJry4ZabyT\n"
			"nIWsaDNfp0fUZgZHf9Lxo9pRvjXVcUJLVlKdjaDcaZJzSnhAoYqn4iJIknL/AFV4\n"
			"RtkLLL2BUvgvi/HK3o84cQKBgF2U/VGQMSB6xk3EN6qbkEhCKjSRLT45LGx2/52t\n"
			"KFZctA+43ehRgXhIxYp6NQ8QO8h1lrlQ5ofymTi4Wn9glnCix3ZbjqS2FsCg2hgh\n"
			"rAhcqpX+kBu3fGrnaY8LWdqBvtP077ahP171+gstQHayBEVKKFVf0p4wdanH13Ic\n"
			"CpppAoGAOzC3FYRb3C3RhAMddPQ3kZ2VWk9XYOwe9KDZtdjGvmyhBHuRlkw2+nX4\n"
			"Gq13GCn2ugWNryIPzq+2uqognb9Z+mdUTwc0DBoIWaKJbf7CRxraD2KOym0jU3nn\n"
			"7QAQsGMrAby/zeT+pQRbQRBim6PAfpRoPicDa9PZNh7orkPxaL0=\n"
			"-----END RSA PRIVATE KEY-----\n";

	tmp_file_init("", "", "", "sa-cafile=\"test/test_key.pem\"\n");
	restore_config_t c1;
	restore_config_t c2;
	restore_config_init(&c1);
	restore_config_init(&c2);
	restore_config_set_heap_defaults(&c2);

	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0);

	c2.secret_cfg.tls.ca_string = (char*) test_malloc(sizeof(data));
	memcpy((void*)c2.secret_cfg.tls.ca_string, data, sizeof(data));
	c2.secret_cfg.tls.enabled = true;

	assert_restore_config_eq(&c1, &c2);

	restore_config_destroy(&c2);
	restore_config_destroy(&c1);
}
END_TEST

#define DEFINE_BOOL_TEST(test_name, str_name, field_name) \
START_TEST(test_name) \
{ \
	tmp_file_init("", str_name "=true\n", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	c2.field_name = true; \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

/*
 * some fields are scaled in parsing, so call this directly to scale the field
 * by mult before comparing to the parsed restore_config
 */
#define DEFINE_INT_TEST_MULT(test_name, str_name, field_name, mult) \
START_TEST(test_name) \
{ \
	tmp_file_init("", str_name "=314\n", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	c2.field_name = 314lu * (mult); \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

#define DEFINE_INT_TEST(test_name, str_name, field_name) \
	DEFINE_INT_TEST_MULT(test_name, str_name, field_name, 1)

#define DEFINE_STR_TEST(test_name, str_name, field_name, str_val) \
START_TEST(test_name) \
{ \
	tmp_file_init("", str_name "=\"" str_val "\"\n", "", ""); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	cf_free(c2.field_name); \
	c2.field_name = strdup(str_val); \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

#define DEFINE_STR_SECRET_TEST(test_name, str_name, field_name, str_val) \
START_TEST(test_name) \
{ \
	tmp_file_init("", "", "", str_name "=\"" str_val "\"\n"); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	cf_free(c2.field_name); \
	c2.field_name = strdup(str_val); \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

#define DEFINE_INT_SECRET_TEST(test_name, str_name, field_name) \
START_TEST(test_name) \
{ \
	tmp_file_init("", "", "", str_name "=314\n"); \
	restore_config_t c1; \
	restore_config_t c2; \
	restore_config_init(&c1); \
	restore_config_init(&c2); \
	restore_config_set_heap_defaults(&c2); \
	\
	ck_assert_int_ne(config_from_file(&c1, NULL, file_name, 0, false), 0); \
	c2.field_name = 314lu; \
	assert_restore_config_eq(&c1, &c2); \
	\
	restore_config_destroy(&c2); \
	restore_config_destroy(&c1); \
} \
END_TEST

DEFINE_INT_TEST(test_init_parallel, "parallel", parallel);
// FIXME idk what this is and it isn't documented
DEFINE_STR_TEST(test_init_nice_list, "nice", nice_list, "127.0.0.1,192.168.0.1");
DEFINE_BOOL_TEST(test_init_validate, "validate", validate);
DEFINE_BOOL_TEST(test_init_no_records, "no-records", no_records);
DEFINE_BOOL_TEST(test_init_no_indexes, "no-indexes", no_indexes);
DEFINE_BOOL_TEST(test_init_indexes_last, "indexes-last", indexes_last);
DEFINE_BOOL_TEST(test_init_no_udfs, "no-udfs", no_udfs);
DEFINE_BOOL_TEST(test_init_wait, "wait", wait);
DEFINE_INT_TEST(test_init_timeout, "timeout", timeout);

DEFINE_STR_TEST(test_init_directory, "directory", directory, "/home/test_guy/this_dir");
DEFINE_STR_TEST(test_init_directory_list, "directory-list", directory_list, "/home/test_guy/this_dir,/another/dir");
DEFINE_STR_TEST(test_init_parent_directory, "parent-directory", parent_directory, "/root/dir");
DEFINE_STR_TEST(test_init_input_file, "input-file", input_file, "test.asb");
DEFINE_STR_TEST(test_init_machine, "machine", machine, "test.asb");
DEFINE_BOOL_TEST(test_init_unique, "unique", unique);
DEFINE_BOOL_TEST(test_init_replace, "replace", replace);
DEFINE_BOOL_TEST(test_init_ignore_rec_error, "ignore-record-error", ignore_rec_error);
DEFINE_BOOL_TEST(test_init_no_gen, "no-generation", no_generation);
DEFINE_INT_TEST(test_init_extra_ttl, "extra-ttl", extra_ttl);
DEFINE_STR_TEST(test_init_bandwidth, "nice", nice_list, "1024,100");
DEFINE_INT_TEST(test_init_tps, "tps", tps);

DEFINE_STR_TEST(test_init_s3_region, "s3-region", s3_region, "us-west-1");
DEFINE_STR_TEST(test_init_s3_profile, "s3-profile", s3_profile, "default");
DEFINE_STR_TEST(test_init_s3_endpoint_override, "s3-endpoint-override", s3_endpoint_override,
		"https://<accountid>.r2.test.com");
DEFINE_INT_TEST(test_init_s3_max_async_downloads, "s3-max-async-downloads", s3_max_async_downloads);
DEFINE_INT_TEST(test_init_s3_connect_timeout, "s3-connect-timeout", s3_connect_timeout);

DEFINE_STR_SECRET_TEST(test_init_sa_address, "sa-address", secret_cfg.addr, "127.0.0.1");
DEFINE_STR_SECRET_TEST(test_init_sa_port, "sa-port", secret_cfg.port, "3005");
DEFINE_INT_SECRET_TEST(test_init_sa_timeout, "sa-timeout", secret_cfg.timeout);


Suite* restore_conf_suite()
{
	Suite* s;
	TCase* tc_init;

	s = suite_create("Restore config file");

	tc_init = tcase_create("Init");
	tcase_add_checked_fixture(tc_init, tmp_file_setup, tmp_file_teardown);
	tcase_add_test(tc_init, test_init_empty);
	tcase_add_test(tc_init, test_init_host);
	tcase_add_test(tc_init, test_init_port);
	tcase_add_test(tc_init, test_init_services_alternate);
	tcase_add_test(tc_init, test_init_user);
	tcase_add_test(tc_init, test_init_passwd);
	tcase_add_test(tc_init, test_init_auth_mode);

	tcase_add_test(tc_init, test_init_tls_enable);
	tcase_add_test(tc_init, test_init_tls_protocols);
	tcase_add_test(tc_init, test_init_tls_cipher_suite);
	tcase_add_test(tc_init, test_init_tls_crl_check);
	tcase_add_test(tc_init, test_init_tls_crl_check_all);
	tcase_add_test(tc_init, test_init_tls_keyfile);
	tcase_add_test(tc_init, test_init_tls_keyfile_pw);
	tcase_add_test(tc_init, test_init_tls_cafile);
	tcase_add_test(tc_init, test_init_tls_capath);
	tcase_add_test(tc_init, test_init_tls_certfile);
	tcase_add_test(tc_init, test_init_tls_cert_blacklist);

	tcase_add_test(tc_init, test_init_set_list);
	tcase_add_test(tc_init, test_init_bin_list);
	tcase_add_test(tc_init, test_init_ns_list);

	tcase_add_test(tc_init, test_init_compress_mode);
	tcase_add_test(tc_init, test_init_encryption_mode);
	tcase_add_test(tc_init, test_init_encrypt_key_file);
	tcase_add_test(tc_init, test_init_encryption_key_env);

	tcase_add_test(tc_init, test_init_parallel);
	tcase_add_test(tc_init, test_init_nice_list);
	tcase_add_test(tc_init, test_init_no_records);
	tcase_add_test(tc_init, test_init_no_indexes);
	tcase_add_test(tc_init, test_init_indexes_last);
	tcase_add_test(tc_init, test_init_no_udfs);
	tcase_add_test(tc_init, test_init_wait);
	tcase_add_test(tc_init, test_init_timeout);
	tcase_add_test(tc_init, test_init_directory);
	tcase_add_test(tc_init, test_init_directory_list);
	tcase_add_test(tc_init, test_init_parent_directory);
	tcase_add_test(tc_init, test_init_input_file);
	tcase_add_test(tc_init, test_init_machine);
	tcase_add_test(tc_init, test_init_unique);
	tcase_add_test(tc_init, test_init_replace);
	tcase_add_test(tc_init, test_init_ignore_rec_error);
	tcase_add_test(tc_init, test_init_no_gen);
	tcase_add_test(tc_init, test_init_extra_ttl);
	tcase_add_test(tc_init, test_init_bandwidth);
	tcase_add_test(tc_init, test_init_tps);
	tcase_add_test(tc_init, test_init_compress_mode);

	tcase_add_test(tc_init, test_init_s3_region);
	tcase_add_test(tc_init, test_init_s3_profile);
	tcase_add_test(tc_init, test_init_s3_endpoint_override);
	tcase_add_test(tc_init, test_init_s3_max_async_downloads);
	tcase_add_test(tc_init, test_init_s3_connect_timeout);
	tcase_add_test(tc_init, test_init_s3_log_level);

	tcase_add_test(tc_init, test_init_sa_address);
	tcase_add_test(tc_init, test_init_sa_port);
	tcase_add_test(tc_init, test_init_sa_timeout);
	tcase_add_test(tc_init, test_init_sa_ca_file);

	suite_add_tcase(s, tc_init);

	return s;
}

