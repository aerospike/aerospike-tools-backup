/*
 * Unit tests for the s3_proxy env-var helpers.
 *
 * Copyright (c) 2026 Aerospike, Inc. All rights reserved.
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include <s3_proxy.h>

#include "backup_tests.h"


static void
clear_proxy_env(void)
{
	unsetenv("http_proxy");
	unsetenv("HTTP_PROXY");
	unsetenv("https_proxy");
	unsetenv("HTTPS_PROXY");
	unsetenv("all_proxy");
	unsetenv("ALL_PROXY");
	unsetenv("no_proxy");
	unsetenv("NO_PROXY");
}

static void
env_setup(void)
{
	clear_proxy_env();
}

static void
env_teardown(void)
{
	clear_proxy_env();
}


//==========================================================
// s3_proxy_parse_url
//

START_TEST(parse_basic_http)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy.example.com:8080", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.host, "proxy.example.com");
	ck_assert_int_eq(r.port, 8080);
	ck_assert_int_eq(r.scheme, S3_PROXY_SCHEME_HTTP);
	ck_assert_str_eq(r.username, "");
	ck_assert_str_eq(r.password, "");
}
END_TEST

START_TEST(parse_basic_https)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("https://proxy.example.com:8443", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_int_eq(r.scheme, S3_PROXY_SCHEME_HTTPS);
	ck_assert_int_eq(r.port, 8443);
}
END_TEST

START_TEST(parse_default_port_http)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy.example.com", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_int_eq(r.port, 80);
}
END_TEST

START_TEST(parse_default_port_https)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("https://proxy.example.com", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_int_eq(r.port, 443);
}
END_TEST

START_TEST(parse_no_scheme_defaults_to_http)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("proxy.example.com:3128", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.host, "proxy.example.com");
	ck_assert_int_eq(r.port, 3128);
	ck_assert_int_eq(r.scheme, S3_PROXY_SCHEME_HTTP);
}
END_TEST

START_TEST(parse_case_insensitive_scheme)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("HTTPS://proxy.example.com", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_int_eq(r.scheme, S3_PROXY_SCHEME_HTTPS);
	ck_assert_int_eq(r.port, 443);

	ck_assert_int_eq(s3_proxy_parse_url("Http://proxy.example.com", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_int_eq(r.scheme, S3_PROXY_SCHEME_HTTP);
}
END_TEST

START_TEST(parse_credentials_both)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url(
					"http://alice:s3cret@proxy.example.com:8080", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.username, "alice");
	ck_assert_str_eq(r.password, "s3cret");
	ck_assert_str_eq(r.host, "proxy.example.com");
	ck_assert_int_eq(r.port, 8080);
}
END_TEST

START_TEST(parse_credentials_user_only)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://alice@proxy.example.com:8080",
					&r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.username, "alice");
	ck_assert_str_eq(r.password, "");
}
END_TEST

START_TEST(parse_percent_decoded_credentials)
{
	s3_proxy_url_t r;
	// password = "p@s:s/word"  encoded as p%40s%3As%2Fword
	ck_assert_int_eq(s3_proxy_parse_url(
					"http://alice:p%40s%3As%2Fword@proxy:8080", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.username, "alice");
	ck_assert_str_eq(r.password, "p@s:s/word");
}
END_TEST

START_TEST(parse_ipv6_with_port)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://[::1]:8080", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.host, "::1");
	ck_assert_int_eq(r.port, 8080);
}
END_TEST

START_TEST(parse_ipv6_no_port)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://[2001:db8::1]", &r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.host, "2001:db8::1");
	ck_assert_int_eq(r.port, 80);
}
END_TEST

START_TEST(parse_strips_trailing_path)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy:8080/some/path?x=1",
					&r),
			S3_PROXY_PARSE_OK);
	ck_assert_str_eq(r.host, "proxy");
	ck_assert_int_eq(r.port, 8080);
}
END_TEST

START_TEST(parse_empty_returns_empty)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("", &r), S3_PROXY_PARSE_EMPTY);
	ck_assert_int_eq(s3_proxy_parse_url(NULL, &r), S3_PROXY_PARSE_EMPTY);
}
END_TEST

START_TEST(parse_socks_rejected)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("socks5://proxy:1080", &r),
			S3_PROXY_PARSE_UNSUPPORTED);
	ck_assert_int_eq(s3_proxy_parse_url("socks://proxy:1080", &r),
			S3_PROXY_PARSE_UNSUPPORTED);
	ck_assert_int_eq(s3_proxy_parse_url("socks4a://proxy:1080", &r),
			S3_PROXY_PARSE_UNSUPPORTED);
	ck_assert_int_eq(s3_proxy_parse_url("socks5h://proxy:1080", &r),
			S3_PROXY_PARSE_UNSUPPORTED);
}
END_TEST

START_TEST(parse_unknown_scheme_malformed)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("ftp://proxy:21", &r),
			S3_PROXY_PARSE_MALFORMED);
}
END_TEST

START_TEST(parse_invalid_port)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy:notanumber", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy:99999", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy:0", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://proxy:65536", &r),
			S3_PROXY_PARSE_MALFORMED);
}
END_TEST

START_TEST(parse_empty_host_malformed)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://:8080", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://user:pass@", &r),
			S3_PROXY_PARSE_MALFORMED);
}
END_TEST

START_TEST(parse_unclosed_ipv6_malformed)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://[::1", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://[]", &r),
			S3_PROXY_PARSE_MALFORMED);
}
END_TEST

START_TEST(parse_bad_percent_encoding_malformed)
{
	s3_proxy_url_t r;
	ck_assert_int_eq(s3_proxy_parse_url("http://user:p%ZZ@proxy", &r),
			S3_PROXY_PARSE_MALFORMED);
	ck_assert_int_eq(s3_proxy_parse_url("http://user:p%4@proxy", &r),
			S3_PROXY_PARSE_MALFORMED);
}
END_TEST

START_TEST(parse_out_zeroed_on_error)
{
	s3_proxy_url_t r;
	memset(&r, 0xaa, sizeof(r));
	ck_assert_int_eq(s3_proxy_parse_url("ftp://x", &r),
			S3_PROXY_PARSE_MALFORMED);
	// host buffer should be zeroed -> empty C string
	ck_assert_str_eq(r.host, "");
	ck_assert_int_eq(r.port, 0);
}
END_TEST


//==========================================================
// s3_proxy_pick_url_env
//

START_TEST(pick_url_env_https_prefers_lowercase)
{
	setenv("https_proxy", "http://a", 1);
	setenv("HTTPS_PROXY", "http://b", 1);
	setenv("http_proxy", "http://c", 1);
	setenv("all_proxy", "http://e", 1);
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS),
			"http://a");
}
END_TEST

START_TEST(pick_url_env_https_falls_back_uppercase_then_all_proxy)
{
	setenv("HTTPS_PROXY", "http://b", 1);
	setenv("all_proxy", "http://e", 1);
	setenv("ALL_PROXY", "http://f", 1);
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS),
			"http://b");

	unsetenv("HTTPS_PROXY");
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS),
			"http://e");

	unsetenv("all_proxy");
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS),
			"http://f");
}
END_TEST

START_TEST(pick_url_env_http_ignores_uppercase_http_proxy)
{
	// httpoxy CVE-2016-5385: uppercase HTTP_PROXY must NOT be consulted for
	// HTTP destinations.
	setenv("HTTP_PROXY", "http://upper", 1);
	ck_assert_ptr_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTP), NULL);

	setenv("all_proxy", "http://all", 1);
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTP),
			"http://all");

	setenv("http_proxy", "http://lower", 1);
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTP),
			"http://lower");
}
END_TEST

START_TEST(pick_url_env_empty_string_treated_as_unset)
{
	setenv("https_proxy", "", 1);
	setenv("HTTPS_PROXY", "http://b", 1);
	ck_assert_str_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS),
			"http://b");
}
END_TEST

START_TEST(pick_url_env_returns_null_when_none_set)
{
	ck_assert_ptr_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTPS), NULL);
	ck_assert_ptr_eq(s3_proxy_pick_url_env(S3_PROXY_SCHEME_HTTP), NULL);
}
END_TEST


//==========================================================
// s3_proxy_pick_no_proxy_env
//

START_TEST(pick_no_proxy_env_lowercase_first)
{
	setenv("NO_PROXY", "upper", 1);
	setenv("no_proxy", "lower", 1);
	ck_assert_str_eq(s3_proxy_pick_no_proxy_env(), "lower");
}
END_TEST

START_TEST(pick_no_proxy_env_fallback_uppercase)
{
	setenv("NO_PROXY", "upper", 1);
	ck_assert_str_eq(s3_proxy_pick_no_proxy_env(), "upper");
}
END_TEST

START_TEST(pick_no_proxy_env_empty_is_unset)
{
	setenv("no_proxy", "", 1);
	setenv("NO_PROXY", "", 1);
	ck_assert_ptr_eq(s3_proxy_pick_no_proxy_env(), NULL);
}
END_TEST

START_TEST(pick_no_proxy_env_null_when_unset)
{
	ck_assert_ptr_eq(s3_proxy_pick_no_proxy_env(), NULL);
}
END_TEST


Suite*
s3_proxy_suite(void)
{
	Suite* s = suite_create("s3_proxy");

	TCase* tc_parse = tcase_create("parse_url");
	tcase_add_test(tc_parse, parse_basic_http);
	tcase_add_test(tc_parse, parse_basic_https);
	tcase_add_test(tc_parse, parse_default_port_http);
	tcase_add_test(tc_parse, parse_default_port_https);
	tcase_add_test(tc_parse, parse_no_scheme_defaults_to_http);
	tcase_add_test(tc_parse, parse_case_insensitive_scheme);
	tcase_add_test(tc_parse, parse_credentials_both);
	tcase_add_test(tc_parse, parse_credentials_user_only);
	tcase_add_test(tc_parse, parse_percent_decoded_credentials);
	tcase_add_test(tc_parse, parse_ipv6_with_port);
	tcase_add_test(tc_parse, parse_ipv6_no_port);
	tcase_add_test(tc_parse, parse_strips_trailing_path);
	tcase_add_test(tc_parse, parse_empty_returns_empty);
	tcase_add_test(tc_parse, parse_socks_rejected);
	tcase_add_test(tc_parse, parse_unknown_scheme_malformed);
	tcase_add_test(tc_parse, parse_invalid_port);
	tcase_add_test(tc_parse, parse_empty_host_malformed);
	tcase_add_test(tc_parse, parse_unclosed_ipv6_malformed);
	tcase_add_test(tc_parse, parse_bad_percent_encoding_malformed);
	tcase_add_test(tc_parse, parse_out_zeroed_on_error);
	suite_add_tcase(s, tc_parse);

	TCase* tc_env = tcase_create("env");
	tcase_add_checked_fixture(tc_env, env_setup, env_teardown);
	tcase_add_test(tc_env, pick_url_env_https_prefers_lowercase);
	tcase_add_test(tc_env, pick_url_env_https_falls_back_uppercase_then_all_proxy);
	tcase_add_test(tc_env, pick_url_env_http_ignores_uppercase_http_proxy);
	tcase_add_test(tc_env, pick_url_env_empty_string_treated_as_unset);
	tcase_add_test(tc_env, pick_url_env_returns_null_when_none_set);
	tcase_add_test(tc_env, pick_no_proxy_env_lowercase_first);
	tcase_add_test(tc_env, pick_no_proxy_env_fallback_uppercase);
	tcase_add_test(tc_env, pick_no_proxy_env_empty_is_unset);
	tcase_add_test(tc_env, pick_no_proxy_env_null_when_unset);
	suite_add_tcase(s, tc_env);

	return s;
}
