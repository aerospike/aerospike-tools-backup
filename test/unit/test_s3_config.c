/*
 * Copyright 2024 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include <stdbool.h>

#include <check.h>

#include <file_proxy.h>

#include "backup_tests.h"


// ==========================================================
// SchemeForEndpoint tests — table-driven via s3_scheme_for_endpoint_is_https.
// ==========================================================

START_TEST(test_scheme_https_lowercase)
{
	ck_assert_msg(s3_scheme_for_endpoint_is_https("https://host:9000"),
			"lowercase https:// must be detected as HTTPS");
}
END_TEST

START_TEST(test_scheme_https_uppercase)
{
	ck_assert_msg(s3_scheme_for_endpoint_is_https("HTTPS://HOST:9000"),
			"uppercase HTTPS:// must be detected as HTTPS");
}
END_TEST

START_TEST(test_scheme_https_mixed_case)
{
	ck_assert_msg(s3_scheme_for_endpoint_is_https("Https://Host"),
			"mixed-case Https:// must be detected as HTTPS");
}
END_TEST

START_TEST(test_scheme_http)
{
	ck_assert_msg(!s3_scheme_for_endpoint_is_https("http://host:9000"),
			"http:// must not be detected as HTTPS");
}
END_TEST

START_TEST(test_scheme_bare_host_port)
{
	ck_assert_msg(!s3_scheme_for_endpoint_is_https("host:9000"),
			"bare host:port (no scheme) must default to HTTP");
}
END_TEST

START_TEST(test_scheme_httpsfoo_not_https)
{
	/*
	 * "httpsfoo.host" starts with "https" but not "https://". The prefix
	 * check must require the full "https://" sentinel to prevent a false
	 * positive match on hostnames that happen to begin with "https".
	 */
	ck_assert_msg(!s3_scheme_for_endpoint_is_https("httpsfoo.host"),
			"httpsfoo.host must not be mistaken for HTTPS");
}
END_TEST

START_TEST(test_scheme_empty_string)
{
	ck_assert_msg(!s3_scheme_for_endpoint_is_https(""),
			"empty endpoint must default to HTTP");
}
END_TEST

START_TEST(test_scheme_null_endpoint)
{
	ck_assert_msg(!s3_scheme_for_endpoint_is_https(NULL),
			"NULL endpoint must default to HTTP (no crash)");
}
END_TEST


// ==========================================================
// SetAllowSystemProxy / GetAllowSystemProxy round-trip tests.
// ==========================================================

START_TEST(test_allow_system_proxy_default_false)
{
	/*
	 * The global S3API object is constructed with allow_system_proxy = false.
	 * Verify the getter reflects that without any explicit setter call.
	 */
	ck_assert_msg(!s3_get_allow_system_proxy(),
			"allow_system_proxy must default to false");
}
END_TEST

START_TEST(test_allow_system_proxy_set_true)
{
	s3_set_allow_system_proxy(true);
	ck_assert_msg(s3_get_allow_system_proxy(),
			"allow_system_proxy must read back true after SetAllowSystemProxy(true)");
	s3_set_allow_system_proxy(false); /* restore default for subsequent tests */
}
END_TEST

START_TEST(test_allow_system_proxy_set_false)
{
	s3_set_allow_system_proxy(true);
	s3_set_allow_system_proxy(false);
	ck_assert_msg(!s3_get_allow_system_proxy(),
			"allow_system_proxy must read back false after SetAllowSystemProxy(false)");
}
END_TEST


// ==========================================================
// Suite assembly.
// ==========================================================

Suite *
s3_config_suite(void)
{
	Suite *s;
	TCase *tc_scheme;
	TCase *tc_proxy;

	s = suite_create("S3 config");

	tc_scheme = tcase_create("SchemeForEndpoint");
	tcase_add_test(tc_scheme, test_scheme_https_lowercase);
	tcase_add_test(tc_scheme, test_scheme_https_uppercase);
	tcase_add_test(tc_scheme, test_scheme_https_mixed_case);
	tcase_add_test(tc_scheme, test_scheme_http);
	tcase_add_test(tc_scheme, test_scheme_bare_host_port);
	tcase_add_test(tc_scheme, test_scheme_httpsfoo_not_https);
	tcase_add_test(tc_scheme, test_scheme_empty_string);
	tcase_add_test(tc_scheme, test_scheme_null_endpoint);
	suite_add_tcase(s, tc_scheme);

	tc_proxy = tcase_create("AllowSystemProxy");
	tcase_add_test(tc_proxy, test_allow_system_proxy_default_false);
	tcase_add_test(tc_proxy, test_allow_system_proxy_set_true);
	tcase_add_test(tc_proxy, test_allow_system_proxy_set_false);
	suite_add_tcase(s, tc_proxy);

	return s;
}
