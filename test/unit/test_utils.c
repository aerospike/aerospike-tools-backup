
#include <check.h>

#include <utils.h>

#include "backup_tests.h"

START_TEST(test_boolstr_false)
{
	ck_assert_str_eq(boolstr(false), "false");
}
END_TEST

START_TEST(test_boolstr_true)
{
	ck_assert_str_eq(boolstr(true), "true");
}
END_TEST

START_TEST(test_boolstr_true_large)
{
	ck_assert_str_eq(boolstr(1234), "true");
}
END_TEST

START_TEST(test_str_vector_clone)
{
	as_vector vec;
	as_vector clone;
	as_vector_inita(&vec, sizeof(char[64]), 8);

	char el1[64] = "test_string";
	as_vector_append(&vec, el1);

	ck_assert(str_vector_clone(&clone, &vec));

	ck_assert_uint_eq(clone.size, vec.size);
	ck_assert_uint_eq(clone.item_size, vec.item_size);

	ck_assert_str_eq((char*) as_vector_get(&clone, 0), (char*) as_vector_get(&vec, 0)	);

	as_vector_destroy(&clone);
	as_vector_destroy(&vec);
}
END_TEST

START_TEST(test_str_vector_contains)
{
	as_vector vec;
	as_vector_inita(&vec, sizeof(char[64]), 8);

	char el1[64] = "test_string";
	char el2[64] = "test_string 2";
	char el3[64] = "way different string";
	as_vector_append(&vec, el1);
	as_vector_append(&vec, el2);
	as_vector_append(&vec, el3);

	ck_assert(str_vector_contains(&vec, "test_string 2"));
	ck_assert(!str_vector_contains(&vec, "test_strin"));
	ck_assert(str_vector_contains(&vec, "way different string"));

	as_vector_destroy(&vec);
}
END_TEST

START_TEST(test_str_vector_tostring)
{
	as_vector vec;
	as_vector_inita(&vec, sizeof(char[64]), 8);

	char el1[64] = "test_string";
	char el2[64] = "test_string 2";
	char el3[64] = "way different string";
	as_vector_append(&vec, el1);
	as_vector_append(&vec, el2);
	as_vector_append(&vec, el3);

	ck_assert_str_eq(str_vector_tostring(&vec), "test_string,test_string 2,way different string");

	as_vector_destroy(&vec);
}
END_TEST

START_TEST(test_str_vector_tostring_empty)
{
	as_vector vec;
	as_vector_inita(&vec, sizeof(char[64]), 8);

	ck_assert_str_eq(str_vector_tostring(&vec), "");

	as_vector_destroy(&vec);
}
END_TEST

START_TEST(test_str_vector_tostring_one_el)
{
	as_vector vec;
	as_vector_inita(&vec, sizeof(char[64]), 8);

	char el1[64] = "test_string";
	as_vector_append(&vec, el1);

	ck_assert_str_eq(str_vector_tostring(&vec), "test_string");

	as_vector_destroy(&vec);
}
END_TEST

START_TEST(test_strdup_null)
{
	ck_assert_ptr_eq(safe_strdup(NULL), NULL);
}
END_TEST

START_TEST(test_strdup_empty_str)
{
	const char* str = "";
	char* dup_str = safe_strdup(str);

	ck_assert_ptr_ne(dup_str, str);
	ck_assert_str_eq(str, "");
	ck_assert_str_eq(dup_str, "");

	cf_free(dup_str);
}
END_TEST

START_TEST(test_strdup_long_str)
{
#define LONG_STR "jfaiwoefioajpowjaosdnc;awenfoiawjoaiwnw;oawwjfoioio"
	const char* str = LONG_STR;
	char* dup_str = safe_strdup(str);

	ck_assert_ptr_ne(dup_str, str);
	ck_assert_str_eq(str, LONG_STR);
	ck_assert_str_eq(dup_str, LONG_STR);

	cf_free(dup_str);
}
END_TEST

START_TEST(test_erfinv_0)
{
	const double val = 0;
	ck_assert_double_eq_tol(erf(erfinv(val)), val, 0.00001);
}
END_TEST

START_TEST(test_erfinv_rand)
{
	const double vals[] = {
		0.63,
		-0.63,
		0.12,
		-0.12,
		0.898,
		-0.898,
		0.999,
		-0.999,
		0.001,
		-0.001,
	};

	for (size_t i = 0; i < sizeof(vals) / sizeof(double); i++) {
		ck_assert_double_eq_tol(erf(erfinv(vals[i])), vals[i], 0.00001);
	}
}
END_TEST

START_TEST(test_erfinv_1)
{
	const double val = 1;
	ck_assert_double_eq(erf(erfinv(val)), val);
}
END_TEST

START_TEST(test_erfinv_n1)
{
	const double val = -1;
	ck_assert_double_eq(erf(erfinv(val)), val);
}
END_TEST

START_TEST(test_confidence_z_90)
{
	const double p = 0.90;
	ck_assert_double_eq_tol(confidence_z(p, 1), 1.281, 0.01);
}
END_TEST

START_TEST(test_confidence_z_99)
{
	const double p = 0.99;
	ck_assert_double_eq_tol(confidence_z(p, 1), 2.326, 0.01);
}
END_TEST

START_TEST(test_confidence_z_999)
{
	const double p = 0.999;
	ck_assert_double_eq_tol(confidence_z(p, 1), 3.090, 0.01);
}
END_TEST

START_TEST(test_better_atoi_0)
{
	const char num[] = "0";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, 0);
}
END_TEST

START_TEST(test_better_atoi_1)
{
	const char num[] = "1";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, 1);
}
END_TEST

START_TEST(test_better_atoi_n1)
{
	const char num[] = "-1";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, -1);
}
END_TEST

START_TEST(test_better_atoi_int_max)
{
	const char num[] = "2147483647";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, INT32_MAX);
}
END_TEST

START_TEST(test_better_atoi_uint_max)
{
	const char num[] = "4294967295";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, UINT32_MAX);
}
END_TEST

START_TEST(test_better_atoi_int_min)
{
	const char num[] = "-2147483648";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, INT32_MIN);
}
END_TEST

START_TEST(test_better_atoi_long_max)
{
	const char num[] = "9223372036854775807";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, INT64_MAX);
}
END_TEST

START_TEST(test_better_atoi_long_min)
{
	const char num[] = "-9223372036854775808";
	int64_t val;

	ck_assert(better_atoi(num, &val));
	ck_assert_int_eq(val, INT64_MIN);
}
END_TEST

Suite* utils_suite()
{
	Suite* s;
	TCase* tc_boolstr;
	TCase* tc_str_vector;
	TCase* tc_strdup;
	TCase* tc_erfinv;
	TCase* tc_confidence_z;
	TCase* tc_better_atoi;

	s = suite_create("Utils");

	tc_boolstr = tcase_create("boolstr");
	tcase_add_test(tc_boolstr, test_boolstr_false);
	tcase_add_test(tc_boolstr, test_boolstr_true);
	tcase_add_test(tc_boolstr, test_boolstr_true_large);
	suite_add_tcase(s, tc_boolstr);

	tc_str_vector = tcase_create("str_vector");
	tcase_add_test(tc_str_vector, test_str_vector_clone);
	tcase_add_test(tc_str_vector, test_str_vector_contains);
	tcase_add_test(tc_str_vector, test_str_vector_tostring);
	tcase_add_test(tc_str_vector, test_str_vector_tostring_empty);
	tcase_add_test(tc_str_vector, test_str_vector_tostring_one_el);
	suite_add_tcase(s, tc_str_vector);

	tc_strdup = tcase_create("safe_strdup");
	tcase_add_test(tc_strdup, test_strdup_null);
	tcase_add_test(tc_strdup, test_strdup_empty_str);
	tcase_add_test(tc_strdup, test_strdup_long_str);
	suite_add_tcase(s, tc_strdup);

	tc_erfinv = tcase_create("erfinv");
	tcase_add_test(tc_erfinv, test_erfinv_0);
	tcase_add_test(tc_erfinv, test_erfinv_rand);
	tcase_add_test(tc_erfinv, test_erfinv_1);
	tcase_add_test(tc_erfinv, test_erfinv_n1);
	suite_add_tcase(s, tc_erfinv);

	tc_confidence_z = tcase_create("confidence_z");
	tcase_add_test(tc_erfinv, test_confidence_z_90);
	tcase_add_test(tc_erfinv, test_confidence_z_99);
	tcase_add_test(tc_erfinv, test_confidence_z_999);
	suite_add_tcase(s, tc_confidence_z);

	tc_better_atoi = tcase_create("better_atoi");
	tcase_add_test(tc_better_atoi, test_better_atoi_0);
	tcase_add_test(tc_better_atoi, test_better_atoi_1);
	tcase_add_test(tc_better_atoi, test_better_atoi_n1);
	tcase_add_test(tc_better_atoi, test_better_atoi_int_max);
	tcase_add_test(tc_better_atoi, test_better_atoi_uint_max);
	tcase_add_test(tc_better_atoi, test_better_atoi_int_min);
	tcase_add_test(tc_better_atoi, test_better_atoi_long_max);
	tcase_add_test(tc_better_atoi, test_better_atoi_long_min);
	suite_add_tcase(s, tc_better_atoi);

	return s;
}

