
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

START_TEST(test_timespec_add_1s)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 0
	};

	timespec_add_us(&ts, 1000000);
	ck_assert_int_eq(ts.tv_sec, 1);
	ck_assert_int_eq(ts.tv_nsec, 0);
}
END_TEST

START_TEST(test_timespec_add_1ms)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 0
	};

	timespec_add_us(&ts, 1000);
	ck_assert_int_eq(ts.tv_sec, 0);
	ck_assert_int_eq(ts.tv_nsec, 1000000);
}
END_TEST

START_TEST(test_timespec_add_1ms_overflow)
{
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 999000050
	};

	timespec_add_us(&ts, 1000);
	ck_assert_int_eq(ts.tv_sec, 1);
	ck_assert_int_eq(ts.tv_nsec, 50);
}
END_TEST

START_TEST(test_timespec_diff_1s)
{
	struct timespec ts1 = {
		.tv_sec = 0,
		.tv_nsec = 0
	};
	struct timespec ts2 = {
		.tv_sec = 1,
		.tv_nsec = 0
	};

	ck_assert_uint_eq(timespec_diff(&ts1, &ts2), 1000000);
}
END_TEST

START_TEST(test_timespec_diff_1ms)
{
	struct timespec ts1 = {
		.tv_sec = 0,
		.tv_nsec = 0
	};
	struct timespec ts2 = {
		.tv_sec = 0,
		.tv_nsec = 1000000
	};

	ck_assert_uint_eq(timespec_diff(&ts1, &ts2), 1000);
}
END_TEST

START_TEST(test_timespec_diff_1ms_overflow)
{
	struct timespec ts1 = {
		.tv_sec = 0,
		.tv_nsec = 999000050
	};
	struct timespec ts2 = {
		.tv_sec = 1,
		.tv_nsec = 50
	};

	ck_assert_uint_eq(timespec_diff(&ts1, &ts2), 1000);
}
END_TEST


START_TEST(test_as_key_move_an_empty_key)
{
	as_key* test_key = (as_key *) test_malloc(sizeof(as_key));
	test_key->valuep = NULL;

	ck_assert(as_key_move(test_key, test_key));
	cf_free(test_key);
}
END_TEST

START_TEST(test_as_key_move_a_populated_int_key)
{
	as_key* test_key = (as_key *) test_malloc(sizeof(as_key));
	
	as_key_value* test_key_value = (as_key_value *) test_malloc(sizeof(as_key_value));
	test_key_value->integer._.count=2;
	test_key_value->integer.value=5;

	test_key->valuep = &test_key_value;
	
	ck_assert(!as_key_move(test_key, test_key));
	cf_free(test_key_value);
	cf_free(test_key);
}
END_TEST

START_TEST(test_as_key_move_a_populated_str_key)
{
	as_key* test_key = (as_key *) test_malloc(sizeof(as_key));
	
	as_key_value* test_key_value = (as_key_value *) test_malloc(sizeof(as_key_value));
	test_key_value->integer._.count=2;
	test_key_value->string.value="test";

	test_key->valuep = &test_key_value;
	
	ck_assert(!as_key_move(test_key, test_key));
	cf_free(test_key_value);
	cf_free(test_key);
}
END_TEST

START_TEST(test_as_key_move_a_populated_bytes_key)
{
	as_key* test_key = (as_key *) test_malloc(sizeof(as_key));
	
	as_key_value* test_key_value = (as_key_value *) test_malloc(sizeof(as_key_value));
	test_key_value->integer._.count=2;

	test_key->valuep = &test_key_value;
	
	ck_assert(!as_key_move(test_key, test_key));
	cf_free(test_key_value);
	cf_free(test_key);
}
END_TEST

START_TEST(test_as_key_move_success)
{
	as_key* src = (as_key *) test_malloc(sizeof(as_key));
	as_key* dst = (as_key *) test_malloc(sizeof(as_key));

	as_key_value* test_key_value = (as_key_value *) test_malloc(sizeof(as_key_value));
	test_key_value->integer._.count=1;
	test_key_value->integer.value=123;

	src->value = *test_key_value;
	src->valuep = &src->value;

	ck_assert(as_key_move(dst, src));
	ck_assert_int_eq(dst->value.integer.value, src->value.integer.value);
	cf_free(test_key_value);
	cf_free(dst);
	cf_free(src);
}
END_TEST

START_TEST(test_secondary_index_param_with_ctx)
{
	char test_ns[] = "test_ns";
	char sindex_str[] = "ns=test_ns:indexname=test_id:set=testset:bin=test_list:type=numeric:indextype=list:context=lhABI8zIIqMDaWQ=:state=RW";
	index_param sindex_params;

	bool res = parse_index_info(test_ns, sindex_str, &sindex_params);
	path_param *path = as_vector_get((as_vector *)&sindex_params.path_vec, 0);

	ck_assert(res); // failed parsing sindex
	ck_assert_str_eq(sindex_params.ns, test_ns);
	ck_assert_str_eq(sindex_params.set, "testset"); //set
	ck_assert_str_eq(sindex_params.name, "test_id"); //indexname
	ck_assert_int_eq(sindex_params.type, INDEX_TYPE_LIST); //indextype
	ck_assert_str_eq(sindex_params.ctx, "lhABI8zIIqMDaWQ="); //b64 encoded ctx	
	ck_assert_str_eq(path->path, "test_list"); //bin name
	ck_assert_int_eq(path->type, PATH_TYPE_NUMERIC); //bin type

	cf_free(path);
}
END_TEST

START_TEST(test_secondary_index_param_without_ctx)
{
	char test_ns[] = "test_ns";
	char sindex_str[] = "ns=test_ns:indexname=test_id:set=testset:bin=test_list:type=numeric:indextype=list:state=RW:path=test_list";
	index_param sindex_params;

	bool res = parse_index_info(test_ns, sindex_str, &sindex_params);
	path_param *path = as_vector_get((as_vector *)&sindex_params.path_vec, 0);

	ck_assert(res); // failed parsing sindex
	ck_assert_str_eq(sindex_params.ns, test_ns);
	ck_assert_str_eq(sindex_params.set, "testset"); //set
	ck_assert_str_eq(sindex_params.name, "test_id"); //indexname
	ck_assert_int_eq(sindex_params.type, INDEX_TYPE_LIST); //indextype
	ck_assert_ptr_null(sindex_params.ctx); //ctx should be null	
	ck_assert_str_eq(path->path, "test_list"); //bin name
	ck_assert_int_eq(path->type, PATH_TYPE_NUMERIC); //bin type

	cf_free(path);
}
END_TEST

START_TEST(test_secondary_index_type_blob)
{
	char test_ns[] = "test_ns";
	char sindex_str[] = "ns=test_ns:indexname=test_id:set=testset:bin=test_list:type=blob:indextype=list:state=RW:path=test_list";
	index_param sindex_params;

	bool res = parse_index_info(test_ns, sindex_str, &sindex_params);
	path_param *path = as_vector_get((as_vector *)&sindex_params.path_vec, 0);

	ck_assert(res); // failed parsing sindex
	ck_assert_str_eq(sindex_params.ns, test_ns);
	ck_assert_str_eq(sindex_params.set, "testset"); //set
	ck_assert_str_eq(sindex_params.name, "test_id"); //indexname
	ck_assert_int_eq(sindex_params.type, INDEX_TYPE_LIST); //indextype
	ck_assert_ptr_null(sindex_params.ctx); //ctx should be null	
	ck_assert_str_eq(path->path, "test_list"); //bin name
	ck_assert_int_eq(path->type, PATH_TYPE_BLOB); //bin type

	cf_free(path);
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
	TCase* tc_timespec;
	TCase* tc_move_key;
	TCase* tc_index_param;

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

	tc_timespec = tcase_create("timespec utils");
	tcase_add_test(tc_timespec, test_timespec_add_1s);
	tcase_add_test(tc_timespec, test_timespec_add_1ms);
	tcase_add_test(tc_timespec, test_timespec_add_1ms_overflow);
	tcase_add_test(tc_timespec, test_timespec_diff_1s);
	tcase_add_test(tc_timespec, test_timespec_diff_1ms);
	tcase_add_test(tc_timespec, test_timespec_diff_1ms_overflow);
	suite_add_tcase(s, tc_timespec);

	
	tc_move_key = tcase_create("as_move_key utils");
	tcase_add_test(tc_move_key, test_as_key_move_an_empty_key);
	tcase_add_test(tc_move_key, test_as_key_move_a_populated_int_key);
	tcase_add_test(tc_move_key, test_as_key_move_a_populated_str_key);
	tcase_add_test(tc_move_key, test_as_key_move_a_populated_bytes_key);
	tcase_add_test(tc_move_key, test_as_key_move_success);
	suite_add_tcase(s, tc_move_key);
	
	tc_index_param = tcase_create("secondary index parameters utils");
	tcase_add_test(tc_index_param, test_secondary_index_param_with_ctx);
	tcase_add_test(tc_index_param, test_secondary_index_param_without_ctx);
	suite_add_tcase(s, tc_index_param);

	return s;
}

