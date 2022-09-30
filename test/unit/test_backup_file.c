#include <check.h>

#include <enc_text.h>
#include <dec_text.h>
#include <io_proxy.h>

#include "backup_tests.h"

#define TMP_FILE_0 "./test/unit/tmp0.asb"

#define WRITE_INIT_MATRIX(io, file, idx) \
	do { \
		ck_assert_int_eq(io_write_proxy_init(&io, file, 0), 0); \
	} while(0)

#define READ_INIT_MATRIX(io, file, idx) \
	do { \
		ck_assert_int_eq(io_read_proxy_init(&io, file), 0); \
	} while(0)
    
START_TEST(test_enc_dec_sindex)
{
    io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_0, 1);
    
	char test_ns[] = "test_ns";
	char sindex_str[] = "ns=test_ns:indexname=test_id:set=testset:bin=test_list:type=numeric:indextype=list:context=lhABI8zIIqMDaWQ=:state=RW";
	index_param sindex_params;

	bool res_parse_index = parse_index_info(test_ns, sindex_str, &sindex_params);
	ck_assert(res_parse_index); // failed parsing sindex
    
	bool res_put = text_put_secondary_index(&wio, &sindex_params);
    io_proxy_flush(&wio);
    ck_assert(res_put); 
    
    io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_0, 1);

    uint32_t line_no[1] = {1}; //only 1 record on file
    decoder_status res = DECODER_ERROR;
    index_param sindex_params2;
    as_vector ns_vec; //empty ns vector

    res = text_parse(&rio, false, &ns_vec, NULL, &line_no[0], NULL, 0, false, &sindex_params2, NULL, NULL);
    ck_assert_int_eq(res, DECODER_INDEX);
    io_proxy_close(&rio);

    path_param *path = as_vector_get((as_vector *)&sindex_params.path_vec, 0);
    path_param *path2 = as_vector_get((as_vector *)&sindex_params2.path_vec, 0);
    
    // check if sindex_params2 is equal to sindex_params
    ck_assert_str_eq(sindex_params.ns, sindex_params2.ns);
    ck_assert_str_eq(sindex_params.set, sindex_params2.set);
    ck_assert_int_eq(sindex_params.type, sindex_params2.type);
    ck_assert_str_eq(sindex_params.ctx, sindex_params2.ctx);
    ck_assert_str_eq(sindex_params.name, sindex_params2.name);
    ck_assert_str_eq(path->path, path2->path); // bin name
    ck_assert_int_eq(path->type, path2->type); //bin type

    remove(TMP_FILE_0);
    cf_free(path);
	cf_free(path2); 
    as_vector_destroy(&ns_vec);
}
END_TEST

START_TEST(test_enc_dec_users_info)
{
    io_write_proxy_t wio;
	WRITE_INIT_MATRIX(wio, TMP_FILE_0, 1);

    as_user* test_user = cf_malloc(sizeof(as_user) + (2 * AS_ROLE_SIZE));
	test_user->roles_size = 2;
    strcpy(test_user->name, "test_user_name");

	as_vector_init(&test_user->roles, sizeof (as_role), 25);
    as_vector_append(&test_user->roles, "test_role_1");
    as_vector_append(&test_user->roles, "test_role_2");

    bool res_put = text_put_user_info(&wio, &test_user);
    io_proxy_flush(&wio);
    ck_assert(res_put); 

    io_proxy_close2(&wio, FILE_PROXY_EOF);

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_0, 1);

    uint32_t line_no[1] = {1}; //only 1 record on file
    decoder_status res_parse = DECODER_ERROR;

    as_user* test_user_2 = cf_malloc(sizeof(as_user) + (2 * AS_ROLE_SIZE));
    as_vector ns_vec; //empty ns vector
    res_parse = text_parse(&rio, false, &ns_vec, NULL, &line_no[0], NULL, 0, false, NULL, NULL, &test_user_2);
    ck_assert_int_eq(res_parse, DECODER_USER);
    io_proxy_close(&rio);

    ck_assert_str_eq(test_user->name, test_user_2->name);
    ck_assert_int_eq(test_user->roles_size, test_user_2->roles_size); 
    ck_assert_str_eq(test_user->roles[0], test_user_2->roles[0]);
    ck_assert_str_eq(test_user->roles[1], test_user_2->roles[1]);

    remove(TMP_FILE_0);
    as_user_destroy(&test_user);
    as_user_destroy(&test_user_2);
}
END_TEST

Suite* backup_file_suite()
{
    Suite* s;
	TCase* tc_enc_dec_text;

    s = suite_create("Backup file: encode/decode global records in backup file");

    tc_enc_dec_text = tcase_create("encode records in a backup file");
	tcase_add_test(tc_enc_dec_text, test_enc_dec_sindex);
    // test below needs to be completed with upcoming user info written on backup file
    //tcase_add_test(tc_enc_dec_text, test_enc_dec_users_info);
    suite_add_tcase(s, tc_enc_dec_text);
    
    return s;
}
