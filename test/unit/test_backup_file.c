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
    
START_TEST(test_enc_dec_text)
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
    /*
	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_0, 1);

    uint32_t line_no[1] = {1}; //only 1 record on file
    decoder_status res = DECODER_ERROR;
    index_param sindex_params2;
    as_vector ns_vec; //empty ns vector

    res = text_parse(&rio, false, &ns_vec, NULL, &line_no[0], NULL, 0, false, &sindex_params2, NULL);
    ck_assert_int_eq(res, DECODER_INDEX);
    
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

    io_proxy_close(&rio);
    io_proxy_close2(&wio, FILE_PROXY_EOF);
    remove(TMP_FILE_0);
    cf_free(path);
	cf_free(path2); 
    as_vector_destroy(&ns_vec);
    */
    io_proxy_close2(&wio, FILE_PROXY_EOF);
    remove(TMP_FILE_0);

}
END_TEST

Suite* backup_file_suite()
{
    Suite* s;
	TCase* tc_enc_dec_text;

    s = suite_create("Backup file: encode/decode a secondary index with ctx");

    tc_enc_dec_text = tcase_create("encode records in a backup file");
	tcase_add_test(tc_enc_dec_text, test_enc_dec_text);
    suite_add_tcase(s, tc_enc_dec_text);

    return s;
}
