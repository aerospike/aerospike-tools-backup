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
	WRITE_INIT_MATRIX(wio, TMP_FILE_0, 0);

	char* test_ns = "test_ns";
	char* sindex_str = "ns=test_ns:indexname=test_id:set=testset:bin=test_list:type=numeric:indextype=list:context=lhABI8zIIqMDaWQ=:state=RW";
	index_param* sindex_params;

	bool res_parse_index = parse_index_info(test_ns, sindex_str, sindex_params);
	ck_assert(!res_parse_index); // failed parsing sindex
    // return?

	bool res_put = text_put_secondary_index(&wio, sindex_params);
	ck_assert(!res_put); 

	io_read_proxy_t rio;
	READ_INIT_MATRIX(rio, TMP_FILE_0, 1);

    uint32_t *line_no = 1; //only 1 record on file
    decoder_status res = DECODER_ERROR;

    res = text_parse(&rio, false, NULL, NULL, *line_no, NULL, 0, false, sindex_params, NULL);
    ck_assert(res != DECODER_INDEX);

    cf_free(sindex_str);
	cf_free(test_ns);
	cf_free(sindex_params);
}
END_TEST

Suite* backup_file_suite()
{
    Suite* s;
	TCase* tc_enc_dec_text;

    s = suite_create("Backup file encode/decode");

    tc_enc_dec_text = tcase_create("encode records in a backup file");
	tcase_add_test(tc_enc_dec_text, test_enc_dec_text);

    return s;
}