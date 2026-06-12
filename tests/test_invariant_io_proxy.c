#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../src/io_proxy.c"

START_TEST(test_buffer_read_bounds)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // 100 A's - 10x buffer
        "BBBBBBBBBBBBBBBBBBBB",  // 20 B's - 2x buffer
        "CCCCCCCC",  // 8 C's - valid input
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char buffer[10];
        memset(buffer, 'X', sizeof(buffer));
        
        FILE *tmpfile = tmpfile();
        ck_assert_ptr_nonnull(tmpfile);
        
        fprintf(tmpfile, "%s\n", payloads[i]);
        rewind(tmpfile);
        
        io_read_proxy_t *io = io_read_proxy_create(tmpfile);
        ck_assert_ptr_nonnull(io);
        
        char *result = io_proxy_gets(io, buffer, sizeof(buffer));
        
        if (result != NULL) {
            size_t actual_len = strlen(buffer);
            ck_assert_int_le(actual_len, sizeof(buffer) - 1);
            
            for (size_t j = actual_len; j < sizeof(buffer); j++) {
                ck_assert_int_eq(buffer[j], 'X');
            }
        }
        
        io_read_proxy_destroy(io);
        fclose(tmpfile);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_read_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}