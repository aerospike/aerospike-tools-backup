#pragma once

#include <check.h>

#include <citrusleaf/alloc.h>

Suite* backup_conf_suite(void);
Suite* backup_state_suite(void);
Suite* restore_conf_suite(void);
Suite* file_proxy_suite(void);
Suite* io_proxy_suite(void);
Suite* priority_queue_suite(void);
Suite* utils_suite(void);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static void* test_malloc(uint64_t size)
{
	void* ptr = cf_malloc(size);
	ck_assert_ptr_ne(ptr, NULL);
	return ptr;
}

#pragma GCC diagnostic pop

