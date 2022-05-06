
#include <check.h>

#include <aerospike/as_random.h>

#include <priority_queue.h>

#include "backup_tests.h"

START_TEST(test_init)
{
	priority_queue_t pq;
	ck_assert_int_eq(priority_queue_init(&pq, 8), 0);

	priority_queue_free(&pq);
}
END_TEST

START_TEST(test_insert_same_prio_capacity_8)
{
	priority_queue_t pq;
	ck_assert_int_eq(priority_queue_init(&pq, 8), 0);

	for (uint32_t i = 0; i < 8; i++) {
		ck_assert(priority_queue_push(&pq, NULL, 0));
	}
	ck_assert(!priority_queue_push(&pq, NULL, 0));

	priority_queue_free(&pq);
}
END_TEST

START_TEST(test_insert_same_prio_capacity_64)
{
	priority_queue_t pq;
	ck_assert_int_eq(priority_queue_init(&pq, 64), 0);

	for (uint32_t i = 0; i < 64; i++) {
		ck_assert(priority_queue_push(&pq, NULL, 0));
	}
	ck_assert(!priority_queue_push(&pq, NULL, 0));

	priority_queue_free(&pq);
}
END_TEST

static void
do_insert_inc_prio(uint64_t capacity)
{
	priority_queue_t pq;
	ck_assert_int_eq(priority_queue_init(&pq, capacity), 0);

	for (uint64_t i = 0; i < capacity; i++) {
		ck_assert(priority_queue_push(&pq, (void*) (i + 1), i));
	}

	for (uint64_t i = 0; i < capacity; i++) {
		void* peek_res = priority_queue_peek(&pq);
		void* res = priority_queue_pop(&pq);

		ck_assert_ptr_eq(res, peek_res);

		ck_assert_ptr_eq(res, (void*) (capacity - i));
	}

	ck_assert_ptr_eq(priority_queue_peek(&pq), NULL);
	ck_assert_ptr_eq(priority_queue_pop(&pq), NULL);

	priority_queue_free(&pq);
}

START_TEST(test_insert_inc_prio_capacity_8)
{
	do_insert_inc_prio(8);
}
END_TEST

START_TEST(test_insert_inc_prio_capacity_64)
{
	do_insert_inc_prio(64);
}
END_TEST

START_TEST(test_insert_inc_prio_capacity_32768)
{
	do_insert_inc_prio(32768);
}
END_TEST

static void
do_insert_rand_prio(uint64_t capacity)
{
	as_random random;
	as_random_init(&random);

	priority_queue_t pq;
	ck_assert_int_eq(priority_queue_init(&pq, capacity), 0);

	uint64_t* prios = (uint64_t*) test_malloc(capacity * sizeof(uint64_t));
	prios[0] = 0;
	for (uint64_t i = 1; i < capacity; i++) {
		prios[i] = i;

		// slight random bias here, but doesn't really matter
		uint64_t offset = as_random_next_uint64(&random) % (i + 1);

		uint64_t tmp = prios[offset];
		prios[offset] = prios[i];
		prios[i] = tmp;
	}

	for (uint64_t i = 0; i < capacity; i++) {
		ck_assert(priority_queue_push(&pq, (void*) (prios[i] + 1), prios[i]));
	}

	for (uint64_t i = 0; i < capacity; i++) {
		void* peek_res = priority_queue_peek(&pq);
		void* res = priority_queue_pop(&pq);

		ck_assert_ptr_eq(res, peek_res);

		ck_assert_ptr_eq(res, (void*) (capacity - i));
	}

	ck_assert_ptr_eq(priority_queue_peek(&pq), NULL);
	ck_assert_ptr_eq(priority_queue_pop(&pq), NULL);

	priority_queue_free(&pq);
}

START_TEST(test_insert_rand_prio_capacity_8)
{
	do_insert_rand_prio(8);
}
END_TEST

START_TEST(test_insert_rand_prio_capacity_64)
{
	do_insert_rand_prio(64);
}
END_TEST

START_TEST(test_insert_rand_prio_capacity_32768)
{
	do_insert_rand_prio(32768);
}
END_TEST


Suite* priority_queue_suite()
{
	Suite* s;
	TCase* tc_init;
	TCase* tc_insert;

	s = suite_create("Priority Queue");

	tc_init = tcase_create("Init");
	tcase_add_test(tc_init, test_init);
	suite_add_tcase(s, tc_init);

	tc_insert = tcase_create("Insert");
	tcase_add_test(tc_insert, test_insert_same_prio_capacity_8);
	tcase_add_test(tc_insert, test_insert_same_prio_capacity_64);
	tcase_add_test(tc_insert, test_insert_inc_prio_capacity_8);
	tcase_add_test(tc_insert, test_insert_inc_prio_capacity_64);
	tcase_add_test(tc_insert, test_insert_inc_prio_capacity_32768);
	tcase_add_test(tc_insert, test_insert_rand_prio_capacity_8);
	tcase_add_test(tc_insert, test_insert_rand_prio_capacity_64);
	tcase_add_test(tc_insert, test_insert_rand_prio_capacity_32768);
	suite_add_tcase(s, tc_insert);

	return s;
}

