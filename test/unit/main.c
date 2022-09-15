/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

#include <stdlib.h>
#include <check.h>
#include "backup_tests.h"

int 
main(void)
{
	int number_failed;
	SRunner* sr;

	sr = srunner_create(backup_conf_suite());
	srunner_add_suite(sr, backup_state_suite());
	srunner_add_suite(sr, restore_conf_suite());
	srunner_add_suite(sr, file_proxy_suite());
	srunner_add_suite(sr, io_proxy_suite());
	srunner_add_suite(sr, priority_queue_suite());
	srunner_add_suite(sr, utils_suite());
	srunner_add_suite(sr, backup_file_suite());

	srunner_set_fork_status(sr, CK_NOFORK);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
