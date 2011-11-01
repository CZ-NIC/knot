/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>

#include "tests/common/skiplist_tests.h"
#include "common/skip-list.h"

static int skiplist_tests_count(int argc, char *argv[]);
static int skiplist_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api skiplist_tests_api = {
	"Skip list",
	&skiplist_tests_count,
	&skiplist_tests_run
};

/*
 * Unit implementation.
 */

static const int SKIPLIST_TEST_COUNT = 5;

static int skiplist_tests_count(int argc, char *argv[])
{
	return SKIPLIST_TEST_COUNT;
}

/* Comparing and merging limited to int keys used in test.
 */
int test_skip_compare_keys(void *key1, void *key2)
{
	return ((long)key1 < (long)key2) ?
	        -1 : (((long)key1 > (long)key2) ? 1 : 0);
}

int test_skip_merge_values(void **lvalue, void **rvalue)
{
	(*lvalue) = (void *)((long)(*lvalue) + (long)(*rvalue));
	return 0;
}

int test_skiplist_create(skip_list_t **list)
{
	*list = skip_create_list(test_skip_compare_keys);
	return *list != NULL;
}

int test_skiplist_fill(skip_list_t *list, long *uitems, int loops)
{
	int uitem_count = 0;
	for (int i = 0; i < loops; ++i) {
		long key = rand() % 100 + 1;
		long value = rand() % 100 + 1;
		int res = skip_insert(list, (void *)key, (void *)value,
		                      test_skip_merge_values);
		switch (res) {
		case -2:
			diag("skiplist: merging failed");
			return 0;
			break;
		case -1:
			diag("skiplist: insert failed");
			return 0;
			break;
		case 0:
			uitems[uitem_count++] = key;
			break;
		default:
			break;
		}
	}

	return uitem_count;
}

int test_skiplist_lookup_seq(skip_list_t *list, long *uitems, int uitems_count)
{
	int errors = 0;

	// Sequential lookup
	for (int i = 0; i < uitems_count; ++i) {
		void *found = skip_find(list, (void *) uitems[i]);
		if (found == NULL) {
			diag("skiplist: sequential "
			     "lookup failed, key: %d", uitems[i]);
			++errors;
		}
	}

	if (errors) {
		diag("skiplist: sequential lookup: %d found %d missed,"
		     " %.2f%% success rate",
		     uitems_count - errors, errors,
		     (uitems_count - errors) / (float) uitems_count * 100.0);
	}

	return errors == 0;
}

int test_skiplist_lookup_rand(skip_list_t *list, long *uitems, int uitems_count)
{
	int errors = 0;
	srand((unsigned)time(NULL));

	// Random lookup
	for (int i = 0; i < uitems_count; ++i) {
		long key = rand() % uitems_count + 1;
		void *found = skip_find(list, (void *) key);
		if (found == NULL) {
			diag("skiplist: random lookup"
			     "failed, key: %d", uitems[i]);
			++errors;
		}
	}

	if (errors) {
		diag("skiplist: sequential lookup: "
		     "%d found %d missed, %.2f%% success rate",
		     uitems_count - errors, errors,
		     (uitems_count - errors) / (float) uitems_count * 100.0);
	}
	return errors == 0;
}


int test_skiplist_remove(skip_list_t *list, long *uitems, int uitems_count)
{
	int errors = 0;

	// delete items
	for (int i = 0; i < uitems_count; ++i) {
		int res = skip_remove(list, (void *) uitems[i], NULL, NULL);
		switch (res) {
		case 0:
			break;
		default:
			++errors;
			break;
		}
	}

	if (errors) {
		diag("skiplist: sequential lookup: %d found %d missed, "
		      "%.2f%% success rate",
		     uitems_count - errors, errors,
		     (uitems_count - errors) / (float) uitems_count * 100.0);
	}
	return errors == 0;
}

static int skiplist_tests_run(int argc, char *argv[])
{
	const int loops = 100;
	int uitems_count = 0;
	long *uitems = malloc(loops * sizeof(long));
	skip_list_t *list = 0;

	// Test 1: create
	ok(test_skiplist_create(&list), "skiplist: create");

	// Test 2: fill
	ok(uitems_count = test_skiplist_fill(list, uitems, loops),
					     "skiplist: fill");

	// Test 3: sequential lookup
	ok(test_skiplist_lookup_seq(list, uitems, uitems_count),
				    "skiplist: sequential lookup");

	// Test 4: sequential lookup
	ok(test_skiplist_lookup_seq(list, uitems, uitems_count),
				    "skiplist: random lookup lookup");

	// Test 5: remove items
	ok(test_skiplist_remove(list, uitems, uitems_count),
				"skiplist: random lookup lookup");

	// Cleanup
	skip_destroy_list(&list, NULL, NULL);
	free(uitems);
	return 0;
}
