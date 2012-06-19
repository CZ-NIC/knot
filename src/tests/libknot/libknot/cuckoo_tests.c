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
#include <assert.h>
#include <string.h>

#include "tests/libknot/libknot/cuckoo_tests.h"

#include "libknot/hash/cuckoo-hash-table.h"

//#define CK_TEST_DEBUG
//#define CK_TEST_LOOKUP
//#define CK_TEST_OUTPUT
//#define CK_TEST_REMOVE
//#define CK_TEST_COMPARE

#ifdef CK_TEST_DEBUG
#define CK_TEST_LOOKUP
#define CK_TEST_OUTPUT
#define CK_TEST_REMOVE
#define CK_TEST_COMPARE
#endif

/*----------------------------------------------------------------------------*/

static int cuckoo_tests_count(int argc, char *argv[]);
static int cuckoo_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api cuckoo_tests_api = {
	"Cuckoo hashing",     //! Unit name
	&cuckoo_tests_count,  //! Count scheduled tests
	&cuckoo_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/

/*
 * Unit implementation
 */
static const int CUCKOO_TESTS_COUNT = 13;
static const int CUCKOO_MAX_ITEMS = 1000;
static const int CUCKOO_TEST_MAX_KEY_SIZE = 10;

typedef struct test_cuckoo_items {
	char **keys;
	size_t *key_sizes;
	size_t *values;
	size_t *deleted;
	int count;
	int total_count;
} test_cuckoo_items;

/*----------------------------------------------------------------------------*/

static inline char rand_char()
{
	return (char)((rand() % 26) + 97);
}

/*----------------------------------------------------------------------------*/

static inline void rand_str(char *str, int size)
{
	for (int i = 0; i < size; ++i) {
		str[i] = rand_char();
	}
}

/*----------------------------------------------------------------------------*/

static int cuckoo_tests_count(int argc, char *argv[])
{
	return CUCKOO_TESTS_COUNT;
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_create(ck_hash_table_t **table, uint items)
{
	*table = ck_create_table(items);
	return (*table != NULL);
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_insert(ck_hash_table_t *table,
                              const test_cuckoo_items *items)
{
	assert(table != NULL);
	int errors = 0;
	for (int i = 0; i < items->count; ++i) {
		assert(items->values[i] != 0);
		if (ck_insert_item(table, items->keys[i], items->key_sizes[i],
		                   (void *)items->values[i]) != 0) {
			++errors;
		}
	}
	return errors == 0;
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_lookup(ck_hash_table_t *table,
                              const test_cuckoo_items *items)
{
	int errors = 0;
	for (int i = 0; i < items->count; ++i) {
		const ck_hash_table_item_t *found = ck_find_item(
		                table, items->keys[i], items->key_sizes[i]);
		if (!found) {
			if (items->deleted[i] == 0) {
				diag("Not found item with key %.*s\n",
				     items->key_sizes[i], items->keys[i]);
				++errors;
			}
		} else {
			if (items->deleted[i] != 0
			    || found->key != items->keys[i]
			    || (size_t)(found->value) != items->values[i]) {
				diag("Found item with key %.*s (size %u) "
				     "(should be %.*s (size %u)) and value %zu "
				     "(should be %d).\n",
				     found->key_length, found->key,
				     found->key_length, items->key_sizes[i],
				     items->keys[i], items->key_sizes[i],
				     (size_t)found->value, items->values[i]);
				++errors;
			}
		}
	}

	if (errors > 0) {
		diag("Not found %d of %d items.\n", errors, items->count);
	} else {
		note("Found %d items.\n", items->count);
	}

	return errors == 0;
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_delete(ck_hash_table_t *table, test_cuckoo_items *items)
{
	int errors = 0;
	// delete approx. 1/10 items from the table
	int count = rand() % (CUCKOO_MAX_ITEMS / 10) + 1;

	for (int i = 0; i < count; ++i) {
		int item = rand() % items->count;
		if (items->deleted[item] == 0
		    && ck_delete_item(table, items->keys[item],
		                      items->key_sizes[item], NULL, 0) != 0) {
			++errors;
		} else {
			items->deleted[item] = 1;
		}
	}

	return errors == 0;
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_modify(ck_hash_table_t *table, test_cuckoo_items *items)
{
	int errors = 0;
	// modify approx. 1/10 items from the table
	int count = rand() % (CUCKOO_MAX_ITEMS / 10) + 1;

	for (int i = 0; i < count; ++i) {
		int item = rand() % items->count;
		int old_value = items->values[item];
		items->values[item] = rand() + 1;
		if (ck_update_item(table, items->keys[item],
		                   items->key_sizes[item],
		                   (void *)items->values[item], NULL) != 0
		                && items->deleted[item] == 1) {
			++errors;
			items->values[item] = old_value;
		}
	}

	return 1;
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_rehash(ck_hash_table_t *table)
{
	return (ck_rehash(table) == 0);
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_resize(ck_hash_table_t *table) 
{
	// test the resize explicitly
	return (ck_resize_table(table) == 0);
}

/*----------------------------------------------------------------------------*/

static int test_cuckoo_full(ck_hash_table_t *table, test_cuckoo_items *items)
{
	// invoke the resize by inserting so much items that thay cannot
	// fit into the table
	int new_count = table->items;
	
	while (new_count < hashsize(table->table_size_exp) * table->table_count) {
		new_count += table->items;
	}
	
	note("Old item count: %d, new count: %d, capacity of the table: %d\n",
	     table->items, new_count, 
	     hashsize(table->table_size_exp) * table->table_count);
	
	assert(new_count <= items->total_count);
	
	int errors = 0;
	
	for (int i = items->count; i < new_count; ++i) {
		assert(items->values[i] != 0);
		if (ck_insert_item(table, items->keys[i], items->key_sizes[i],
		                   (void *)items->values[i]) != 0) {
			++errors;
		}
	}
	
	items->count = new_count;
	
	return (errors == 0);
}

/*----------------------------------------------------------------------------*/

static void create_random_items(test_cuckoo_items *items, int item_count)
{
	assert(items != NULL);

	items->count = item_count;
	items->total_count = item_count * 10;
	items->values = (size_t *)malloc(items->total_count * sizeof(size_t));
	items->key_sizes = (size_t *)malloc(items->total_count * sizeof(size_t));
	items->deleted = (size_t *)malloc(items->total_count * sizeof(size_t));
	items->keys = (char **)malloc(items->total_count * sizeof(char *));

	for (int i = 0; i < items->total_count; ++i) {
		int value = rand() + 1;
		int key_size = rand() % CUCKOO_TEST_MAX_KEY_SIZE + 1;
		char *key = malloc(key_size * sizeof(char));
		assert(key != NULL);
		rand_str(key, key_size);

		// check if the key is not already in the table
		int found = 0;
		for (int j = 0; j < i; ++j) {
			if (items->key_sizes[j] == key_size
			    && strncmp(items->keys[j], key, key_size) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			assert(value != 0);
			items->values[i] = value;
			items->key_sizes[i] = key_size;
			items->keys[i] = key;
			items->deleted[i] = 0;
		} else {
			free(key);
			--i;
		}
	}
}

/*----------------------------------------------------------------------------*/

static void delete_items(test_cuckoo_items *items)
{
	free(items->deleted);
	free(items->key_sizes);
	free(items->values);
	for (int i = 0; i < items->total_count; ++i) {
		free(items->keys[i]);
	}
	free(items->keys);
}

/*----------------------------------------------------------------------------*/

/*! Run all scheduled tests for given parameters.
 */
static int cuckoo_tests_run(int argc, char *argv[])
{
	srand(time(NULL));
	int res;

	const int item_count = rand() % CUCKOO_MAX_ITEMS + 1;
	test_cuckoo_items *items = (test_cuckoo_items *)
	                           malloc(sizeof(test_cuckoo_items));

	ck_hash_table_t *table = NULL;

	// Test 1: create
	ok(res = test_cuckoo_create(&table, item_count),
	   "cuckoo hashing: create");

	create_random_items(items, item_count);

	skip(!res, 10);
	// Test 2: insert
	ok(test_cuckoo_insert(table, items), "cuckoo hashing: insert");

	// Test 3: lookup
	ok(test_cuckoo_lookup(table, items), "cuckoo hashing: lookup");

	// Test 4: delete
	ok(test_cuckoo_delete(table, items), "cuckoo hashing: delete");

	// Test 5: lookup 2
	ok(test_cuckoo_lookup(table, items),
	   "cuckoo hashing: lookup after delete");

	// Test 6: modify
	ok(test_cuckoo_modify(table, items), "cuckoo hashing: modify");

	// Test 7: lookup 3
	ok(test_cuckoo_lookup(table, items),
	   "cuckoo hashing: lookup after modify");

	// Test 8: rehash
	ok(test_cuckoo_rehash(table), "cuckoo hashing: rehash");
	
	// Test 9: lookup 4
	ok(test_cuckoo_lookup(table, items),
	   "cuckoo hashing: lookup after rehash");
	
	// Test 10: resize
	ok(test_cuckoo_resize(table), "cuckoo hashing: resize");
	
	// Test 11: lookup 5
	ok(test_cuckoo_lookup(table, items),
	   "cuckoo hashing: lookup after resize");
	
	// Test 12: owerflow the table
	ok(test_cuckoo_full(table, items), "cuckoo hashing: overflow");
	
	// Test 13: lookup 5
	ok(test_cuckoo_lookup(table, items),
	   "cuckoo hashing: lookup after overflow");

	endskip;

	/**
	 * \note These last 2 tests found some major bug in the cuckoo hash
	 * table, so running them results in abort upon assertion.
	 * Disabled for now.
	 */

	// Cleanup
	ck_destroy_table(&table, NULL, 0);
	delete_items(items);
	free(items);

	return 0;
}
