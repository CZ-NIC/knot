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
/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "dname_table_tests.h"
#include "libknot/zone/dname-table.h"
/* *test_t structures */
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"

static int knot_dname_table_tests_count(int argc, char *argv[]);
static int knot_dname_table_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dname_table_tests_api = {
	"Dname table",     //! Unit name
	&knot_dname_table_tests_count,  //! Count scheduled tests
	&knot_dname_table_tests_run     //! Run scheduled tests
};

/* Helper functions. */
static knot_dname_t *dname_from_test_dname_str(const test_dname_t *test_dname)
{
	assert(test_dname != NULL);
	knot_dname_t *ret = knot_dname_new_from_str (test_dname->str,
						strlen(test_dname->str),
						NULL);
	CHECK_ALLOC(ret, NULL);

	return ret;
}

static int dname_compare_sort_wrapper(const void *ptr1, const void *ptr2)
{
	const knot_dname_t *dname1 =
		dname_from_test_dname_str((const test_dname_t *)ptr1);
	const knot_dname_t *dname2 =
		dname_from_test_dname_str((const test_dname_t *)ptr2);
	assert(dname1 && dname2);
	return knot_dname_compare(dname1, dname2);
}

/* Unit implementation. */
enum {DNAME_TABLE_DNAME_COUNT = 3};

/* Strings are enough, we're not testing dname here ... */
static test_dname_t DNAME_TABLE_DNAMES[DNAME_TABLE_DNAME_COUNT] = {
	/* list ptr, string, wire, length, labels, label_count */
	{NULL, NULL, ".", NULL, 1, NULL, 0},
	{NULL, NULL, "a.ns.nic.cz.", NULL, 13, NULL, 0},
	{NULL, NULL, "b.ns.nic.cz.", NULL, 13, NULL, 0}
};

static int test_dname_table_new()
{
	knot_dname_table_t *table = knot_dname_table_new();
	if (table == NULL) {
		return 0;
	}

	knot_dname_table_free(&table);
	return 1;
}

struct test_dname_table_arg {
	/* Times two - safety measure. */
	knot_dname_t *array[DNAME_TABLE_DNAME_COUNT * 2];
	uint count;
};

static void save_dname_to_array(knot_dname_t *node, void *data)
{
	assert(data);
	struct test_dname_table_arg *arg = (struct test_dname_table_arg *)data;
	arg->array[arg->count] = node;
	arg->count++;
}

static int test_dname_table_adding()
{
	int errors = 0;
	knot_dname_table_t *table = knot_dname_table_new();
	CHECK_ALLOC(table, 0);

	/* Add NULL */
	if (knot_dname_table_add_dname(table, NULL) != KNOT_EINVAL) {
		diag("Adding NULL dname did not result in an error!");
		errors++;
	}

	/* Add to NULL table*/
	if (knot_dname_table_add_dname(NULL, NULL) != KNOT_EINVAL) {
		diag("Adding to NULL table did not result in an error!");
		errors++;
	}

	/* Add NULL */
	if (knot_dname_table_add_dname_check(table, NULL) != KNOT_EINVAL) {
		diag("Adding NULL dname did not result in an error!");
		errors++;
	}

	/* Add to NULL table*/
	if (knot_dname_table_add_dname_check(NULL, NULL) != KNOT_EINVAL) {
		diag("Adding to NULL table did not result in an error!");
		errors++;
	}


	/* Add valid dnames. */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT; i++) {
		knot_dname_t *dname =
			dname_from_test_dname_str(&DNAME_TABLE_DNAMES[i]);
		if (!dname) {
			diag("Could not create dname from test dname!");
			errors++;
			continue;
		}
		if (knot_dname_table_add_dname(table, dname) != KNOT_EOK) {
			diag("Could not add dname! (%s)",
			     DNAME_TABLE_DNAMES[i].str);
			errors++;
		}
	}

	/*
	 * Using inorder traversal of the table,
	 * create array containing dnames.
	 */

	struct test_dname_table_arg arg;
	arg.count = 0;

	knot_dname_table_tree_inorder_apply(table, save_dname_to_array, &arg);

	if (arg.count != DNAME_TABLE_DNAME_COUNT) {
		diag("Table contains too many dnames!");
		/* No sense in continuing. */
		knot_dname_table_deep_free(&table);
		return 0;
	}

	/*
	 * Check that inordered array is really sorted
	 * and contains valid dnames.
	 */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT; i++) {
		assert(arg.array[i]);
		const char *str = knot_dname_to_str(arg.array[i]);
		if (str == NULL) {
			diag("Wrong dname in table!");
			errors++;
			continue;
		}

		if (arg.array[i]->size !=
		                DNAME_TABLE_DNAMES[i].size) {
			diag("Wrong dname size in table!");
			diag("Is: %u should be %u.",
			     arg.array[i]->size,
			     DNAME_TABLE_DNAMES[i].size);
			errors++;
			continue;
		}

		if (strncmp(str, DNAME_TABLE_DNAMES[i].str,
		            DNAME_TABLE_DNAMES[i].size) != 0) {
			diag("Wrong dname wire in table!");
			errors++;
		}
	}

	/* Now add one dname once again. It has to be the first item! */

	if (knot_dname_table_add_dname(table,
		dname_from_test_dname_str(&DNAME_TABLE_DNAMES[0])) !=
	                                 KNOT_EOK) {
		diag("Could not add dname to table once it's already there!");
		/* Next test would not make sense. */
		knot_dname_table_deep_free(&table);
		return 0;
	}

	/*
	 * After walking the table, there should now be
	 * DNAME_TABLE_DNAME_COUNT + 1 items, with 2 identical
	 * items at the beginning.
	 */

	memset(arg.array, 0,
	       sizeof(knot_dname_t *) * DNAME_TABLE_DNAME_COUNT * 2);
	arg.count = 0;
	knot_dname_table_tree_inorder_apply(table, save_dname_to_array, &arg);

	if (arg.count != DNAME_TABLE_DNAME_COUNT + 1) {
		diag("Identical dname was not added!");
		/* Again, next test would not make any sense. */
		knot_dname_table_deep_free(&table);
		return 0;
	}

	if (knot_dname_compare(arg.array[0], arg.array[1]) != 0) {
		diag("First two dnames in table are not identical!");
		errors++;
	}

	/* Delete table, wipe out array. */
	knot_dname_table_deep_free(&table);
	memset(arg.array, 0,
	       sizeof(knot_dname_t *) * DNAME_TABLE_DNAME_COUNT * 2);
	arg.count = 0;

	table = knot_dname_table_new();
	assert(table);

	/*
	 * Add dname with same content twice using knot_dname_table_add2 -
	 * table should now only contain one item.
	 */

	knot_dname_t *tmp_dname =
		dname_from_test_dname_str(&DNAME_TABLE_DNAMES[0]);
	assert(tmp_dname);

	if (knot_dname_table_add_dname_check(table, &tmp_dname) != KNOT_EOK) {
		diag("Could not add dname using dname_table_add_dname2!");
		knot_dname_table_deep_free(&table);
		knot_dname_free(&tmp_dname);
		return 0;
	}

	tmp_dname = dname_from_test_dname_str(&DNAME_TABLE_DNAMES[0]);
	assert(tmp_dname);

	knot_dname_t *dname_before_add = tmp_dname;

	if (knot_dname_table_add_dname_check(table, &tmp_dname) != 1) {
		diag("Could not add dname again using dname_table_add_dname2!");
		knot_dname_table_deep_free(&table);
		return 0;
	}

	if (tmp_dname == dname_before_add) {
		diag("Dname was not freed after insertion!");
		errors++;
	}

	knot_dname_table_tree_inorder_apply(table, save_dname_to_array, &arg);

	if (arg.count != 1) {
		diag("Add_dname2 has added dname when it shouldn't!");
		errors++;
	}

	if (knot_dname_compare(tmp_dname, arg.array[0]) != 0) {
		diag("Add_dname2 has added wrong dname!");
		errors++;
	}

	knot_dname_table_deep_free(&table);
	return (errors == 0);
}

static int test_dname_table_find()
{
	int errors = 0;
	knot_dname_table_t *table = knot_dname_table_new();
	assert(table);

	if (knot_dname_table_find_dname(table, NULL) != NULL) {
		diag("Dname table did not return NULL when searching NULL!");
		errors++;
	}

	if (knot_dname_table_find_dname(NULL, NULL) != NULL) {
		diag("Passing NULL instead of dname table did not "
		     "return NULL!");
		errors++;
	}

	/* Add all dnames but the last one. */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT - 1; i++) {
		knot_dname_t *dname =
			dname_from_test_dname_str(&DNAME_TABLE_DNAMES[i]);
		if (!dname) {
			diag("Could not create dname from test dname!");
			errors++;
			continue;
		}
		if (knot_dname_table_add_dname(table, dname) != KNOT_EOK) {
			diag("Could not add dname! (%s)",
			     DNAME_TABLE_DNAMES[i].str);
			errors++;
		}
	}

	/* Search for added dnames. */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT - 1; i++) {
		knot_dname_t *dname =
			dname_from_test_dname_str(&DNAME_TABLE_DNAMES[i]);
		if (!dname) {
			diag("Could not create dname from test dname!");
			errors++;
			continue;
		}

		knot_dname_t *found_dname =
			knot_dname_table_find_dname(table, dname);

		if (found_dname == NULL) {
			diag("Dname table did not return "
			     "dname when it should!");
			errors++;
			continue;
		}

		if (knot_dname_compare(found_dname, dname) != 0) {
			diag("Returned dname did not match!");
			errors++;
			continue;
		}
	}

	/* Search for last dname, it should return NULL. */
	knot_dname_t *dname =
		dname_from_test_dname_str(
			&DNAME_TABLE_DNAMES[DNAME_TABLE_DNAME_COUNT]);
	assert(dname);

	if (knot_dname_table_find_dname(table, dname) != NULL) {
		diag("Dname table returned dname when it "
		     "should not be there!");
		errors++;
	}

	knot_dname_free(&dname);
	knot_dname_table_deep_free(&table);

	return (errors == 0);
}

static const int KNOT_DNAME_TABLE_TEST_COUNT = 3;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_dname_table_tests_count(int argc, char *argv[])
{
	return KNOT_DNAME_TABLE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_dname_table_tests_run(int argc, char *argv[])
{
	int final_res = 1;
	int res = 0;

	/* Sort array containing test dnames. */
	qsort(DNAME_TABLE_DNAMES, DNAME_TABLE_DNAME_COUNT,
	      sizeof(test_dname_t), dname_compare_sort_wrapper);

	ok((res = test_dname_table_new()), "dname table: new");
	final_res *= res;

	skip(!res, 2);

	ok((res = test_dname_table_adding()), "dname table: adding");
	final_res *= res;

	ok((res = test_dname_table_find()), "dname table: searching");
	final_res *= res;

	endskip;

	return final_res;
}
