/* blame: jan.kadlec@nic.cz */

#include <assert.h>

#include "dname_table_tests.h"
#include "dnslib/error.h"
#include "dnslib/dname-table.h"
/* *test_t structures */
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"

static int dnslib_dname_table_tests_count(int argc, char *argv[]);
static int dnslib_dname_table_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dname_table_tests_api = {
	"Dname table",     //! Unit name
	&dnslib_dname_table_tests_count,  //! Count scheduled tests
	&dnslib_dname_table_tests_run     //! Run scheduled tests
};

/* Helper functions. */
static dnslib_dname_t *dname_from_test_dname_str(const test_dname_t *test_dname)
{
	assert(test_dname != NULL);
	dnslib_dname_t *ret = dnslib_dname_new_from_str (test_dname->str,
						strlen(test_dname->str),
						NULL);
	CHECK_ALLOC(ret, NULL);

	return ret;
}

static int dname_compare_sort_wrapper(const void *ptr1, const void *ptr2)
{
	const dnslib_dname_t *dname1 =
		dname_from_test_dname_str((const test_dname_t *)ptr1);
	const dnslib_dname_t *dname2 =
		dname_from_test_dname_str((const test_dname_t *)ptr2);
	assert(dname1 && dname2);
	return dnslib_dname_compare(dname1, dname2);
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
	dnslib_dname_table_t *table = dnslib_dname_table_new();
	if (table == NULL) {
		return 0;
	}

	dnslib_dname_table_free(&table);
	return 1;
}

struct test_dname_table_arg {
	/* Times two - safety measure. */
	dnslib_dname_t *array[DNAME_TABLE_DNAME_COUNT * 2];
	uint count;
};

static void save_dname_to_array(struct dname_table_node *node, void *data)
{
	assert(data);
	struct test_dname_table_arg *arg = (struct test_dname_table_arg *)data;
	arg->array[arg->count] = node->dname;
	arg->count++;
}

static int test_dname_table_adding()
{
	int errors = 0;
	dnslib_dname_table_t *table = dnslib_dname_table_new();
	CHECK_ALLOC(table, 0);

	/* Add NULL */
	if (dnslib_dname_table_add_dname(table, NULL) != DNSLIB_EBADARG) {
		diag("Adding NULL dname did not result in an error!");
		errors++;
	}

	/* Add to NULL table*/
	if (dnslib_dname_table_add_dname(NULL, NULL) != DNSLIB_EBADARG) {
		diag("Adding to NULL table did not result in an error!");
		errors++;
	}

	/* Add valid dnames. */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT; i++) {
		dnslib_dname_t *dname =
			dname_from_test_dname_str(&DNAME_TABLE_DNAMES[i]);
		if (!dname) {
			diag("Could not create dname from test dname!");
			errors++;
			continue;
		}
		if (dnslib_dname_table_add_dname(table, dname) != DNSLIB_EOK) {
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

	dnslib_dname_table_tree_inorder_apply(table, save_dname_to_array, &arg);

	if (arg.count != DNAME_TABLE_DNAME_COUNT) {
		diag("Table contains too many dnames!");
		/* No sense in continuing. */
		dnslib_dname_table_deep_free(&table);
		return 0;
	}

	/*
	 * Check that inordered array is really sorted
	 * and contains valid dnames.
	 */
	for (int i = 0; i < DNAME_TABLE_DNAME_COUNT; i++) {
		assert(arg.array[i]);
		const char *str = dnslib_dname_to_str(arg.array[i]);
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

	if (dnslib_dname_table_add_dname(table,
		dname_from_test_dname_str(&DNAME_TABLE_DNAMES[0])) !=
	                                 DNSLIB_EOK) {
		diag("Could not add dname to table once it's already there!");
		/* Next test would not make sense. */
		dnslib_dname_table_deep_free(&table);
		return 0;
	}

	/*
	 * After walking the table, there should now be
	 * DNAME_TABLE_DNAME_COUNT + 1 items, with 2 identical
	 * items at the beginning.
	 */

	memset(arg.array, 0,
	       sizeof(dnslib_dname_t *) * DNAME_TABLE_DNAME_COUNT * 2);
	arg.count = 0;
	dnslib_dname_table_tree_inorder_apply(table, save_dname_to_array, &arg);

	if (arg.count != DNAME_TABLE_DNAME_COUNT + 1) {
		diag("Identical dname was not added!");
		/* Again, next test would not make any sense. */
		dnslib_dname_table_deep_free(&table);
		return 0;
	}

	if (dnslib_dname_compare(arg.array[0], arg.array[1]) != 0) {
		diag("First two dnames in table are not identical!");
		errors++;
	}

	/* Delete table, wipe out array. */
	dnslib_dname_table_deep_free(&table);
	memset(arg.array, 0,
	       sizeof(dnslib_dname_t *) * DNAME_TABLE_DNAME_COUNT * 2);
	arg.count = 0;

	dnslib_dname_table_deep_free(&table);
	return (errors == 0);
}

static const int DNSLIB_DNAME_TABLE_TEST_COUNT = 6;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_dname_table_tests_count(int argc, char *argv[])
{
	return DNSLIB_DNAME_TABLE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_dname_table_tests_run(int argc, char *argv[])
{
	int final_res = 1;
	int res = 0;

	/* Sort array containing test dnames. */
	qsort(DNAME_TABLE_DNAMES, DNAME_TABLE_DNAME_COUNT,
	      sizeof(test_dname_t), dname_compare_sort_wrapper);

	ok((res = test_dname_table_new()), "dname table: new");
	final_res *= res;

	skip(!res, 6);

	ok((res = test_dname_table_adding()), "dname table: adding");
	final_res *= res;

	endskip;

	return final_res;
}
