/*!
 * \file dnslib_rdata_tests.c
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * Contains unit tests for RDATA (dnslib_rdata_t) and RDATA item
 * (dnslib_rdata_item_t) structures.
 *
 * Contains tests for:
 * - creating empty RDATA structure with or without reserved space.
 * - setting RDATA items one-by-one
 * - setting RDATA items all at once
 *
 * As for now, the tests use several (TEST_RDATAS) RDATA structures, each
 * with different number of RDATA items (given by test_rdatas). These are all
 * initialized to pointers derived from RDATA_ITEM_PTR (first is RDATA_ITEM_PTR,
 * second RDATA_ITEM_PTR + 1, etc.). The functions only test if the pointer
 * is set properly.
 *
 * \todo It may be better to test also some RDATAs with predefined contents,
 *       such as some numbers, some domain name, etc. For this purpose, we'd
 *       need RDATA descriptors (telling the types of each RDATA item within an
 *       RDATA).
 *
 * \todo It will be fine to test all possible output values of all functions,
 *       e.g. test whether dnslib_rdata_get_item() returns NULL when passed an
 *       illegal position, etc.
 */

#include "tap_unit.h"

#include "common.h"
#include "rdata.h"

static int dnslib_rdata_tests_count(int argc, char *argv[]);
static int dnslib_rdata_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_rdata_tests_api = {
   "DNS library - rdata",        //! Unit name
   &dnslib_rdata_tests_count,  //! Count scheduled tests
   &dnslib_rdata_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

// C will not accept const int in other const definition
enum { TEST_RDATAS = 7 };

static uint8_t *RDATA_ITEM_PTR = (uint8_t *)0xDEADBEEF;

struct test_rdata {
	uint items;
};

static const struct test_rdata
		test_rdatas[TEST_RDATAS] = {
	{ 1 },
	{ 2 },
	{ 3 },
	{ 4 },
	{ 5 },
	{ 10 },
	{ 100 },
};

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests dnslib_rdata_new().
 *
 * Creates new RDATA structure with \a count RDATA items. If \a count > 0,
 * it also tests if the RDATA items are properly initialized
 * (all should be NULL).
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_create( uint count )
{
	dnslib_rdata_t *rdata = dnslib_rdata_new(count);
	if (rdata == NULL) {
		diag("RDATA structure not created!");
		return 0;
	}

	for (int i = 0; i < count; ++i) {
		const dnslib_rdata_item_t *item;
		if ((item = dnslib_rdata_get_item(rdata, i)) == NULL) {
			diag("Missing RDATA item on position %d", i);
			dnslib_rdata_free(rdata);
			return 0;
		} else if (item->dname != NULL) {
			diag("RDATA item on position %d not properly initialized: %p"
				 " (should be NULL).", i, item->dname);
			dnslib_rdata_free(rdata);
			return 0;
		}
	}

	dnslib_rdata_free(rdata);
	return 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests dnslib_rdata_free().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_delete() {
	// how to test this??
	return 0;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Checks if all RDATA items in the given RDATA structure are correct.
 *
 * Compares items with the expected value, which is (as of now) the
 * RDATA_ITEM_PTR pointer, increased by the index of the item.
 *
 * \return Number of errors encountered. Error is either if some RDATA item
 *         is not set (i.e. NULL) or if it has other than the expected value.
 */
static int check_rdata( const dnslib_rdata_t *rdata, int i )
{
	assert(rdata != NULL);

	int errors = 0;

	for (int j = 0; j < test_rdatas[i].items; ++j) {
		const dnslib_rdata_item_t *item = dnslib_rdata_get_item(rdata, j);
		if (item == NULL) {
			diag("RDATA item at position %d NULL when it should not be!", j);
			++errors;
		} else if (item->raw_data != RDATA_ITEM_PTR + j) {
			diag("RDATA item at position %d should be %p, but is %p!",
				 RDATA_ITEM_PTR + j, item->raw_data);
			++errors;
		}
	}

	return errors;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets RDATA items within the given RDATA structure one-by-one.
 *
 * Sets the items to hold value RDATA_ITEM_PTR increased by the index of the
 * item (i.e. + 0 for the first, + 1 for the second, etc.).
 */
static void set_rdata( dnslib_rdata_t *rdata, int i )
{
	assert(rdata != NULL);

	dnslib_rdata_item_t item;
	item.raw_data = RDATA_ITEM_PTR;

	for (int j = 0; j < test_rdatas[i].items; ++j) {
		dnslib_rdata_set_item(rdata, j, item);
		++item.raw_data;
	}
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Sets RDATA items within the given RDATA structure all at once.
 *
 * Sets the items to hold value RDATA_ITEM_PTR increased by the index of the
 * item (i.e. + 0 for the first, + 1 for the second, etc.).
 *
 * \retval > 0 if successful.
 * \retval 0 if an error occured.
 */
static int set_rdata_all( dnslib_rdata_t *rdata, int i )
{
	assert(rdata != NULL);

	dnslib_rdata_item_t *items = (dnslib_rdata_item_t *)malloc(
			test_rdatas[i].items * sizeof(dnslib_rdata_item_t));

	if (items == NULL) {
		diag("Allocation failed in set_rdata_all().");
		return 0;
	}

	for (int j = 0; j < test_rdatas[i].items; ++j) {
		items[j].raw_data = RDATA_ITEM_PTR + j;
	}

	dnslib_rdata_set_items(rdata, items, test_rdatas[i].items);

	return 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests dnslib_rdata_set_item().
 *
 * Iterates over the test_rdatas array and for each testing RDATA it creates
 * the RDATA structure, sets its items one-by-one (\see set_rdata()) and checks
 * if the items are set properly (\see check_rdata()).
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_set_item()
{
	dnslib_rdata_t *rdata;

	for (int i = 0; i < TEST_RDATAS; ++i) {
		rdata = dnslib_rdata_new(test_rdatas[i].items);
		set_rdata(rdata, i);
		if (check_rdata(rdata, i) != 0) {
			dnslib_rdata_free(rdata);
			return 0;
		}
		dnslib_rdata_free(rdata);
	}

	return 1;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests dnslib_rdata_set_items().
 *
 * Iterates over the test_rdatas array and for each testing RDATA it creates
 * the RDATA structure, sets its items (\see set_rdata_all()) and checks if the
 * items are set properly (\see check_rdata()).
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_set_items()
{
	dnslib_rdata_t *rdata;

	for (int i = 0; i < TEST_RDATAS; ++i) {
		rdata = dnslib_rdata_new(test_rdatas[i].items);
		if (!set_rdata_all(rdata, i)) {
			dnslib_rdata_free(rdata);
			return 0;
		}
		if (check_rdata(rdata, i) != 0) {
			dnslib_rdata_free(rdata);
			return 0;
		}
		dnslib_rdata_free(rdata);
	}

	return 1;
}

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RDATA_TEST_COUNT = 5;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_rdata_tests_count(int argc, char *argv[])
{
   return DNSLIB_RDATA_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_rdata_tests_run(int argc, char *argv[])
{
	int res_create = 0;

	res_create = test_rdata_create(0);
	ok(res_create, "rdata: create empty");

	skip(!res_create, 4);

	res_create = test_rdata_create(TEST_RDATAS);
	ok(res_create, "rdata: create non-empty");

	skip(!res_create, 3);

	todo();

	ok(test_rdata_delete(), "rdata: delete");

	endtodo;

	ok(test_rdata_set_item(), "rdata: set items one-by-one");

	ok(test_rdata_set_items(), "rdata: set items all at once");

	endskip;	/* !res_create (count > 0) */

	endskip;	/* !res_create (count == 0) */

	return 0;
}
