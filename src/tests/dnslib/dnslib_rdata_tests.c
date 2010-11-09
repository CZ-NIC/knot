#include "tap_unit.h"

#include "common.h"
#include "rdata.h"
//#include "node.h"

static int dnslib_rdata_tests_count(int argc, char *argv[]);
static int dnslib_rdata_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_rdata_tests_api = {
   "DNS library - rdata",        //! Unit name
   &dnslib_rdata_tests_count,  //! Count scheduled tests
   &dnslib_rdata_tests_run     //! Run scheduled tests
};

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

/*!
 * \brief Tests dnslib_rdata_new().
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

/*!
 * \brief Tests dnslib_rdata_free().
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_delete() {
	// how to test this??
	return 0;
}

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

/*!
 * \brief Tests dnslib_rdata_set_item().
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

//static int test_rdata_set_items( dnslib_rdata_t *rdata, uint count )
//{
//	assert(rdata != NULL);

//	dnslib_rdata_item_t *items = (dnslib_rdata_item_t *)malloc(
//			count * sizeof(dnslib_rdata_item_t));
//	if (items == NULL) {
//		diag("Error during executing test test_rdata_set_items()");
//		return 0;
//	}

//	for (int i = 0; i < count; ++i) {
//		items[i].raw_data = RDATA_ITEM_PTR + i;
//	}

//	return 1;

//}


static const int DNSLIB_RDATA_TEST_COUNT = 4;

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

	skip(!res_create, 3);

	res_create = test_rdata_create(TEST_RDATAS);
	ok(res_create, "rdata: create non-empty");

	skip(!res_create, 2);

	todo();

	ok(test_rdata_delete(), "rdata: delete");

	endtodo;

	ok(test_rdata_set_item(), "rdata: set items one-by-one");

	endskip;	/* !res_create (count > 0) */

	endskip;	/* !res_create (count == 0) */

	return 0;
}
