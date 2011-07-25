#include <stdlib.h>
#include <assert.h>

#include "dnslib/tests/realdata/dnslib/rdata_tests_realdata.h"
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/rdata.h"
#include "dnslib/descriptor.h"
#include "dnslib/utils.h"
#include "dnslib/error.h"

static int dnslib_rdata_tests_count(int argc, char *argv[]);
static int dnslib_rdata_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rdata_tests_api = {
	"DNS library - rdata",        //! Unit name
	&dnslib_rdata_tests_count,  //! Count scheduled tests
	&dnslib_rdata_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

extern int check_domain_name(const dnslib_dname_t *dname,
                             const test_dname_t *test_dname);

extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);

/*!
 * \brief Checks if all RDATA items in the given RDATA structure are correct.
 *
 * \return Number of errors encountered. Error is either if some RDATA item
 *         is not set (i.e. NULL) or if it has other than the expected value.
 */
static int check_rdata(const dnslib_rdata_t *rdata,
                       const test_rdata_t *test_rdata)
{
	assert(rdata != NULL);
	assert(test_rdata != NULL);

	int errors = 0;

	dnslib_rrtype_descriptor_t *desc =
	dnslib_rrtype_descriptor_by_type(test_rdata->type);
	//note("check_rdata(), RRType: %u", rrtype);

	for (int i = 0; i < desc->length; ++i) {
		uint size = 0;

		switch (desc->wireformat[i]) {
		case DNSLIB_RDATA_WF_COMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME:
		case DNSLIB_RDATA_WF_LITERAL_DNAME:
			size = dnslib_dname_size(dnslib_rdata_item(
						 rdata, i)->dname);
			if (check_domain_name(rdata->items[i].dname,
			               test_rdata->items[i].dname) != 0) {
				errors++;
				diag("Rdata contains wrong dname item");
			}
			break;
		default:
			if (test_rdata->items[i].raw_data[0] !=
				rdata->items[i].raw_data[0]) {
				diag("Raw rdata in items have different "
				     "sizes!");
				return 0;
			}

			errors +=
				compare_wires_simple(
				       (uint8_t *)test_rdata->items[i].raw_data,
				       (uint8_t *)rdata->items[i].raw_data,
				       (uint)rdata->items[i].raw_data[0]);
		}
	}
	return errors;
}

extern dnslib_dname_t *dname_from_test_dname(test_dname_t *test_dname);

///*!
// * \brief Tests dnslib_rdata_set_item().
// *
// * \retval > 0 on success.
// * \retval 0 otherwise.
// */
//static int test_rdata_set_item(list rdata_list)
//{
//	node *n = NULL;
//	WALK_LIST(n, rdata_list) {
//		dnslib_rdata_t *rdata = dnslib_rdata_new();
//		assert(rdata);
//		test_rdata_t *test_rdata = (test_rdata_t *)n;

//		dnslib_rrtype_descriptor_t *desc =
//			dnslib_rrtype_descriptor_by_type(test_rdata->type);
//		for (int i = 0; i < test_rdata->count; i++) {
//			dnslib_rdata_item_t item;
//			if (test_rdata->items[i].type == TEST_ITEM_DNAME) {
//				item.dname =
//				dname_from_test_dname(
//					test_rdata->items[i].dname);
//			} else {
//				item.raw_data = test_rdata->items[i].raw_data;
//			}
//			if (dnslib_rdata_set_item(rdata, i, item) != 0) {
//				diag("Could not set item, rdata count: %d",
//				     rdata->count);
//				return 0;
//			}
//		}

//		/* Check that all items are OK */
//		if (check_rdata(rdata, test_rdata) != 0) {
//			return 0;
//		}
//	}
//	return 1;
//}

static dnslib_rdata_item_t *items_from_test_items(test_item_t *test_items,
                                                  size_t count)
{
	dnslib_rdata_item_t *items =
		malloc(sizeof(dnslib_rdata_item_t) * count);
	assert(items);
	for (int i = 0; i < count; i++) {
		if (test_items[i].type == TEST_ITEM_DNAME) {
			items[i].dname =
				dname_from_test_dname(test_items[i].dname);
		} else {
			items[i].raw_data = test_items[i].raw_data;
		}
	}

	return items;
}

static int test_rdata_set_items(list rdata_list)
{
	int errors = 0;

	// check error return values
	dnslib_rdata_t *rdata = dnslib_rdata_new();
	assert(rdata);

	node *n = NULL;
	WALK_LIST(n, rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		dnslib_rdata_t *rdata = dnslib_rdata_new();

		/* create dnslib items from tests items. */
		dnslib_rdata_item_t *items =
			items_from_test_items(test_rdata->items,
			test_rdata->count);

		assert(items);
		assert(test_rdata->count > 0);
		assert(rdata->items == NULL);

		if (dnslib_rdata_set_items(rdata, items,
		                           test_rdata->count) != 0) {
				diag("Could not set items!");
				errors++;
		}

		if (check_rdata(rdata, test_rdata) != 0) {
			diag("Wrong rdata after dnslib_rdata_set_items!");
			errors++;
		}

		dnslib_rdata_free(&rdata);
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests dnslib_rdata_get_item().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_get_item(list rdata_list)
{
	node *n = NULL;
	WALK_LIST(n, rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		dnslib_rdata_t *rdata = dnslib_rdata_new();
		assert(rdata);
		dnslib_rdata_item_t *items =
			items_from_test_items(test_rdata->items,
		                              test_rdata->count);
		assert(dnslib_rdata_set_items(rdata, items,
		                              test_rdata->count) == 0);
		dnslib_rdata_item_t *new_items =
			malloc(sizeof(dnslib_rdata_item_t) * test_rdata->count);
		for (int i = 0; i < test_rdata->count; i++) {
			dnslib_rdata_item_t *item =
				dnslib_rdata_get_item(rdata, i);
			if (item == NULL) {
				diag("Could not get item");
				return 0;
			}
			new_items[i] = *item;
		}

		dnslib_rdata_free(&rdata);
		free(items);

		dnslib_rdata_t *new_rdata = dnslib_rdata_new();
		assert(new_rdata);
		assert(dnslib_rdata_set_items(new_rdata,
		                              new_items,
		                              test_rdata->count) == 0);

		if (check_rdata(new_rdata, test_rdata) != 0) {
			diag("Wrong rdata created using rdata_get_item");
			return 0;
		}

		dnslib_rdata_free(&new_rdata);
		free(new_items);
	}

	return 1;
}

//static int test_rdata_wire_size()
//{
//	dnslib_rdata_t *rdata;
//	int errors = 0;

//	// generate some random data
//	uint8_t data[DNSLIB_MAX_RDATA_WIRE_SIZE];
//	generate_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE);

//	for (int i = 0; i <= DNSLIB_RRTYPE_LAST; ++i) {
//		rdata = dnslib_rdata_new();

//		int size =
//		fill_rdata(data, DNSLIB_MAX_RDATA_WIRE_SIZE, i, rdata);

//		if (size < 0) {
//			++errors;
//		} else {
//			int counted_size = dnslib_rdata_wire_size(rdata,
//			    dnslib_rrtype_descriptor_by_type(i)->wireformat);
//			if (size != counted_size) {
//				diag("Wrong wire size computed (type %d):"
//				     " %d (should be %d)",
//				     i, counted_size, size);
//				++errors;
//			}
//		}

//		dnslib_rrtype_descriptor_t *desc =
//		    dnslib_rrtype_descriptor_by_type(i);

//		for (int x = 0; x < desc->length; x++) {
//			if (desc->wireformat[x] ==
//			    DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    DNSLIB_RDATA_WF_LITERAL_DNAME) {
//				dnslib_dname_free(&(rdata->items[x].dname));
//			}
//		}
//		dnslib_rdata_free(&rdata);
//	}

//	return (errors == 0);
//}

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

static const int DNSLIB_RDATA_TEST_COUNT = 2;

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
	test_data_t *data = data_for_dnslib_tests;
	int res = 0,
	    res_final = 1;

	ok(res = test_rdata_set_items(data->rdata_list),
	   "rdata: set items all at once");
	res_final *= res;

	ok(res = test_rdata_get_item(data->rdata_list),
	   "rdata: get item");
	res_final *= res;

//	ok(res = test_rdata_set_item(data->rdata_list),
//	   "rdata: set items one-by-one");
//	res_final *= res;

	return res_final;
}
