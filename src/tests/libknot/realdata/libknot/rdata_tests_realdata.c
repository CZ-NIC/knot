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

#include <stdlib.h>
#include <assert.h>

#include "tests/libknot/realdata/libknot/rdata_tests_realdata.h"
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "libknot/common.h"
#include "libknot/rdata.h"
#include "libknot/util/descriptor.h"
#include "libknot/util/utils.h"

static int knot_rdata_tests_count(int argc, char *argv[]);
static int knot_rdata_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rdata_tests_api = {
	"DNS library - rdata",        //! Unit name
	&knot_rdata_tests_count,  //! Count scheduled tests
	&knot_rdata_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

extern int check_domain_name(const knot_dname_t *dname,
                             const test_dname_t *test_dname);

extern int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count);

/*!
 * \brief Checks if all RDATA items in the given RDATA structure are correct.
 *
 * \return Number of errors encountered. Error is either if some RDATA item
 *         is not set (i.e. NULL) or if it has other than the expected value.
 */
static int check_rdata(const knot_rdata_t *rdata,
                       const test_rdata_t *test_rdata)
{
	assert(rdata != NULL);
	assert(test_rdata != NULL);

	int errors = 0;

	knot_rrtype_descriptor_t *desc =
	knot_rrtype_descriptor_by_type(test_rdata->type);
	//note("check_rdata(), RRType: %u", rrtype);

	for (int i = 0; i < desc->length; ++i) {

		switch (desc->wireformat[i]) {
		case KNOT_RDATA_WF_COMPRESSED_DNAME:
		case KNOT_RDATA_WF_UNCOMPRESSED_DNAME:
		case KNOT_RDATA_WF_LITERAL_DNAME:
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

extern knot_dname_t *dname_from_test_dname(test_dname_t *test_dname);

///*!
// * \brief Tests knot_rdata_set_item().
// *
// * \retval > 0 on success.
// * \retval 0 otherwise.
// */
//static int test_rdata_set_item(list rdata_list)
//{
//	node *n = NULL;
//	WALK_LIST(n, rdata_list) {
//		knot_rdata_t *rdata = knot_rdata_new();
//		assert(rdata);
//		test_rdata_t *test_rdata = (test_rdata_t *)n;

//		knot_rrtype_descriptor_t *desc =
//			knot_rrtype_descriptor_by_type(test_rdata->type);
//		for (int i = 0; i < test_rdata->count; i++) {
//			knot_rdata_item_t item;
//			if (test_rdata->items[i].type == TEST_ITEM_DNAME) {
//				item.dname =
//				dname_from_test_dname(
//					test_rdata->items[i].dname);
//			} else {
//				item.raw_data = test_rdata->items[i].raw_data;
//			}
//			if (knot_rdata_set_item(rdata, i, item) != 0) {
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

static knot_rdata_item_t *items_from_test_items(test_item_t *test_items,
                                                  size_t count)
{
	knot_rdata_item_t *items =
		malloc(sizeof(knot_rdata_item_t) * count);
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
	knot_rdata_t *rdata = knot_rdata_new();
	assert(rdata);

	node *n = NULL;
	WALK_LIST(n, rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		knot_rdata_t *rdata = knot_rdata_new();

		/* create dnslib items from tests items. */
		knot_rdata_item_t *items =
			items_from_test_items(test_rdata->items,
			test_rdata->count);

		assert(items);
		assert(test_rdata->count > 0);
		assert(rdata->items == NULL);

		if (knot_rdata_set_items(rdata, items,
		                           test_rdata->count) != 0) {
				diag("Could not set items!");
				errors++;
		}

		if (check_rdata(rdata, test_rdata) != 0) {
			diag("Wrong rdata after knot_rdata_set_items!");
			errors++;
		}

		knot_rdata_free(&rdata);
	}

	return (errors == 0);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Tests knot_rdata_get_item().
 *
 * \retval > 0 on success.
 * \retval 0 otherwise.
 */
static int test_rdata_get_item(list rdata_list)
{
	node *n = NULL;
	WALK_LIST(n, rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		knot_rdata_t *rdata = knot_rdata_new();
		assert(rdata);
		knot_rdata_item_t *items =
			items_from_test_items(test_rdata->items,
		                              test_rdata->count);
		assert(knot_rdata_set_items(rdata, items,
		                              test_rdata->count) == 0);
		knot_rdata_item_t *new_items =
			malloc(sizeof(knot_rdata_item_t) * test_rdata->count);
		for (int i = 0; i < test_rdata->count; i++) {
			knot_rdata_item_t *item =
				knot_rdata_get_item(rdata, i);
			if (item == NULL) {
				diag("Could not get item");
				return 0;
			}
			new_items[i] = *item;
		}

		knot_rdata_free(&rdata);
		free(items);

		knot_rdata_t *new_rdata = knot_rdata_new();
		assert(new_rdata);
		assert(knot_rdata_set_items(new_rdata,
		                              new_items,
		                              test_rdata->count) == 0);

		if (check_rdata(new_rdata, test_rdata) != 0) {
			diag("Wrong rdata created using rdata_get_item");
			return 0;
		}

		knot_rdata_free(&new_rdata);
		free(new_items);
	}

	return 1;
}

//static int test_rdata_wire_size()
//{
//	knot_rdata_t *rdata;
//	int errors = 0;

//	// generate some random data
//	uint8_t data[KNOT_MAX_RDATA_WIRE_SIZE];
//	generate_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE);

//	for (int i = 0; i <= KNOT_RRTYPE_LAST; ++i) {
//		rdata = knot_rdata_new();

//		int size =
//		fill_rdata(data, KNOT_MAX_RDATA_WIRE_SIZE, i, rdata);

//		if (size < 0) {
//			++errors;
//		} else {
//			int counted_size = knot_rdata_wire_size(rdata,
//			    knot_rrtype_descriptor_by_type(i)->wireformat);
//			if (size != counted_size) {
//				diag("Wrong wire size computed (type %d):"
//				     " %d (should be %d)",
//				     i, counted_size, size);
//				++errors;
//			}
//		}

//		knot_rrtype_descriptor_t *desc =
//		    knot_rrtype_descriptor_by_type(i);

//		for (int x = 0; x < desc->length; x++) {
//			if (desc->wireformat[x] ==
//			    KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_COMPRESSED_DNAME ||
//			    desc->wireformat[x] ==
//			    KNOT_RDATA_WF_LITERAL_DNAME) {
//				knot_dname_free(&(rdata->items[x].dname));
//			}
//		}
//		knot_rdata_free(&rdata);
//	}

//	return (errors == 0);
//}

/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

static const int KNOT_RDATA_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_rdata_tests_count(int argc, char *argv[])
{
	return KNOT_RDATA_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_rdata_tests_run(int argc, char *argv[])
{
	test_data_t *data = data_for_knot_tests;
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
