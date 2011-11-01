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

#include <assert.h>

#include "tests/libknot/realdata/libknot/rrset_tests_realdata.h"
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "libknot/common.h"
#include "libknot/util/descriptor.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/util/utils.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"

static int knot_rrset_tests_count(int argc, char *argv[]);
static int knot_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rrset_tests_api = {
	"DNS library - rrset",        //! Unit name
	&knot_rrset_tests_count,  //! Count scheduled tests
	&knot_rrset_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

/* count1 == count2 */
int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count)
{
	int i = 0;
	while (i < count &&
	       wire1[i] == wire2[i]) {
		i++;
	}
	return (!(count == i));
}


knot_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset)
{
//	diag("owner: %s\n", test_rrset->owner->str);
	knot_dname_t *owner =
		knot_dname_new_from_wire(test_rrset->owner->wire,
	                                   test_rrset->owner->size, NULL);

//	diag("Created owner: %s (%p) from %p\n", knot_dname_to_str(owner),
//	     owner, test_rrset->owner);

	if (!owner) {
		return NULL;
	}

	knot_rrset_t *ret = knot_rrset_new(owner, test_rrset->type,
	                                       test_rrset->rclass,
	                                       test_rrset->ttl);

	/* Add rdata to rrset. */
	knot_rdata_t *rdata = knot_rdata_new();

	knot_rrtype_descriptor_t *desc =
		knot_rrtype_descriptor_by_type(test_rrset->type);

	node *n = NULL;
	WALK_LIST(n, test_rrset->rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		if (test_rdata->count != desc->length) {
			diag("Malformed RRSet data!");
			knot_rdata_free(&rdata);
			return ret;
		}
		assert(test_rdata->type == test_rrset->type);
		/* Add items to the actual rdata. */
		rdata->items = malloc(sizeof(knot_rdata_item_t) * desc->length);
		if (rdata->items == NULL) {
			return NULL;
		}
//		diag("Rdata type: %s\n", knot_rrtype_to_string(test_rrset->type));
		for (int i = 0; i < desc->length; i++) {
			if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
			    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME ||
			    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME) {
//				diag("%p\n", test_rdata->items[i].raw_data);
				assert(test_rdata->items[i].type == TEST_ITEM_DNAME);
				rdata->items[i].dname =
					knot_dname_new_from_wire(test_rdata->items[i].dname->wire,
				                                   test_rdata->items[i].dname->size,
				                                   NULL);
			} else {
//				diag("%p\n", test_rdata->items[i].dname);
				assert(test_rdata->items[i].type == TEST_ITEM_RAW_DATA);
				assert(test_rdata->items[i].raw_data != NULL);
				rdata->items[i].raw_data = test_rdata->items[i].raw_data;
			}
		}
	}

	rdata->next = rdata;

	ret->rdata = rdata;

	return ret;
}

extern int check_domain_name(knot_dname_t *dname, test_dname_t *test_dname);

int check_rrset(const knot_rrset_t *rrset,
                const test_rrset_t *test_rrset,
                int check_rdata, int check_items,
                int check_rrsigs)
{
	/* following implementation should be self-explanatory */
	int errors = 0;

	if (rrset == NULL) {
		diag("RRSet not created!");
		return 1;
	}

	errors += check_domain_name(rrset->owner, test_rrset->owner);

	if (rrset->type != test_rrset->type) {
		diag("TYPE wrong: %u (should be: %u)", rrset->type,
		     test_rrset->type);
		++errors;
	}

	if (rrset->rclass != test_rrset->rclass) {
		diag("CLASS wrong: %u (should be: %u)", rrset->rclass,
		     test_rrset->rclass);
		++errors;
	}

	if (rrset->ttl != test_rrset->ttl) {
		diag("TTL wrong: %u (should be: %u)", rrset->ttl,
		     test_rrset->ttl);
		++errors;
	}

	if (check_rdata) {
		/* TODO use rdata_compare */
		knot_rdata_t *rdata = rrset->rdata;

		if (rdata == NULL) {
			diag("There are no RDATAs in the RRSet");
			++errors;
		}

		if (rdata != NULL) {
			while (rdata->next != NULL &&
			       rdata->next != rrset->rdata) {
				rdata = rdata->next;
			}
			if (rdata->next == NULL) {
				diag("The list of RDATAs is not cyclic!");
				++errors;
			} else {
				assert(rdata->next == rrset->rdata);
			}
		}
	}

	/* Iterate rrset rdata list and compare items. */
	if (check_items && rrset->rdata != NULL) {
		knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(rrset->type);
		node *n = NULL;
		knot_rdata_t *tmp_rdata = rrset->rdata;
		WALK_LIST(n, test_rrset->rdata_list) {
			test_rdata_t *test_rdata = (test_rdata_t *)n;
			for (int i = 0; i < desc->length; i++) {
				if (desc->wireformat[i] == KNOT_RDATA_WF_COMPRESSED_DNAME ||
				    desc->wireformat[i] == KNOT_RDATA_WF_UNCOMPRESSED_DNAME ||
				    desc->wireformat[i] == KNOT_RDATA_WF_LITERAL_DNAME) {
					errors += check_domain_name(tmp_rdata->items[i].dname,
					                            test_rdata->items[i].dname);
				} else {
					assert(tmp_rdata != NULL);
					errors += compare_wires_simple((uint8_t *)tmp_rdata->items[i].raw_data,
					          (uint8_t *)test_rdata->items[i].raw_data,
					          test_rdata->items[i].raw_data[0]);
				}
			}
		}
	} else if (check_items && rrset->rdata == NULL) {
		diag("Could not test items, since rdata is empty!");
	}

	if (check_rrsigs) {
		/* there are currently no rrsigs */
	}
	return errors;
}

extern knot_dname_t *dname_from_test_dname(test_dname_t *test_dname);

static int test_rrset_create(const list rrset_list)
{
	int errors = 0;

	/* Test with real data. */
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		knot_rrset_t *rrset =
			knot_rrset_new(dname_from_test_dname
			                 (test_rrset->owner),
		                         test_rrset->type,
		                         test_rrset->rclass,
		                         test_rrset->ttl);
		assert(rrset);
		errors += check_rrset(rrset, test_rrset, 0, 0, 0);
		knot_rrset_deep_free(&rrset, 1, 0, 0);
	}

	return (errors == 0);
}

static int test_rrset_add_rdata(list rrset_list)
{
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		knot_rrset_t *tmp_rrset = rrset_from_test_rrset(test_rrset);
		/* TODO use all the rdata */
		assert(tmp_rrset->rdata->next = tmp_rrset->rdata);
		knot_rrset_t *rrset =
			knot_rrset_new(dname_from_test_dname
			                 (test_rrset->owner),
		                         test_rrset->type,
		                         test_rrset->rclass,
		                         test_rrset->ttl);
		assert(rrset);
		knot_rrset_add_rdata(rrset, tmp_rrset->rdata);
		errors += check_rrset(rrset, test_rrset, 1, 1, 1);
		knot_rrset_free(&tmp_rrset);
		knot_rrset_deep_free(&rrset, 1, 1, 0);

	}
	return (errors == 0);
}

static const int KNOT_RRSET_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_rrset_tests_count(int argc, char *argv[])
{
	return KNOT_RRSET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_rrset_tests_run(int argc, char *argv[])
{
	test_data_t *data = data_for_knot_tests;

	int res = 0,
	    res_final = 1;

	res = test_rrset_create(data->rrset_list);
	ok(res, "rrset: create");
	res_final *= res;

	ok(res = test_rrset_add_rdata(data->rrset_list), "rrset: add_rdata");
	res_final *= res;

	return res_final;
}
