#include <assert.h>

#include "dnslib/tests/realdata/dnslib/rrset_tests_realdata.h"
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/descriptor.h"
#include "dnslib/rrset.h"
#include "dnslib/dname.h"
#include "dnslib/rdata.h"
#include "dnslib/utils.h"
#include "dnslib/node.h"
#include "dnslib/debug.h"

static int dnslib_rrset_tests_count(int argc, char *argv[]);
static int dnslib_rrset_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api rrset_tests_api = {
	"DNS library - rrset",        //! Unit name
	&dnslib_rrset_tests_count,  //! Count scheduled tests
	&dnslib_rrset_tests_run     //! Run scheduled tests
};

/*----------------------------------------------------------------------------*/
/*
 *  Unit implementation.
 */

/* count1 == count2 */
static int compare_wires_simple(uint8_t *wire1, uint8_t *wire2, uint count)
{
	int i = 0;
	while (i < count &&
	       wire1[i] == wire2[i]) {
		i++;
	}
	return (!(count == i));
}


dnslib_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset)
{
//	diag("owner: %s\n", test_rrset->owner->str);
	dnslib_dname_t *owner =
		dnslib_dname_new_from_wire(test_rrset->owner->wire,
	                                   test_rrset->owner->size, NULL);

//	diag("Created owner: %s (%p) from %p\n", dnslib_dname_to_str(owner),
//	     owner, test_rrset->owner);

	if (!owner) {
		return NULL;
	}

	dnslib_rrset_t *ret = dnslib_rrset_new(owner, test_rrset->type,
	                                       test_rrset->rclass,
	                                       test_rrset->ttl);

	/* Add rdata to rrset. */
	dnslib_rdata_t *rdata = dnslib_rdata_new();

	dnslib_rrtype_descriptor_t *desc =
		dnslib_rrtype_descriptor_by_type(test_rrset->type);

	node *n = NULL;
	WALK_LIST(n, test_rrset->rdata_list) {
		test_rdata_t *test_rdata = (test_rdata_t *)n;
		if (test_rdata->count != desc->length) {
			diag("Malformed RRSet data!");
			dnslib_rdata_free(&rdata);
			return ret;
		}
		assert(test_rdata->type == test_rrset->type);
		/* Add items to the actual rdata. */
		rdata->items = malloc(sizeof(dnslib_rdata_item_t) * desc->length);
		if (rdata->items == NULL) {
			return NULL;
		}
//		diag("Rdata type: %s\n", dnslib_rrtype_to_string(test_rrset->type));
		for (int i = 0; i < desc->length; i++) {
			if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
			    desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME ||
			    desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME) {
//				diag("%p\n", test_rdata->items[i].raw_data);
				assert(test_rdata->items[i].type == TEST_ITEM_DNAME);
				rdata->items[i].dname =
					dnslib_dname_new_from_wire(test_rdata->items[i].dname->wire,
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

extern int check_domain_name(dnslib_dname_t *dname, test_dname_t *test_dname);

int check_rrset(const dnslib_rrset_t *rrset,
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
		dnslib_rdata_t *rdata = rrset->rdata;

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
		dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);
		node *n = NULL;
		dnslib_rdata_t *tmp_rdata = rrset->rdata;
		WALK_LIST(n, test_rrset->rdata_list) {
			test_rdata_t *test_rdata = (test_rdata_t *)n;
			for (int i = 0; i < desc->length; i++) {
				if (desc->wireformat[i] == DNSLIB_RDATA_WF_COMPRESSED_DNAME ||
				    desc->wireformat[i] == DNSLIB_RDATA_WF_UNCOMPRESSED_DNAME ||
				    desc->wireformat[i] == DNSLIB_RDATA_WF_LITERAL_DNAME) {
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

extern dnslib_dname_t *dname_from_test_dname(test_dname_t *test_dname);

static int test_rrset_create(const list rrset_list)
{
	int errors = 0;

	/* Test with real data. */
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		dnslib_rrset_t *rrset =
			dnslib_rrset_new(dname_from_test_dname
			                 (test_rrset->owner),
		                         test_rrset->type,
		                         test_rrset->rclass,
		                         test_rrset->ttl);
		assert(rrset);
		errors += check_rrset(rrset, test_rrset, 0, 0, 0);
		dnslib_rrset_deep_free(&rrset, 1, 0, 0);
	}

	return (errors == 0);
}

static int test_rrset_add_rdata(list rrset_list)
{
	int errors = 0;
	node *n = NULL;
	WALK_LIST(n, rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		dnslib_rrset_t *tmp_rrset = rrset_from_test_rrset(test_rrset);
		/* TODO use all the rdata */
		assert(tmp_rrset->rdata->next = tmp_rrset->rdata);
		dnslib_rrset_t *rrset =
			dnslib_rrset_new(dname_from_test_dname
			                 (test_rrset->owner),
		                         test_rrset->type,
		                         test_rrset->rclass,
		                         test_rrset->ttl);
		assert(rrset);
		dnslib_rrset_add_rdata(rrset, tmp_rrset->rdata);
		errors += check_rrset(rrset, test_rrset, 1, 1, 1);
		dnslib_rrset_free(&tmp_rrset);
		dnslib_rrset_deep_free(&rrset, 1, 1, 0);

	}
	return (errors == 0);
}

static const int DNSLIB_RRSET_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_count(int argc, char *argv[])
{
	return DNSLIB_RRSET_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_rrset_tests_run(int argc, char *argv[])
{
	test_data_t *data = data_for_dnslib_tests;

	int res = 0,
	    res_final = 1;

	res = test_rrset_create(data->rrset_list);
	ok(res, "rrset: create");
	res_final *= res;

	ok(res = test_rrset_add_rdata(data->rrset_list), "rrset: add_rdata");
	res_final *= res;

	return res_final;
}
