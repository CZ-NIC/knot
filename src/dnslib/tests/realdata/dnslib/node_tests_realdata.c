#include <assert.h>

#include "dnslib/tests/realdata/dnslib/node_tests_realdata.h"
#include "dnslib/tests/realdata/dnslib_tests_loader_realdata.h"
#include "dnslib/dname.h"
#include "dnslib/node.h"
#include "dnslib/descriptor.h"

static int dnslib_node_tests_count(int argc, char *argv[]);
static int dnslib_node_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api node_tests_api = {
	"DNS library - node",       //! Unit name
	&dnslib_node_tests_count,  //! Count scheduled tests
	&dnslib_node_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

/* TODO It would be wise not to name variables totally same as structures ... */
dnslib_dname_t *dname_from_test_dname(const test_dname_t *test_dname)
{
	assert(test_dname != NULL);
	dnslib_dname_t *ret = dnslib_dname_new_from_wire(test_dname->wire,
	                                                 test_dname->size,
	                                                 NULL);
	CHECK_ALLOC(ret, NULL);

	return ret;
}

static dnslib_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset)
{
	assert(test_rrset != NULL);
	dnslib_dname_t *owner = dname_from_test_dname(test_rrset->owner);
	CHECK_ALLOC(owner, NULL);

	dnslib_rrset_t *ret = dnslib_rrset_new(owner, test_rrset->type,
	                                       test_rrset->rclass,
	                                       test_rrset->ttl);
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		dnslib_dname_free(&owner);
		return NULL;
	}

	return ret;
}

static int test_node_create(const list *node_list)
{
	/* Tests creation of node by comparing with test_node struct */
	dnslib_node_t *tmp;
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n, *node_list) {
		const test_node_t *tmp_node = (test_node_t *)n;
		assert(tmp_node);

		dnslib_dname_t *owner =
			dname_from_test_dname(tmp_node->owner);
		if (owner == NULL) {
			return 0;
		}
		tmp = dnslib_node_new(owner,
		                      (dnslib_node_t *)tmp_node->parent);
		if (tmp == NULL ||
		    (strncmp((char *)tmp->owner->name,
		             (char *)tmp_node->owner->wire,
		             tmp->owner->size) != 0) ||
		    tmp->parent != (dnslib_node_t *)tmp_node->parent ||
		    tmp->rrsets == NULL) {
			errors++;
			diag("Failed to create node structure");
		}
		dnslib_node_free(&tmp, 0);
	}

	return (errors == 0);
}

static int test_node_add_rrset(list *rrset_list)
{
	dnslib_node_t *tmp;
	dnslib_rrset_t *rrset;
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n, *rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		rrset = rrset_from_test_rrset(test_rrset);
		if (rrset == NULL) {
			diag("Could not create rrset from test data");
			return 0;
		}

		/* create node from test_node structure. Always the first one.*/
		dnslib_dname_t *owner =
			dname_from_test_dname(test_rrset->owner);
		if (owner == NULL) {
			diag("Could not create owner from test data");
			return 0;
		}

		tmp = dnslib_node_new(owner,
		                      NULL);

		if (dnslib_node_add_rrset(tmp, rrset, 0) != 0) {
			errors++;
			diag("Failed to insert rrset into node");
		}

		/* check if rrset is really there */

		const dnslib_rrset_t *rrset_from_node = NULL;
		if ((rrset_from_node =
			     dnslib_node_rrset(tmp, rrset->type)) == NULL) {
			errors++;
			diag("Inserted rrset could not be found");
			continue;
		}

		/* compare rrset from node with original rrset */

		const dnslib_rrtype_descriptor_t *desc =
			dnslib_rrtype_descriptor_by_type(rrset->type);

		int cmp = 0;

		if ((rrset_from_node->rdata == NULL) &&
		    (rrset->rdata == NULL)) {
			cmp = 0;
		} else if ((rrset_from_node->rdata != NULL) &&
			   (rrset->rdata != NULL)) {
			cmp = dnslib_rdata_compare(rrset_from_node->rdata,
						   rrset->rdata,
						   desc->wireformat);
		} else { /* one is not NULL and other is -> error */
			cmp = 1;
		}

		if (!((rrset_from_node->type == rrset->type) &&
		    (rrset_from_node->rclass == rrset->rclass) &&
		    (rrset_from_node->ttl == rrset->ttl) &&
		    (rrset_from_node->rrsigs == rrset->rrsigs) &&
		     (cmp == 0))) {
			errors++;
			diag("Values in found rrset are wrong");
		}

		dnslib_node_free(&tmp, 1);
	}

	return (errors == 0);
}

//static int test_node_get_rrset()
//{
//	dnslib_node_t *tmp;
//	dnslib_rrset_t *rrset;
//	int errors = 0;

//	dnslib_node_t *nodes[TEST_NODES];

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		tmp = dnslib_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);
//		nodes[i] = tmp;
//		for (int j = 0; j < RRSETS; j++) {
//			dnslib_node_add_rrset(tmp, &rrsets[j]);
//		}
//	}

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		for (int j = 0; j < RRSETS; j++) {
//			rrset = &rrsets[j];
//			if (dnslib_node_rrset(nodes[i], rrset->type)
//			    != rrset) {
//				errors++;
//				diag("Failed to get proper rrset from node");
//			}
//		}
//		dnslib_node_free(&nodes[i], 0);
//	}

//	return (errors == 0);
//}

//static int test_node_get_parent()
//{
//	dnslib_node_t *tmp;
//	dnslib_rrset_t *rrset;
//	int errors = 0;

//	dnslib_node_t *nodes[TEST_NODES];

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		tmp = dnslib_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);
//		nodes[i] = tmp;
//		rrset = &rrsets[i];
//		dnslib_node_add_rrset(tmp, rrset);
//	}

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		rrset = &rrsets[i];
//		if (dnslib_node_parent(nodes[i]) != test_nodes[i].parent) {
//			errors++;
//			diag("Failed to get proper parent from node");
//		}
//		dnslib_node_free(&nodes[i], 0);
//	}
//	return (errors == 0);
//}

//static int test_node_sorting()
//{
//	dnslib_node_t *tmp = NULL;
//	dnslib_rrset_t *rrset = NULL;
//	int errors = 0;

//	dnslib_dname_t *owner = dname_from_test_dname(test_nodes[0].owner);

//	tmp = dnslib_node_new(owner,
//	                      (dnslib_node_t *)test_nodes[0].parent);

//	/* Will add rrsets to node. */
//		dnslib_node_add_rrset(tmp, rrset);
//	}

//	const skip_node_t *node = skip_first(tmp->rrsets);

//	int last = *((uint16_t *)node->key);

//	/* TODO there is now an API function dnslib_node_rrsets ... */

//	/* Iterates through skip list and checks, whether it is sorted. */

//	while ((node = skip_next(node)) != NULL) {
//		if (last > *((uint16_t *)node->key)) {
//			errors++;
//			diag("RRset sorting error");
//		}
//		last = *((uint16_t *)node->key);
//	}

//	dnslib_node_free(&tmp, 1);
//	return (errors == 0);
//}

//static int test_node_delete()
//{
//	int errors = 0;

//	dnslib_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		dnslib_dname_t *owner =
//			dname_from_test_dname(test_nodes[i].owner);
//		tmp_node = dnslib_node_new(owner,
//					(dnslib_node_t *)test_nodes[i].parent);

//		dnslib_node_free(&tmp_node, 1);

//		errors += (tmp_node != NULL);
//	}

//	return (errors == 0);
//}

//static int test_node_set_parent()
//{
//	dnslib_node_t *tmp_parent = (dnslib_node_t *)0xABCDEF;
//	int errors = 0;

//	dnslib_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		tmp_node = dnslib_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);

//		dnslib_node_set_parent(tmp_node, tmp_parent);

//		if (tmp_node->parent != tmp_node->parent) {
//			diag("Parent node is wrongly set.");
//			errors++;
//		}
//		dnslib_node_free(&tmp_node, 0);
//	}
//	return (errors == 0);
//}

//static int test_node_free_rrsets()
//{
//	int errors = 0;

//	dnslib_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		dnslib_dname_t *owner =
//			dname_from_test_dname(test_nodes[i].owner);
//		if (owner == NULL) {
//			return 0;
//		}

//		tmp_node = dnslib_node_new(owner,
//				      (dnslib_node_t *)test_nodes[i].parent);

//		dnslib_node_free_rrsets(tmp_node, 0);

//		errors += (tmp_node->rrsets != NULL);

//		dnslib_node_free(&tmp_node, 1);
//	}
//	return (errors == 0);
//}

static const int DNSLIB_NODE_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_node_tests_count(int argc, char *argv[])
{
	return DNSLIB_NODE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_node_tests_run(int argc, char *argv[])
{
	test_data_t *data = data_for_dnslib_tests;
	int res = 0,
	    res_final = 1;

	res = test_node_create(&data->node_list);
	ok(res, "node: create");
	res_final *= res;


	ok((res = test_node_add_rrset(&data->rrset_list)), "node: add");
	res_final *= res;

//	ok((res = test_node_get_rrset()), "node: get");
//	res_final *= res;

//	ok((res = test_node_get_parent()), "node: get parent");
//	res_final *= res;

//	ok((res = test_node_set_parent()), "node: set parent");
//	res_final *= res;

//	ok((res = test_node_sorting()), "node: sort");
//	res_final *= res;

//	ok((res = test_node_free_rrsets()), "node: free rrsets");
//	res_final *= res;

//	endskip;

//	ok((res = test_node_delete()), "node: delete");
//	//res_final *= res;

	return res_final;
}
