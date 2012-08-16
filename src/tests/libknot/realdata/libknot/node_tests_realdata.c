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

#include "tests/libknot/realdata/libknot/node_tests_realdata.h"
#include "tests/libknot/realdata/libknot_tests_loader_realdata.h"
#include "libknot/dname.h"
#include "libknot/zone/node.h"
#include "libknot/util/descriptor.h"

static int knot_node_tests_count(int argc, char *argv[]);
static int knot_node_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api node_tests_api = {
	"DNS library - node",       //! Unit name
	&knot_node_tests_count,  //! Count scheduled tests
	&knot_node_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

/* TODO It would be wise not to name variables totally same as structures ... */
knot_dname_t *dname_from_test_dname(const test_dname_t *test_dname)
{
	assert(test_dname != NULL);
	knot_dname_t *ret = knot_dname_new_from_wire(test_dname->wire,
	                                                 test_dname->size,
	                                                 NULL);
	CHECK_ALLOC(ret, NULL);

	return ret;
}

static knot_rrset_t *rrset_from_test_rrset(const test_rrset_t *test_rrset)
{
	assert(test_rrset != NULL);
	knot_dname_t *owner = dname_from_test_dname(test_rrset->owner);
	CHECK_ALLOC(owner, NULL);

	knot_rrset_t *ret = knot_rrset_new(owner, test_rrset->type,
	                                       test_rrset->rclass,
	                                       test_rrset->ttl);
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&owner);
		return NULL;
	}

	return ret;
}

static int test_node_create(const list *node_list)
{
	/* Tests creation of node by comparing with test_node struct */
	knot_node_t *tmp;
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n, *node_list) {
		const test_node_t *tmp_node = (test_node_t *)n;
		assert(tmp_node);

		knot_dname_t *owner =
			dname_from_test_dname(tmp_node->owner);
		if (owner == NULL) {
			return 0;
		}
		tmp = knot_node_new(owner,
				      (knot_node_t *)tmp_node->parent, 0);
		if (tmp == NULL ||
		    (strncmp((char *)tmp->owner->name,
		             (char *)tmp_node->owner->wire,
		             tmp->owner->size) != 0) ||
		    tmp->parent != (knot_node_t *)tmp_node->parent ||
		    tmp->rrset_tree == NULL) {
			errors++;
			diag("Failed to create node structure");
		}
		knot_node_free(&tmp);
	}

	return (errors == 0);
}

static int test_node_add_rrset(list *rrset_list)
{
	knot_node_t *tmp;
	knot_rrset_t *rrset;
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
		knot_dname_t *owner =
			dname_from_test_dname(test_rrset->owner);
		if (owner == NULL) {
			diag("Could not create owner from test data");
			return 0;
		}

		tmp = knot_node_new(owner, NULL, 0);

		if (knot_node_add_rrset(tmp, rrset, 0) != 0) {
			errors++;
			diag("Failed to insert rrset into node");
		}

		/* check if rrset is really there */

		const knot_rrset_t *rrset_from_node = NULL;
		if ((rrset_from_node =
			     knot_node_rrset(tmp, rrset->type)) == NULL) {
			errors++;
			diag("Inserted rrset could not be found");
			continue;
		}

		/* compare rrset from node with original rrset */

		const knot_rrtype_descriptor_t *desc =
			knot_rrtype_descriptor_by_type(rrset->type);

		int cmp = 0;

		if ((rrset_from_node->rdata == NULL) &&
		    (rrset->rdata == NULL)) {
			cmp = 0;
		} else if ((rrset_from_node->rdata != NULL) &&
			   (rrset->rdata != NULL)) {
			cmp = knot_rdata_compare(rrset_from_node->rdata,
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

		knot_node_free(&tmp);
	}

	return (errors == 0);
}

//static int test_node_get_rrset()
//{
//	knot_node_t *tmp;
//	knot_rrset_t *rrset;
//	int errors = 0;

//	knot_node_t *nodes[TEST_NODES];

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		tmp = knot_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);
//		nodes[i] = tmp;
//		for (int j = 0; j < RRSETS; j++) {
//			knot_node_add_rrset(tmp, &rrsets[j]);
//		}
//	}

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		for (int j = 0; j < RRSETS; j++) {
//			rrset = &rrsets[j];
//			if (knot_node_rrset(nodes[i], rrset->type)
//			    != rrset) {
//				errors++;
//				diag("Failed to get proper rrset from node");
//			}
//		}
//		knot_node_free(&nodes[i], 0);
//	}

//	return (errors == 0);
//}

//static int test_node_get_parent()
//{
//	knot_node_t *tmp;
//	knot_rrset_t *rrset;
//	int errors = 0;

//	knot_node_t *nodes[TEST_NODES];

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		tmp = knot_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);
//		nodes[i] = tmp;
//		rrset = &rrsets[i];
//		knot_node_add_rrset(tmp, rrset);
//	}

//	for (int i = 0; i < TEST_NODES && !errors; i++) {
//		rrset = &rrsets[i];
//		if (knot_node_parent(nodes[i]) != test_nodes[i].parent) {
//			errors++;
//			diag("Failed to get proper parent from node");
//		}
//		knot_node_free(&nodes[i], 0);
//	}
//	return (errors == 0);
//}

//static int test_node_sorting()
//{
//	knot_node_t *tmp = NULL;
//	knot_rrset_t *rrset = NULL;
//	int errors = 0;

//	knot_dname_t *owner = dname_from_test_dname(test_nodes[0].owner);

//	tmp = knot_node_new(owner,
//	                      (knot_node_t *)test_nodes[0].parent);

//	/* Will add rrsets to node. */
//		knot_node_add_rrset(tmp, rrset);
//	}

//	const skip_node_t *node = skip_first(tmp->rrsets);

//	int last = *((uint16_t *)node->key);

//	/* TODO there is now an API function knot_node_rrsets ... */

//	/* Iterates through skip list and checks, whether it is sorted. */

//	while ((node = skip_next(node)) != NULL) {
//		if (last > *((uint16_t *)node->key)) {
//			errors++;
//			diag("RRset sorting error");
//		}
//		last = *((uint16_t *)node->key);
//	}

//	knot_node_free(&tmp, 1);
//	return (errors == 0);
//}

//static int test_node_delete()
//{
//	int errors = 0;

//	knot_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		knot_dname_t *owner =
//			dname_from_test_dname(test_nodes[i].owner);
//		tmp_node = knot_node_new(owner,
//					(knot_node_t *)test_nodes[i].parent);

//		knot_node_free(&tmp_node, 1);

//		errors += (tmp_node != NULL);
//	}

//	return (errors == 0);
//}

//static int test_node_set_parent()
//{
//	knot_node_t *tmp_parent = (knot_node_t *)0xABCDEF;
//	int errors = 0;

//	knot_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		tmp_node = knot_node_new(&test_nodes[i].owner,
//				      test_nodes[i].parent);

//		knot_node_set_parent(tmp_node, tmp_parent);

//		if (tmp_node->parent != tmp_node->parent) {
//			diag("Parent node is wrongly set.");
//			errors++;
//		}
//		knot_node_free(&tmp_node, 0);
//	}
//	return (errors == 0);
//}

//static int test_node_free_rrsets()
//{
//	int errors = 0;

//	knot_node_t *tmp_node;

//	for (int i = 0; i < TEST_NODES; i++) {
//		knot_dname_t *owner =
//			dname_from_test_dname(test_nodes[i].owner);
//		if (owner == NULL) {
//			return 0;
//		}

//		tmp_node = knot_node_new(owner,
//				      (knot_node_t *)test_nodes[i].parent);

//		knot_node_free_rrsets(tmp_node, 0);

//		errors += (tmp_node->rrsets != NULL);

//		knot_node_free(&tmp_node, 1);
//	}
//	return (errors == 0);
//}

static const int KNOT_NODE_TEST_COUNT = 2;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_node_tests_count(int argc, char *argv[])
{
	return KNOT_NODE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_node_tests_run(int argc, char *argv[])
{
	test_data_t *data = data_for_knot_tests;
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
