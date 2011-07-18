#include <assert.h>

#include "dnslib/tests/dnslib/zone_tests.h"
#include "dnslib/tests/dnslib_tests_loader.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/zone.h"
#include "dnslib/error.h"
#include "dnslib/node.h"

static int dnslib_zone_tests_count(int argc, char *argv[]);
static int dnslib_zone_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api zone_tests_api = {
	"DNS library - zone",        //! Unit name
	&dnslib_zone_tests_count,  //! Count scheduled tests
	&dnslib_zone_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

extern dnslib_dname_t *dname_from_test_dname(test_dname_t *test_dname);
extern dnslib_rrset_t *rrset_from_test_rrset(test_rrset_t *test_rrset);

static dnslib_node_t *node_from_test_node(const test_node_t *test_node)
{
	dnslib_dname_t *owner = dname_from_test_dname(test_node->owner);
	/* TODO parent? */
	dnslib_node_t *new_node = dnslib_node_new(owner, NULL);
	node *n = NULL;
	WALK_LIST(n, test_node->rrset_list) {
		test_rrset_t *test_rrset = (test_rrset_t *)n;
		dnslib_rrset_t *rrset = rrset_from_test_rrset(test_rrset);
		assert(rrset);
		assert(dnslib_node_add_rrset(new_node, rrset) == 0);
	}

	return new_node;
}

static int test_zone_create(list node_list)
{
//	dnslib_dname_t *dname = dnslib_dname_new_from_wire(
//		test_apex.owner.name, test_apex.owner.size, NULL);
//	assert(dname);
	int errors = 0;

	node *n = NULL;
	WALK_LIST(n, node_list) {
		test_node_t *test_node = (test_node_t *)n;
		dnslib_node_t *node = node_from_test_node(test_node);
		assert(node);

		dnslib_zone_t *zone = dnslib_zone_new(node, 0);
		if (zone == NULL) {
			diag("Could not create zone with owner: %s\n",
			     test_node->owner->str);
			errors++;
		}
		dnslib_node_free_rrsets(node, 1);
		dnslib_node_free(&node, 0);
	}

	return (errors == 0);
}

//static int test_zone_add_node(dnslib_zone_t *zone, int nsec3)
//{
//	/*
//	 * NSEC3 nodes are de facto identical to normal nodes, so there is no
//	 * need for separate tests. The only difference is where are they stored
//	 * in the zone structure.
//	 */

//	int errors = 0;
//	int res = 0;

//	//note("Good nodes");

//	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
//		dnslib_node_t *node = dnslib_node_new(&test_nodes_good[i].owner,
//		                                     test_nodes_good[i].parent);
//		if (node == NULL) {
//			diag("zone: Could not create node.");
//			return 0;
//		}

//		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node)
//		                   : dnslib_zone_add_node(zone, node))) != 0) {
//			diag("zone: Failed to insert node into zone (returned"
//			     " %d).", res);
//			dnslib_node_free(&node, 0);
//			++errors;
//		}
//		/* TODO check values in the node as well */
//	}

//	//note("Bad nodes");

//	for (int i = 0; i < TEST_NODES_BAD; ++i) {
//		dnslib_node_t *node = dnslib_node_new(&test_nodes_bad[i].owner,
//		                                    test_nodes_bad[i].parent);
//		if (node == NULL) {
//			diag("zone: Could not create node.");
//			return 0;
//		}

//		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node)
//			: dnslib_zone_add_node(zone, node))) !=
//		                DNSLIB_EBADZONE) {
//			diag("zone: Inserting wrong node did not result in"
//			     "proper return value (%d instead of %d).", res,
//			     DNSLIB_EBADZONE);
//			++errors;
//		}
//		dnslib_node_free(&node, 0);
//	}

//	// check if all nodes are inserted
//	//int nodes = 0;
//	if (!nsec3
//	    && !test_zone_check_node(dnslib_zone_apex(zone), &test_apex)) {
//		diag("zone: Apex of zone not right.");
////		diag("Apex owner: %s (%p), apex parent: %p\n",
////		     dnslib_dname_to_str(dnslib_zone_apex(zone)->owner),
////		     dnslib_zone_apex(zone)->owner,
////		     dnslib_zone_apex(zone)->parent);
////		diag("Should be: owner: %s (%p), parent: %p\n",
////		     dnslib_dname_to_str(&test_apex.owner),
////		     &test_apex.owner,
////		     test_apex.parent);
//		++errors;
//	}
//	//++nodes;
//	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
//		const dnslib_node_t *n = ((nsec3) ? dnslib_zone_find_nsec3_node(
//				zone, &test_nodes_good[i].owner) :
//			dnslib_zone_find_node(zone, &test_nodes_good[i].owner));
//		if (n == NULL) {
//			diag("zone: Missing node with owner %s",
//			     test_nodes_good[i].owner.name);
//			++errors;
//			continue;
//		}

//		if (!test_zone_check_node(n, &test_nodes_good[i])) {
//			diag("zone: Node does not match: owner: %s (should be "
//			     "%s), parent: %p (should be %p)",
//			     node->owner->name, test_nodes_good[i].owner.name,
//			     node->parent, test_nodes_good[i].parent);
//			++errors;
//		}
//		//++nodes;
//	}

//	//note("zone: %d nodes in the zone (including apex)", nodes);

//	return (errors == 0);
//}

//static int test_zone_get_node(dnslib_zone_t *zone, int nsec3)
//{
//	int errors = 0;

//	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
//		if (((nsec3) ? dnslib_zone_get_nsec3_node(
//		                   zone, &test_nodes_good[i].owner)
//			: dnslib_zone_get_node(zone, &test_nodes_good[i].owner))
//			== NULL) {
//			diag("zone: Node (%s) not found in zone.",
//			     (char *)test_nodes_good[i].owner.name);
//			++errors;
//		}
//	}

//	for (int i = 0; i < TEST_NODES_BAD; ++i) {
//		if (((nsec3) ? dnslib_zone_get_nsec3_node(
//		                   zone, &test_nodes_bad[i].owner)
//			: dnslib_zone_get_node(zone, &test_nodes_bad[i].owner))
//			!= NULL) {
//			diag("zone: Node (%s) found in zone even if it should"
//			     "not be there.",
//			     (char *)test_nodes_bad[i].owner.name);
//			++errors;
//		}
//	}

//	if (((nsec3)
//	     ? dnslib_zone_get_nsec3_node(NULL, &test_nodes_good[0].owner)
//	     : dnslib_zone_get_node(NULL, &test_nodes_good[0].owner)) != NULL) {
//		diag("zone: Getting node from NULL zone did not result in"
//		     "proper return value (NULL)");
//		++errors;
//	}

//	if (((nsec3) ? dnslib_zone_get_nsec3_node(zone, NULL)
//	             : dnslib_zone_get_node(zone, NULL)) != NULL) {
//		diag("zone: Getting node with NULL owner from zone did not "
//		     "result in proper return value (NULL)");
//		++errors;
//	}

//	if (!nsec3 && dnslib_zone_get_node(zone, &test_apex.owner) == NULL) {
//		diag("zone: Getting zone apex from the zone failed");
//		++errors;
//	}

//	return (errors == 0);
//}

//static int test_zone_find_node(dnslib_zone_t *zone, int nsec3)
//{
//	int errors = 0;

//	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
//		if (((nsec3) ? dnslib_zone_find_nsec3_node(
//		                   zone, &test_nodes_good[i].owner)
//		    : dnslib_zone_find_node(zone, &test_nodes_good[i].owner))
//		    == NULL) {
//			diag("zone: Node (%s) not found in zone.",
//			     (char *)test_nodes_good[i].owner.name);
//			++errors;
//		}
//	}

//	for (int i = 0; i < TEST_NODES_BAD; ++i) {
//		if (((nsec3) ? dnslib_zone_find_nsec3_node(
//		                   zone, &test_nodes_bad[i].owner)
//		    : dnslib_zone_find_node(zone, &test_nodes_bad[i].owner))
//		    != NULL) {
//			diag("zone: Node (%s) found in zone even if it should"
//			     "not be there.",
//			     (char *)test_nodes_bad[i].owner.name);
//			++errors;
//		}
//	}

//	if (((nsec3)
//	    ? dnslib_zone_find_nsec3_node(NULL, &test_nodes_good[0].owner)
//	    : dnslib_zone_find_node(NULL, &test_nodes_good[0].owner)) != NULL) {
//		diag("zone: Finding node from NULL zone did not result in"
//		     "proper return value (NULL)");
//		++errors;
//	}

//	if (((nsec3) ? dnslib_zone_find_nsec3_node(zone, NULL)
//	             : dnslib_zone_find_node(zone, NULL)) != NULL) {
//		diag("zone: Finding node with NULL owner from zone did not "
//		     "result in proper return value (NULL)");
//		++errors;
//	}

//	if (!nsec3 && dnslib_zone_find_node(zone, &test_apex.owner) == NULL) {
//		diag("zone: Finding zone apex from the zone failed");
//		++errors;
//	}

//	return (errors == 0);
//}

static const int DNSLIB_ZONE_TEST_COUNT = 1;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int dnslib_zone_tests_count(int argc, char *argv[])
{
	return DNSLIB_ZONE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int dnslib_zone_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 0;

	test_data_t *data = data_for_dnslib_tests;

	ok((res = test_zone_create(data->node_list)), "zone: create");
	res_final *= res;

//	skip(!res, 6);

//	ok((res = test_zone_add_node(zone, 0)), "zone: add node");
//	res_final *= res;

//	skip(!res, 2);

//	skip(!res, 1);

//	ok((res = test_zone_find_node(zone, 0)), "zone: find node");
//	res_final *= res;

//	endskip; // get node failed

//	endskip; // add node failed

//	ok((res = test_zone_add_node(zone, 1)), "zone: add nsec3 node");
//	res_final *= res;

//	skip(!res, 2);

//	skip(!res, 1);

//	ok((res = test_zone_find_node(zone, 1)), "zone: find nsec3 node");
//	res_final *= res;

//	endskip; // get nsec3 node failed

//	endskip; // add nsec3 node failed

//	endskip; // create failed

	return res_final;
}
