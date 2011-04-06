#include <assert.h>

#include "dnslib/tests/dnslib/zone_tests.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/zone.h"
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

enum { TEST_NODES_GOOD = 7, TEST_NODES_BAD = 1, TRAVERSAL_TYPES = 3};

struct zone_test_node {
	dnslib_dname_t owner;
	dnslib_node_t *parent;
};

static struct zone_test_node test_apex =
{{(uint8_t *)"\3com\0", 5, (uint8_t *)"\x0", 1}, (dnslib_node_t *)NULL};

static struct zone_test_node test_nodes_bad[TEST_NODES_BAD] = {
	{{(uint8_t *)"\5other\6domain\0", 14, (uint8_t *)"\x0\x6", 2},
	 (dnslib_node_t *)NULL}
};

static struct zone_test_node test_nodes_good[TEST_NODES_GOOD] = {
	{{(uint8_t *)"\7example\3com\0", 13, (uint8_t *)"\x0\x8", 2},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\3www\7example\3com\0", 17, (uint8_t *)"\x0\x4\xC", 3},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\7another\6domain\3com\0", 20, (uint8_t *)"\x0\x8\xF", 3},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\5mail1\7example\3com\0", 19, (uint8_t *)"\x0\x6\xE", 3},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\5mail2\7example\3com\0", 19, (uint8_t *)"\x0\x6\xE", 3},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\3smb\7example\3com\0", 17, (uint8_t *)"\x0\x4\xC", 3},
	 (dnslib_node_t *)NULL},
	{{(uint8_t *)"\4smtp\7example\3com\0", 18, (uint8_t *)"\x0\x5\xD", 3},
	 (dnslib_node_t *)NULL},
};

static int test_zone_check_node(const dnslib_node_t *node,
                                const struct zone_test_node *test_node)
{
	return (node->owner == &test_node->owner
	        && node->parent == test_node->parent);
}

static int test_zone_create(dnslib_zone_t **zone)
{
//	dnslib_dname_t *dname = dnslib_dname_new_from_wire(
//		test_apex.owner.name, test_apex.owner.size, NULL);
//	assert(dname);

	dnslib_node_t *node = dnslib_node_new(&test_apex.owner,
	                                      test_apex.parent);
	if (node == NULL) {
		diag("zone: Could not create zone apex.");
		return 0;
	}

	*zone = dnslib_zone_new(node, 0);

	if ((*zone) == NULL) {
		diag("zone: Failed to create zone.");
		dnslib_node_free(&node, 1);
		return 0;
	}

	if ((*zone)->apex != node) {
		diag("zone: Zone apex not set right.");
		dnslib_node_free(&node, 1);
		return 0;
	}

	return 1;
}

static int test_zone_add_node(dnslib_zone_t *zone, int nsec3)
{
	/*
	 * NSEC3 nodes are de facto identical to normal nodes, so there is no
	 * need for separate tests. The only difference is where are they stored
	 * in the zone structure.
	 */

	int errors = 0;
	int res = 0;

	//note("Good nodes");

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		dnslib_node_t *node = dnslib_node_new(&test_nodes_good[i].owner,
		                                     test_nodes_good[i].parent);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node)
		                   : dnslib_zone_add_node(zone, node))) != 0) {
			diag("zone: Failed to insert node into zone (returned"
			     " %d).", res);
			dnslib_node_free(&node, 0);
			++errors;
		}
		/* TODO check values in the node as well */
	}

	//note("Bad nodes");

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		dnslib_node_t *node = dnslib_node_new(&test_nodes_bad[i].owner,
		                                    test_nodes_bad[i].parent);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node)
			: dnslib_zone_add_node(zone, node))) != -2) {
			diag("zone: Inserting wrong node did not result in"
			     "proper return value (%d instead of -2).", res);
			++errors;
		}
		dnslib_node_free(&node, 0);
	}

	//note("NULL zone");

	note("Inserting into NULL zone...\n");

	dnslib_node_t *node = dnslib_node_new(&test_nodes_good[0].owner,
	                                      test_nodes_good[0].parent);
	if (node == NULL) {
		diag("zone: Could not create node.");
		return 0;
	}

	if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(NULL, node)
		: dnslib_zone_add_node(NULL, node))) != -1) {
		diag("zone: Inserting node to NULL zone did not result in"
		     "proper return value (%d instead of -1)", res);
		++errors;
	}

	dnslib_node_free(&node, 0);

	//note("NULL node");
	note("Inserting NULL node...\n");

	if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, NULL)
		: dnslib_zone_add_node(zone, NULL))) != -1) {
		diag("zone: Inserting NULL node to zone did not result in"
		     "proper return value (%d instead of -1)", res);
		++errors;
	}

	if (!nsec3) {
		//note("Inserting Apex again...\n");

		node = dnslib_node_new(&test_apex.owner, test_apex.parent);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		//note("Apex again");

		if ((res = dnslib_zone_add_node(zone, node)) != -2) {
			diag("zone: Inserting zone apex again did not result in"
			     "proper return value (%d instead of -2)", res);
			++errors;
		}

		dnslib_node_free(&node, 0);
	}

	// check if all nodes are inserted
	//int nodes = 0;
	if (!nsec3
	    && !test_zone_check_node(dnslib_zone_apex(zone), &test_apex)) {
		diag("zone: Apex of zone not right.");
//		diag("Apex owner: %s (%p), apex parent: %p\n",
//		     dnslib_dname_to_str(dnslib_zone_apex(zone)->owner),
//		     dnslib_zone_apex(zone)->owner,
//		     dnslib_zone_apex(zone)->parent);
//		diag("Should be: owner: %s (%p), parent: %p\n",
//		     dnslib_dname_to_str(&test_apex.owner),
//		     &test_apex.owner,
//		     test_apex.parent);
		++errors;
	}
	//++nodes;
	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		const dnslib_node_t *n = ((nsec3) ? dnslib_zone_find_nsec3_node(
				zone, &test_nodes_good[i].owner) :
			dnslib_zone_find_node(zone, &test_nodes_good[i].owner));
		if (n == NULL) {
			diag("zone: Missing node with owner %s",
			     test_nodes_good[i].owner.name);
			++errors;
			continue;
		}

		if (!test_zone_check_node(n, &test_nodes_good[i])) {
			diag("zone: Node does not match: owner: %s (should be "
			     "%s), parent: %p (should be %p)",
			     node->owner->name, test_nodes_good[i].owner.name,
			     node->parent, test_nodes_good[i].parent);
			++errors;
		}
		//++nodes;
	}

	//note("zone: %d nodes in the zone (including apex)", nodes);

	return (errors == 0);
}

static int test_zone_get_node(dnslib_zone_t *zone, int nsec3)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (((nsec3) ? dnslib_zone_get_nsec3_node(
		                   zone, &test_nodes_good[i].owner)
			: dnslib_zone_get_node(zone, &test_nodes_good[i].owner))
			== NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (((nsec3) ? dnslib_zone_get_nsec3_node(
		                   zone, &test_nodes_bad[i].owner)
			: dnslib_zone_get_node(zone, &test_nodes_bad[i].owner))
			!= NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (((nsec3)
	     ? dnslib_zone_get_nsec3_node(NULL, &test_nodes_good[0].owner)
	     : dnslib_zone_get_node(NULL, &test_nodes_good[0].owner)) != NULL) {
		diag("zone: Getting node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (((nsec3) ? dnslib_zone_get_nsec3_node(zone, NULL)
	             : dnslib_zone_get_node(zone, NULL)) != NULL) {
		diag("zone: Getting node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (!nsec3 && dnslib_zone_get_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Getting zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

static int test_zone_find_node(dnslib_zone_t *zone, int nsec3)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (((nsec3) ? dnslib_zone_find_nsec3_node(
		                   zone, &test_nodes_good[i].owner)
		    : dnslib_zone_find_node(zone, &test_nodes_good[i].owner))
		    == NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (((nsec3) ? dnslib_zone_find_nsec3_node(
		                   zone, &test_nodes_bad[i].owner)
		    : dnslib_zone_find_node(zone, &test_nodes_bad[i].owner))
		    != NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (((nsec3)
	    ? dnslib_zone_find_nsec3_node(NULL, &test_nodes_good[0].owner)
	    : dnslib_zone_find_node(NULL, &test_nodes_good[0].owner)) != NULL) {
		diag("zone: Finding node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (((nsec3) ? dnslib_zone_find_nsec3_node(zone, NULL)
	             : dnslib_zone_find_node(zone, NULL)) != NULL) {
		diag("zone: Finding node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (!nsec3 && dnslib_zone_find_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Finding zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

static void test_zone_destroy_node_from_tree(dnslib_node_t *node,
                                             void *data)
{
	UNUSED(data);
	dnslib_node_free(&node, 0);
}

/* explained below */
static size_t node_index = 0;

/*! \brief
 * This function will overwrite parent field in node structure -
 * we don't (and can't, with current structures) use it in these tests anyway.
 * Since zone structure itself has no count field, only option known to me
 * is (sadly) to use a global variable.
 */
static void tmp_apply_function(dnslib_node_t *node, void *data)
{
	node->parent = (dnslib_node_t *)node_index;
	node_index++;
}

/* \note Since I am unaware of a way how to get a return value from traversal
 * functions, I will use (hopefully for the last time here) global variable
 */

static int compare_ok = 1;

static void tmp_compare_function(dnslib_node_t *node, void *data)
{
	/* node_index will start set to zero */
	if (node->parent != (dnslib_node_t *)node_index) {
		compare_ok = 0;
		return;
	} else if (!compare_ok) {
		diag("Traversal function has partially set values right");
	}
	node_index++;
}

static int test_zone_tree_apply(dnslib_zone_t *zone,
                                int type, int nsec3)
{

	assert(node_index == 0);
	assert(compare_ok == 1);

	void (*traversal_func)(dnslib_zone_t *zone,
	                       void (*function)(dnslib_node_t *node,
	                                        void *data),
	                       void *data);

	switch (type) {
		case 0: {
			if (nsec3) {
				traversal_func =
					&dnslib_zone_nsec3_apply_postorder;
				diag("Testing postorder traversal");
			} else {
				traversal_func =
					&dnslib_zone_tree_apply_postorder;
				diag("Testing postorder traversal - NSEC3");
			}
			break;
		}
		case 1: {
			if (nsec3) {
				traversal_func =
					&dnslib_zone_nsec3_apply_inorder;
				diag("Testing inorder traversal");
			} else {
				traversal_func =
					&dnslib_zone_tree_apply_inorder;
				diag("Testing inorder traversal - NSEC3");
			}
			break;
		}
		case 2: {
			if (nsec3) {
				traversal_func =
				&dnslib_zone_nsec3_apply_inorder_reverse;
				diag("Testing inorder reverse traversal");
			} else {
				traversal_func =
				&dnslib_zone_tree_apply_inorder_reverse;
				diag("Testing inorder reverse "
				     "traversal - NSEC3");
			}
			break;
		}
		default: {
			diag("Unknown traversal function type");
			return 0;
		}
	}

	/*
	 * This will iterate through tree and set node->parent field values
	 * from 0 to number of nodes.
	 */

	traversal_func(zone, &tmp_apply_function, NULL);

	node_index = 0;

	/*
	 * This will check whether the values were set accordingly.
	 */

	traversal_func(zone, &tmp_compare_function, NULL);

	int ret = compare_ok;

	compare_ok = 1;
	node_index = 0;

	return (ret);
}

/* Tests all kinds of zone traversals, explainded above */
static int test_zone_traversals(dnslib_zone_t *zone)
{
	for (int i = 0; i < TRAVERSAL_TYPES; i++) {
		for (int j = 0; j < 2; j++) {
			if (!test_zone_tree_apply(zone, i, j)) {
				return 0;
			}
		}
	}
	return 1;
}

static int test_zone_free(dnslib_zone_t **zone)
{
	dnslib_zone_tree_apply_postorder(*zone,
	                                 test_zone_destroy_node_from_tree,
	                                 NULL);
	dnslib_zone_nsec3_apply_postorder(*zone,
	                                 test_zone_destroy_node_from_tree,
	                                 NULL);
	dnslib_zone_free(zone);
	return (*zone == NULL);
}

static const int DNSLIB_ZONE_TEST_COUNT = 9;

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

	dnslib_zone_t *zone = NULL;

	ok((res = test_zone_create(&zone)), "zone: create");
	res_final *= res;

	skip(!res, 6);

	ok((res = test_zone_add_node(zone, 0)), "zone: add node");
	res_final *= res;

	skip(!res, 2);

	ok((res = test_zone_get_node(zone, 0)), "zone: get node");
	res_final *= res;

	skip(!res, 1);

	ok((res = test_zone_find_node(zone, 0)), "zone: find node");
	res_final *= res;

	endskip; // get node failed

	endskip; // add node failed

	ok((res = test_zone_add_node(zone, 1)), "zone: add nsec3 node");
	res_final *= res;

	skip(!res, 2);

	ok((res = test_zone_get_node(zone, 1)), "zone: get nsec3 node");
	res_final *= res;

	skip(!res, 1);

	ok((res = test_zone_find_node(zone, 1)), "zone: find nsec3 node");
	res_final *= res;

	endskip; // get nsec3 node failed

	endskip; // add nsec3 node failed

	ok(res = test_zone_traversals(zone), "zone: traversals");
	res_final *= res;

	ok((res = test_zone_free(&zone)), "zone: free");
	res_final *= res;

	endskip; // create failed

	return res_final;
}
