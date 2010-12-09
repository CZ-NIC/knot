#include "tap_unit.h"

#include "common.h"
#include "zone.h"
#include "node.h"

static int dnslib_zone_tests_count(int argc, char *argv[]);
static int dnslib_zone_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api dnslib_zone_tests_api = {
	"DNS library - zone",        //! Unit name
	&dnslib_zone_tests_count,  //! Count scheduled tests
	&dnslib_zone_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

enum { TEST_NODES_GOOD = 2, TEST_NODES_BAD = 1 };

struct zone_test_node {
	dnslib_dname_t owner;
	dnslib_node_t *parent;
};

static struct zone_test_node test_apex =
	{{(uint8_t *)"\3com\0", 5}, (dnslib_node_t *)NULL};

static struct zone_test_node test_nodes_bad[TEST_NODES_BAD] = {
	{{(uint8_t *)"\5other\6domain\0", 14}, (dnslib_node_t *)NULL}
};

static struct zone_test_node test_nodes_good[TEST_NODES_GOOD] = {
	{{(uint8_t *)"\3www\7example\3com\0", 17}, (dnslib_node_t *)NULL},
	{{(uint8_t *)"\7another\6domain\3com\0", 20}, (dnslib_node_t *)NULL},
};

static int test_zone_check_node(const dnslib_node_t *node,
                                const struct zone_test_node *test_node)
{
	return (node->owner == &test_node->owner
	        && node->parent == test_node->parent);
}

static int test_zone_create(dnslib_zone_t **zone)
{
	dnslib_node_t *node = dnslib_node_new(&test_apex.owner,
	                                      test_apex.parent);
	if (node == NULL) {
		diag("zone: Could not create zone apex.");
		return 0;
	}

	*zone = dnslib_zone_new(node);

	if ((*zone) == NULL) {
		diag("zone: Failed to create zone.");
		return 0;
	}

	if ((*zone)->apex != node) {
		diag("zone: Zone apex not set right.");
		return 0;
	}

	return 1;
}

static int test_zone_add_node(dnslib_zone_t *zone)
{
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

		//note("Node created");

		if ((res = dnslib_zone_add_node(zone, node)) != 0) {
			diag("zone: Failed to insert node into zone (returned"
			     " %d).", res);
			dnslib_node_free(&node);
			++errors;
		}
	}

	//note("Bad nodes");

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		dnslib_node_t *node = dnslib_node_new(&test_nodes_bad[i].owner,
		                                    test_nodes_bad[i].parent);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if ((res = dnslib_zone_add_node(zone, node)) != -2) {
			diag("zone: Inserting wrong node did not result in"
			     "proper return value (%d instead of -2).", res);
			++errors;
		}
		dnslib_node_free(&node);
	}

	//note("NULL zone");

	dnslib_node_t *node = dnslib_node_new(&test_nodes_good[0].owner,
	                                      test_nodes_good[0].parent);
	if (node == NULL) {
		diag("zone: Could not create node.");
		return 0;
	}

	if ((res = dnslib_zone_add_node(NULL, node)) != -1) {
		diag("zone: Inserting node to NULL zone did not result in"
		     "proper return value (%d instead of -1)", res);
		++errors;
	}

	dnslib_node_free(&node);

	//note("NULL node");

	if ((res = dnslib_zone_add_node(zone, NULL)) != -1) {
		diag("zone: Inserting NULL node to zone did not result in"
		     "proper return value (%d instead of -1)", res);
		++errors;
	}

	node = dnslib_node_new(&test_apex.owner, test_apex.parent);
	if (node == NULL) {
		diag("zone: Could not create node.");
		return 0;
	}

	//note("Apex again");

	if ((res = dnslib_zone_add_node(zone, node)) != -2) {
		diag("zone: Inserting zone apex again did not result in proper"
		     "return value (%d instead of -2)", res);
		++errors;
	}

	dnslib_node_free(&node);

	// check if all nodes are inserted
	//int nodes = 0;
	if (!test_zone_check_node(dnslib_zone_apex(zone), &test_apex)) {
		diag("zone: Apex of zone not right.");
		++errors;
	}
	//++nodes;
	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		const dnslib_node_t *tmp =
			dnslib_zone_find_node(zone, &test_nodes_good[i].owner);
		if (tmp == NULL) {
			diag("zone: Missing node with owner %s",
			     test_nodes_good[i].owner.name);
			++errors;
			continue;
		}

		if (!test_zone_check_node(tmp, &test_nodes_good[i])) {
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

static int test_zone_get_node(dnslib_zone_t *zone)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (dnslib_zone_get_node(zone, &test_nodes_good[i].owner)
			== NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (dnslib_zone_get_node(zone, &test_nodes_bad[i].owner)
			!= NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (dnslib_zone_get_node(NULL, &test_nodes_good[0].owner) != NULL) {
		diag("zone: Getting node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (dnslib_zone_get_node(zone, NULL) != NULL) {
		diag("zone: Getting node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (dnslib_zone_get_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Getting zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

static int test_zone_find_node(dnslib_zone_t *zone)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (dnslib_zone_find_node(zone, &test_nodes_good[i].owner)
			== NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (dnslib_zone_find_node(zone, &test_nodes_bad[i].owner)
			!= NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (dnslib_zone_find_node(NULL, &test_nodes_good[0].owner) != NULL) {
		diag("zone: Finding node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (dnslib_zone_find_node(zone, NULL) != NULL) {
		diag("zone: Finding node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (dnslib_zone_find_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Finding zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

static int test_zone_free(dnslib_zone_t **zone)
{
	dnslib_zone_free(zone, 1);
	return (*zone == NULL);
}

static const int DNSLIB_ZONE_TEST_COUNT = 5;

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
	res_final += res;

	//skip(!res, 3);

	ok((res = test_zone_add_node(zone)), "zone: add node");
	res_final += res;

	skip(!res, 2);

	ok((res = test_zone_get_node(zone)), "zone: get node");
	res_final += res;

	skip(!res, 1);

	ok((res = test_zone_find_node(zone)), "zone: find node");
	res_final += res;

	endskip; // get node failed

	endskip; // add node failed

	ok((res = test_zone_free(&zone)), "zone: free");
	res_final += res;

	//endskip; // create failed

	return res_final;
}
