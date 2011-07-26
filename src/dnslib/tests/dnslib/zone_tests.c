#include <assert.h>

#include "dnslib/tests/dnslib/zone_tests.h"
#include "dnslib/dnslib-common.h"
#include "dnslib/dname-table.h"
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

	*zone = dnslib_zone_new(node, 0, 1);

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

		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node, 0, 1)
		                   : dnslib_zone_add_node(zone, node, 0, 1))) != 0) {
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

		if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, node, 0, 1)
			: dnslib_zone_add_node(zone, node, 0, 1))) !=
		                DNSLIB_EBADZONE) {
			diag("zone: Inserting wrong node did not result in"
			     "proper return value (%d instead of %d).", res,
			     DNSLIB_EBADZONE);
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

	if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(NULL, node, 0, 1)
		: dnslib_zone_add_node(NULL, node, 0, 1))) != DNSLIB_EBADARG) {
		diag("zone: Inserting node to NULL zone did not result in"
		     "proper return value (%d instead of %d)", res,
		     DNSLIB_EBADARG);
		++errors;
	}

	dnslib_node_free(&node, 0);

	//note("NULL node");
	note("Inserting NULL node...\n");

	if ((res = ((nsec3) ? dnslib_zone_add_nsec3_node(zone, NULL, 0, 1)
		: dnslib_zone_add_node(zone, NULL, 0, 1))) != DNSLIB_EBADARG) {
		diag("zone: Inserting NULL node to zone did not result in"
		     "proper return value (%d instead of %d)", res,
		     DNSLIB_EBADARG);
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

		if ((res = dnslib_zone_add_node(zone, node, 0, 1)) !=
		                DNSLIB_EBADZONE) {
			diag("zone: Inserting zone apex again did not result in"
			     "proper return value (%d instead of -2)",
			     DNSLIB_EBADZONE);
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

	int (*traversal_func)(dnslib_zone_t *zone,
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

struct zone_test_param {
	/* Times 2 so that we don't have to mess with mallocs. */
	dnslib_node_t *dnslib_node_array[TEST_NODES_GOOD * 2];
	dnslib_dname_t *table_node_array[TEST_NODES_GOOD * 2];
	int count;
};

static void tree_node_to_array(dnslib_node_t *node, void *data)
{
	struct zone_test_param *param = (struct zone_test_param *)data;
	param->dnslib_node_array[param->count++] = node;
}

static void tree_dname_node_to_array(struct dname_table_node *node,
                                     void *data)
{
	struct zone_test_param *param = (struct zone_test_param *)data;
	param->table_node_array[param->count++] = node->dname;
}

extern int compare_wires_simple(uint8_t *w1, uint8_t *w2, uint count);
static int test_zone_shallow_copy()
{
	int errors = 0;
	int lived = 0;
	dnslib_dname_t *apex_dname =
		dnslib_dname_new_from_str("a.ns.nic.cz.",
	                                  strlen("a.ns.nic.cz"), NULL);
	assert(apex_dname);
	dnslib_node_t *apex_node =
		dnslib_node_new(apex_dname, NULL);
	assert(apex_node);
	lives_ok({
		if (dnslib_zone_shallow_copy(NULL, NULL) != DNSLIB_EBADARG) {
			diag("Calling zone_shallow_copy with NULL "
			     "arguments did not return DNSLIB_EBADARG!");
			errors++;
		}

		dnslib_zone_t *zone = dnslib_zone_new(apex_node, 0, 1);
		if (dnslib_zone_shallow_copy(zone, NULL) != DNSLIB_EBADARG) {
			diag("Calling zone_shallow_copy with NULL destination "
			     "zone argument did not return DNSLIB_EBADARG!");
			errors++;
		}

		if (dnslib_zone_shallow_copy(NULL, &zone) != DNSLIB_EBADARG) {
			diag("Calling zone_shallow_copy with NULL source "
			     "zone argument did not return DNSLIB_EBADARG!");
			errors++;
		}

		if (dnslib_zone_shallow_copy(zone, &zone) != DNSLIB_EBADARG) {
			diag("Calling zone_shallow_copy with identical source "
			 "and destination zone did not return DNSLIB_EBADARG!");
			errors++;
		}

		dnslib_zone_free(&zone);
	}, "zone: shallow copy NULL tests");

	/* example.com. */
	dnslib_zone_t *from =
		dnslib_zone_new(dnslib_node_new(&test_nodes_good[0].owner,
		                test_nodes_good[0].parent), 10, 1);

	/* Add nodes to zone. */
	for (int i = 1; i < TEST_NODES_GOOD; ++i) {
		dnslib_node_t *node = dnslib_node_new(&test_nodes_good[i].owner,
		                                     test_nodes_good[i].parent);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if (dnslib_zone_add_node(from, node, 1, 1) != DNSLIB_EOK) {
			diag("zone: Could not add node. %s",
			     dnslib_dname_to_str(node->owner));
//			return 0;
		}
	}

	/* Make a copy of zone */
	dnslib_zone_t *to = NULL;
	int ret = 0;
	if ((ret = dnslib_zone_shallow_copy(from, &to) != DNSLIB_EOK)) {
		diag("Could not copy zone! %s", dnslib_strerror(ret));
		return 0;
	}

	assert(to);

	/* Compare non-tree parts of the zone. */
	if (from->data != to->data) {
		diag("Zone data field wrong after shallow copy!");
		errors++;
	}

	if (from->dtor != to->dtor) {
		diag("Zone data destructor field wrong after shallow copy!");
		errors++;
	}

	if (from->node_count != to->node_count) {
		diag("Zone node count data field wrong after shallow copy!");
		errors++;
	}

	if (from->version != to->version) {
		diag("Zone version data field wrong after shallow copy!");
		errors++;
	}

	if (from->apex != to->apex) {
		diag("Zone apex differ after shallow copy!");
	}

	if (compare_wires_simple((uint8_t *)(&from->nsec3_params),
	                         (uint8_t *)(&to->nsec3_params),
	                         sizeof(from->nsec3_params)) != 0) {
		diag("Nsec3_params data field wrong after shallow copy!");
		errors++;
	}

	if (from->nodes == to->nodes) {
		diag("Copied zones have identical trees!");
		errors++;
	}

	if (from->nsec3_nodes == to->nsec3_nodes) {
		diag("Copied zones have identical trees!");
		errors++;
	}

	/* Compare nodes, convert tree to array then compare those arrays. */
	struct zone_test_param param1;
	param1.count = 0;
	dnslib_zone_tree_apply_inorder(from, tree_node_to_array,
	                               (void *)&param1);

	struct zone_test_param param2;
	param2.count = 0;
	dnslib_zone_tree_apply_inorder(to, tree_node_to_array,
	                               (void *)&param2);

	if (param1.count != param2.count) {
		diag("wrong tree");
		return 0;
	}

	for (int i = 0; i < param1.count; i++) {
		if (param1.dnslib_node_array[i] !=
		    param2.dnslib_node_array[i]) {
			diag("wrong tree");
			return 0;
		}
	}

	param1.count = 0;
	dnslib_dname_table_tree_inorder_apply(from->dname_table,
	                                       tree_dname_node_to_array,
	                                       (void *)&param1);

	param2.count = 0;
	dnslib_dname_table_tree_inorder_apply(to->dname_table,
	                                      tree_dname_node_to_array,
	                                      (void *)&param2);

	if (param1.count != param2.count) {
		diag("wrong table count");
		return 0;
	}

	for (int i = 0; i < param1.count; i++) {
		if (param1.table_node_array[i] != param2.table_node_array[i]) {
			diag("wrong table nodes");
			errors++;
		}
	}

#ifdef USE_HASH_TABLE
	if (from->table) {
		if (from->table == to->table) {
			diag("hash tables after shallow copy are identical!");
			return 0;
		}
		uint i;
		if (hashsize(from->table->table_size_exp) !=
		                hashsize(to->table->table_size_exp)) {
			diag("hash tables after shallow copy error!");
			return 0;
		}

		if (from->table->table_count != to->table->table_count) {
			diag("hash tables after shallow copy error!");
			return 0;
		}

		for (uint t = 0; t < from->table->table_count; ++t) {
			for (i = 0; i <
			     hashsize(from->table->table_size_exp); i++) {
				if (from->table->tables[t][i] == NULL) {
					if (to->table->tables[t][i] != NULL) {
						diag("hash table item error");
					}
					continue;
				}
				if ((from->table->tables[t])[i]->key_length !=
				    (to->table->tables[t])[i]->key_length) {
					diag("hash table key lengths error!");
					return 0;
				}
				if ((from->table->tables[t])[i]->key !=
				    (to->table->tables[t])[i]->key) {
					diag("hash table key error!");
					return 0;
				}
				if ((from->table->tables[t])[i]->value !=
				    (to->table->tables[t])[i]->value) {
					diag("hash table value error!");
					return 0;
				}
			}
		}

		ck_stash_item_t *item1 = from->table->stash2;
		ck_stash_item_t *item2 = to->table->stash2;
		while (item1 != NULL && item2 != NULL) {
			if (item1->item->key_length !=
			    item2->item->key_length) {
				diag("hash stash key length error!");
				return 0;
			}
			if (item1->item->key != item2->item->key) {
				diag("hash stash key error!");
				return 0;
			}
			if (item1->item->value != item2->item->value) {
				diag("hash stash value error!");
				return 0;
			}

			item1 = item1->next;
			item2 = item2->next;
		}
	} else {
		if (to->table) {
			diag("Hash table is not set to NULL "
			     "after shallow copy!");
			errors++;
		}
	}
#endif

	dnslib_zone_free(&from);
	dnslib_zone_free(&to);
	return (errors == 0);

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

static const int DNSLIB_ZONE_TEST_COUNT = 10;

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

	ok((res = test_zone_shallow_copy()), "zone: shallow copy");
	res_final *= res;

//	ok((res = test_zone_free(&zone)), "zone: free");
//	res_final *= res;

	endskip; // create failed

	return res_final;
}
