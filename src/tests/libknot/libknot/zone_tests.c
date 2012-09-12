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

#include "tests/libknot/libknot/zone_tests.h"
#include "libknot/common.h"
#include "libknot/zone/dname-table.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/node.h"

static int knot_zone_tests_count(int argc, char *argv[]);
static int knot_zone_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api zone_tests_api = {
	"DNS library - zone",        //! Unit name
	&knot_zone_tests_count,  //! Count scheduled tests
	&knot_zone_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

enum { TEST_NODES_GOOD = 7, TEST_NODES_BAD = 1, TRAVERSAL_TYPES = 3};

struct zone_test_node {
	knot_dname_t owner;
	knot_node_t *parent;
};

static struct zone_test_node test_apex =
{{{}, (uint8_t *)"\3com\0", (uint8_t *)"\x0", NULL, 0, 5, 1}, (knot_node_t *)NULL};

static struct zone_test_node test_nodes_bad[TEST_NODES_BAD] = {
	{{{},(uint8_t *)"\5other\6domain\0", (uint8_t *)"\x0\x6", NULL, 0, 14, 2},
	 (knot_node_t *)NULL}
};

static struct zone_test_node test_nodes_good[TEST_NODES_GOOD] = {
	{{{}, (uint8_t *)"\7example\3com\0", (uint8_t *)"\x0\x8", NULL, 0, 13, 2},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\3www\7example\3com\0", (uint8_t *)"\x0\x4\xC", NULL, 0, 17, 3},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\7another\6domain\3com\0", (uint8_t *)"\x0\x8\xF", NULL, 0, 20, 3},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\5mail1\7example\3com\0", (uint8_t *)"\x0\x6\xE", NULL, 0, 19, 3},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\5mail2\7example\3com\0", (uint8_t *)"\x0\x6\xE", NULL, 0, 19, 3},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\3smb\7example\3com\0", (uint8_t *)"\x0\x4\xC", NULL, 0, 17, 3},
	 (knot_node_t *)NULL},
	{{{}, (uint8_t *)"\4smtp\7example\3com\0", (uint8_t *)"\x0\x5\xD", NULL, 0, 18, 3},
	 (knot_node_t *)NULL},
};

static int test_zone_check_node(const knot_node_t *node,
                                const struct zone_test_node *test_node,
                                int test_parent)
{
	return (node->owner == &test_node->owner) &&
		((test_parent) ? node->parent == test_node->parent : 1);
}

static int test_zone_create(knot_zone_contents_t **zone)
{
//	knot_dname_t *dname = knot_dname_new_from_wire(
//		test_apex.owner.name, test_apex.owner.size, NULL);
//	assert(dname);

	knot_node_t *node = knot_node_new(&test_apex.owner,
	                                      test_apex.parent, 0);
	if (node == NULL) {
		diag("zone: Could not create zone apex.");
		return 0;
	}

	*zone = knot_zone_contents_new(node, 0, 0, NULL);

	if ((*zone) == NULL) {
		diag("zone: Failed to create zone.");
		knot_node_free(&node);
		return 0;
	}

	if ((*zone)->apex != node) {
		diag("zone: Zone apex not set right.");
		knot_node_free(&node);
		return 0;
	}

	return 1;
}

static int test_zone_add_node(knot_zone_contents_t *zone, int nsec3)
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
		knot_node_t *node = knot_node_new(&test_nodes_good[i].owner,
		                                     test_nodes_good[i].parent, 0);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if ((res = ((nsec3) ? knot_zone_contents_add_nsec3_node(zone, node, 0, 0, 0)
		                   : knot_zone_contents_add_node(zone, node, 0, 0, 0))) != 0) {
			diag("zone: Failed to insert node into zone (returned"
			     " %d).", res);
			knot_node_free(&node);
			++errors;
		}
		/* TODO check values in the node as well */
	}

	//note("Bad nodes");

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		knot_node_t *node = knot_node_new(&test_nodes_bad[i].owner,
		                                    test_nodes_bad[i].parent, 0);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if ((res = ((nsec3) ? knot_zone_contents_add_nsec3_node(zone, node, 0, 0, 0)
			: knot_zone_contents_add_node(zone, node, 0, 0, 0))) !=
		                KNOT_EBADZONE) {
			diag("zone: Inserting wrong node did not result in"
			     "proper return value (%d instead of %d).", res,
			     KNOT_EBADZONE);
			++errors;
		}
		knot_node_free(&node);
	}

	//note("NULL zone");

	note("Inserting into NULL zone...\n");

	knot_node_t *node = knot_node_new(&test_nodes_good[0].owner,
	                                      test_nodes_good[0].parent, 0);
	if (node == NULL) {
		diag("zone: Could not create node.");
		return 0;
	}

	if ((res = ((nsec3) ? knot_zone_contents_add_nsec3_node(NULL, node, 0, 0, 0)
		: knot_zone_contents_add_node(NULL, node, 0, 0, 0))) != KNOT_EINVAL) {
		diag("zone: Inserting node to NULL zone did not result in"
		     "proper return value (%d instead of %d)", res,
		     KNOT_EINVAL);
		++errors;
	}

	knot_node_free(&node);

	//note("NULL node");
	note("Inserting NULL node...\n");

	if ((res = ((nsec3) ? knot_zone_contents_add_nsec3_node(zone, NULL, 0, 0, 0)
		: knot_zone_contents_add_node(zone, NULL, 0, 0, 0))) != KNOT_EINVAL) {
		diag("zone: Inserting NULL node to zone did not result in"
		     "proper return value (%d instead of %d)", res,
		     KNOT_EINVAL);
		++errors;
	}

	if (!nsec3) {
		//note("Inserting Apex again...\n");

		node = knot_node_new(&test_apex.owner, test_apex.parent, 0);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		//note("Apex again");

		if ((res = knot_zone_contents_add_node(zone, node, 0, 0, 0)) !=
		                KNOT_EBADZONE) {
			diag("zone: Inserting zone apex again did not result in"
			     "proper return value (%d instead of -2)",
			     KNOT_EBADZONE);
			++errors;
		}

		knot_node_free(&node);
	}

	// check if all nodes are inserted
	//int nodes = 0;
	if (!nsec3
	    && !test_zone_check_node(knot_zone_contents_apex(zone), &test_apex, !nsec3)) {
		diag("zone: Apex of zone not right.");
//		diag("Apex owner: %s (%p), apex parent: %p\n",
//		     knot_dname_to_str(knot_zone_apex(zone)->owner),
//		     knot_zone_apex(zone)->owner,
//		     knot_zone_apex(zone)->parent);
//		diag("Should be: owner: %s (%p), parent: %p\n",
//		     knot_dname_to_str(&test_apex.owner),
//		     &test_apex.owner,
//		     test_apex.parent);
		++errors;
	}
	//++nodes;
	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		const knot_node_t *n = ((nsec3) ? knot_zone_contents_find_nsec3_node(
				zone, &test_nodes_good[i].owner) :
			knot_zone_contents_find_node(zone, &test_nodes_good[i].owner));
		if (n == NULL) {
			diag("zone: Missing node with owner %s",
			     test_nodes_good[i].owner.name);
			++errors;
			continue;
		}

		if (!test_zone_check_node(n, &test_nodes_good[i], !nsec3)) {
			diag("zone: Node does not match: owner: %s (should be "
			     "%s), parent: %p (should be %p)",
			     n->owner->name, test_nodes_good[i].owner.name,
			     n->parent, test_nodes_good[i].parent);
			++errors;
		}
		//++nodes;
	}

	//note("zone: %d nodes in the zone (including apex)", nodes);

	return (errors == 0);
}

static int test_zone_get_node(knot_zone_contents_t *zone, int nsec3)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (((nsec3) ? knot_zone_contents_get_nsec3_node(
		                   zone, &test_nodes_good[i].owner)
			: knot_zone_contents_get_node(zone, &test_nodes_good[i].owner))
			== NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (((nsec3) ? knot_zone_contents_get_nsec3_node(
		                   zone, &test_nodes_bad[i].owner)
			: knot_zone_contents_get_node(zone, &test_nodes_bad[i].owner))
			!= NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (((nsec3)
	     ? knot_zone_contents_get_nsec3_node(NULL, &test_nodes_good[0].owner)
	     : knot_zone_contents_get_node(NULL, &test_nodes_good[0].owner)) != NULL) {
		diag("zone: Getting node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (((nsec3) ? knot_zone_contents_get_nsec3_node(zone, NULL)
	             : knot_zone_contents_get_node(zone, NULL)) != NULL) {
		diag("zone: Getting node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (!nsec3 && knot_zone_contents_get_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Getting zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

static int test_zone_find_node(knot_zone_contents_t *zone, int nsec3)
{
	int errors = 0;

	for (int i = 0; i < TEST_NODES_GOOD; ++i) {
		if (((nsec3) ? knot_zone_contents_find_nsec3_node(
		                   zone, &test_nodes_good[i].owner)
		    : knot_zone_contents_find_node(zone, &test_nodes_good[i].owner))
		    == NULL) {
			diag("zone: Node (%s) not found in zone.",
			     (char *)test_nodes_good[i].owner.name);
			++errors;
		}
	}

	for (int i = 0; i < TEST_NODES_BAD; ++i) {
		if (((nsec3) ? knot_zone_contents_find_nsec3_node(
		                   zone, &test_nodes_bad[i].owner)
		    : knot_zone_contents_find_node(zone, &test_nodes_bad[i].owner))
		    != NULL) {
			diag("zone: Node (%s) found in zone even if it should"
			     "not be there.",
			     (char *)test_nodes_bad[i].owner.name);
			++errors;
		}
	}

	if (((nsec3)
	    ? knot_zone_contents_find_nsec3_node(NULL, &test_nodes_good[0].owner)
	    : knot_zone_contents_find_node(NULL, &test_nodes_good[0].owner)) != NULL) {
		diag("zone: Finding node from NULL zone did not result in"
		     "proper return value (NULL)");
		++errors;
	}

	if (((nsec3) ? knot_zone_contents_find_nsec3_node(zone, NULL)
	             : knot_zone_contents_find_node(zone, NULL)) != NULL) {
		diag("zone: Finding node with NULL owner from zone did not "
		     "result in proper return value (NULL)");
		++errors;
	}

	if (!nsec3 && knot_zone_contents_find_node(zone, &test_apex.owner) == NULL) {
		diag("zone: Finding zone apex from the zone failed");
		++errors;
	}

	return (errors == 0);
}

//static void test_zone_destroy_node_from_tree(knot_node_t *node,
//                                             void *data)
//{
//	UNUSED(data);
//	knot_node_free(&node, 0);
//}

/* explained below */
static size_t node_index = 0;

/*! \brief
 * This function will overwrite parent field in node structure -
 * we don't (and can't, with current structures) use it in these tests anyway.
 * Since zone structure itself has no count field, only option known to me
 * is (sadly) to use a global variable.
 */
static void tmp_apply_function(knot_node_t *node, void *data)
{
	node->parent = (knot_node_t *)node_index;
	node_index++;
}

/* \note Since I am unaware of a way how to get a return value from traversal
 * functions, I will use (hopefully for the last time here) global variable
 */

static int compare_ok = 1;

static void tmp_compare_function(knot_node_t *node, void *data)
{
	/* node_index will start set to zero */
	if (node->parent != (knot_node_t *)node_index) {
		compare_ok = 0;
		return;
	} else if (!compare_ok) {
		diag("Traversal function has partially set values right");
	}
	node->parent = NULL;
	node_index++;
}

static int test_zone_tree_apply(knot_zone_contents_t *zone,
                                int type, int nsec3)
{

	assert(node_index == 0);
	assert(compare_ok == 1);

	int (*traversal_func)(knot_zone_contents_t *zone,
	                       void (*function)(knot_node_t *node,
	                                        void *data),
	                       void *data);

	switch (type) {
		case 0: {
			if (nsec3) {
				traversal_func =
					&knot_zone_contents_nsec3_apply_postorder;
				diag("Testing postorder traversal");
			} else {
				traversal_func =
					&knot_zone_contents_tree_apply_postorder;
				diag("Testing postorder traversal - NSEC3");
			}
			break;
		}
		case 1: {
			if (nsec3) {
				traversal_func =
					&knot_zone_contents_nsec3_apply_inorder;
				diag("Testing inorder traversal");
			} else {
				traversal_func =
					&knot_zone_contents_tree_apply_inorder;
				diag("Testing inorder traversal - NSEC3");
			}
			break;
		}
		case 2: {
			if (nsec3) {
				traversal_func =
				&knot_zone_contents_nsec3_apply_inorder_reverse;
				diag("Testing inorder reverse traversal");
			} else {
				traversal_func =
				&knot_zone_contents_tree_apply_inorder_reverse;
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
static int test_zone_traversals(knot_zone_contents_t *zone)
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
	knot_node_t *knot_node_array[TEST_NODES_GOOD * 5];
	knot_dname_t *table_node_array[TEST_NODES_GOOD * 5];
	size_t count;
};

static void tree_node_to_array(knot_node_t *node, void *data)
{
	struct zone_test_param *param = (struct zone_test_param *)data;
	param->knot_node_array[param->count++] = node;
}

static void tree_dname_node_to_array(knot_dname_t *node,
                                     void *data)
{
	struct zone_test_param *param = (struct zone_test_param *)data;
	param->table_node_array[param->count++] = node;
}

extern int compare_wires_simple(uint8_t *w1, uint8_t *w2, uint count);
static int test_zone_shallow_copy()
{
	int errors = 0;
	int lived = 0;
	knot_dname_t *apex_dname =
		knot_dname_new_from_str("a.ns.nic.cz.",
	                                  strlen("a.ns.nic.cz"), NULL);
	assert(apex_dname);
	knot_node_t *apex_node =
		knot_node_new(apex_dname, NULL, 0);
	assert(apex_node);
	lives_ok({
		if (knot_zone_contents_shallow_copy(NULL, NULL) != KNOT_EINVAL) {
			diag("Calling zone_shallow_copy with NULL "
			     "arguments did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		lived = 0;
		knot_zone_contents_t *zone = knot_zone_contents_new(apex_node,
									0, 1, 0);
		if (knot_zone_contents_shallow_copy(zone, NULL) != KNOT_EINVAL) {
			diag("Calling zone_shallow_copy with NULL destination "
			     "zone argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_contents_shallow_copy(NULL, &zone) != KNOT_EINVAL) {
			diag("Calling zone_shallow_copy with NULL source "
			     "zone argument did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_contents_shallow_copy(zone, &zone) != KNOT_EINVAL) {
			diag("Calling zone_shallow_copy with identical source "
			 "and destination zone did not return KNOT_EINVAL!");
			errors++;
		}
		lived = 1;
		knot_zone_contents_free(&zone);
	}, "zone: shallow copy NULL tests");
	errors += lived != 1;

	knot_dname_t *d = knot_dname_deep_copy(&test_nodes_good[0].owner);
	if (d == NULL) {
		return 0;
	}
	knot_node_t *n = knot_node_new(d, NULL, 0);
	
	/* example.com. */
//	knot_zone_t *from_zone =
//		knot_zone_new(knot_node_new(&test_nodes_good[0].owner,
//				test_nodes_good[0].parent, 0), 10, 1);
	knot_zone_t *from_zone = knot_zone_new(n, 10, 1);
	knot_zone_contents_t *from = knot_zone_get_contents(from_zone);

	/* Add nodes to zone. */
	for (int i = 1; i < TEST_NODES_GOOD; ++i) {
		knot_dname_t *d = knot_dname_deep_copy(&test_nodes_good[i].owner);
		if (d == NULL) {
			return 0;
		}
		knot_node_t *node = knot_node_new(d, test_nodes_good[i].parent,
		                                  0);
		if (node == NULL) {
			diag("zone: Could not create node.");
			return 0;
		}

		if (knot_zone_contents_add_node(from, node, 1, 1, 1) != KNOT_EOK) {
			diag("zone: Could not add node. %s",
			     knot_dname_to_str(node->owner));
//			return 0;
		}
	}

	/* Make a copy of zone */
	knot_zone_contents_t *to = NULL;
	int ret = 0;
	if ((ret = knot_zone_contents_shallow_copy(from, &to) != KNOT_EOK)) {
		diag("Could not copy zone! %s", knot_strerror(ret));
		return 0;
	}

	assert(to);

	/* Compare non-tree parts of the zone. */
//	if (from->data != to->data) {
//		diag("Zone data field wrong after shallow copy!");
//		errors++;
//	}

//	if (from->dtor != to->dtor) {
//		diag("Zone data destructor field wrong after shallow copy!");
//		errors++;
//	}

	if (from->node_count != to->node_count) {
		diag("Zone node count data field wrong after shallow copy!");
		errors++;
	}

//	if (from->version != to->version) {
//		diag("Zone version data field wrong after shallow copy!");
//		errors++;
//	}

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
	memset(&param1, 0, sizeof(struct zone_test_param));

	knot_zone_contents_tree_apply_inorder(from, tree_node_to_array,
						(void *)&param1);

	struct zone_test_param param2;
	memset(&param2, 0, sizeof(struct zone_test_param));

	knot_zone_contents_tree_apply_inorder(to, tree_node_to_array,
						(void *)&param2);

	if (param1.count != param2.count) {
		diag("wrong tree");
		return 0;
	}

	for (int i = 0; i < param1.count; i++) {
		if (param1.knot_node_array[i] !=
		    param2.knot_node_array[i]) {
			diag("wrong tree");
			return 0;
		}
	}

	param1.count = 0;
	knot_dname_table_tree_inorder_apply(from->dname_table,
	                                       tree_dname_node_to_array,
	                                       (void *)&param1);

	param2.count = 0;
	knot_dname_table_tree_inorder_apply(to->dname_table,
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

		ck_stash_item_t *item1 = from->table->stash;
		ck_stash_item_t *item2 = to->table->stash;
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

//	knot_zone_deep_free(&from_zone, 0);
//	knot_zone_contents_free(&to);
	return (errors == 0);

}

//static int test_zone_free(knot_zone_t **zone)
//{
//	knot_zone_tree_apply_postorder(*zone,
//	                                 test_zone_destroy_node_from_tree,
//	                                 NULL);
//	knot_zone_nsec3_apply_postorder(*zone,
//	                                 test_zone_destroy_node_from_tree,
//	                                 NULL);
//	knot_zone_free(zone);
//	return (*zone == NULL);
//}

static const int KNOT_ZONE_TEST_COUNT = 10;

/*! This helper routine should report number of
 *  scheduled tests for given parameters.
 */
static int knot_zone_tests_count(int argc, char *argv[])
{
	return KNOT_ZONE_TEST_COUNT;
}

/*! Run all scheduled tests for given parameters.
 */
static int knot_zone_tests_run(int argc, char *argv[])
{
	int res = 0,
	    res_final = 0;

	knot_zone_contents_t *zone = NULL;

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
