#include <string.h>
#include <assert.h>

#include "tests/libknot/libknot/zone_tree_tests.h"
#include "libknot/zone/zone-tree.h"
#include "libknot/errors.h"

static int knot_zone_tree_tests_count(int argc, char *argv[]);
static int knot_zone_tree_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api zone_tree_tests_api = {
	"DNS library - dname",        //! Unit name
	&knot_zone_tree_tests_count,  //! Count scheduled tests
	&knot_zone_tree_tests_run     //! Run scheduled tests
};

/*
 *  Unit implementation.
 */

static int test_tree_init()
{
	int errors = 0;
	int lived = 0;

	lives_ok({
		if (knot_zone_tree_init(NULL) != KNOT_EBADARG) {
			diag("Calling knot_zone_tree_init with NULL "
			     "tree did not return KNOT_EBADARG!");
			errors++;
		}
		lived = 1;
	}, "init NULL tests");
	errors += lived != 1;

	return (errors == 0);
}

static int test_tree_insert()
{
	int errors = 0;
	int lived = 0;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);
	knot_node_t *node =
		knot_node_new(knot_dname_new_from_str("a.ns.nic.cz."),
	                                              NULL, 0);
	assert(node);

	lives_ok({
		if (knot_zone_tree_insert(NULL, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_insert(tree, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_insert(NULL, node) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "init NULL tests");
	if (errors) {
		diag("Zone tree insert did not return KNOT_EBADARG "
		     "when given wrong arguments");
	}
	errors += lived != 1;

	if (knot_zone_tree_insert(tree, node) != KNOT_EOK) {
		diag("Calling zone tree insert with valid arguments "
		     "did not return KNOT_EOK");
		errors++;
	}

	/* Sorting will be tested in traversal functions. */
}

static int test_tree_finding()
{
	int errors = 0;
	int lived = 0;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);
	knot_node_t *node =
		knot_node_new(knot_dname_new_from_str("a.ns.nic.cz."),
	                                              NULL, 0);
	assert(node);

	lives_ok({
		if (knot_zone_tree_find(NULL, NULL, NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_find(tree, NULL, NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_find(tree, node->owner,
		                        NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		knot_node_t *found_node = NULL;
		lived = 0;
		if (knot_zone_tree_find(NULL, node->owner,
		                        &found_node) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_find(tree, NULL,
		                        &found_node) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "init NULL tests");
	if (errors) {
		diag("Zone tree find did not return KNOT_EBADARG "
		     "when given wrong arguments");
	}

	/* Insert node */
	assert(knot_zone_tree_insert(tree, node) == KNOT_EOK);

	dnslib_node_t *found_node = NULL;
	if (knot_zone_tree_find(tree, node->onwer, &found_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree find with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree find did not return right node");
		errors++;
	}

	if (knot_zone_tree_get(tree, node->onwer, &found_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree get with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree get did not return right node");
		errors++;
	}

	/* Try to search for node not in tree. */
	knot_dname_t *alien_dname =
		knot_dname_new_from_str("this.name.is.not.in.the.tree.",
	                                strlen("this.name.is.not.in.the.tree."),
	                                NULL);

	if (knot_zone_tree_find(tree, alien_dname, &found_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree find with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != NULL) {
		diag("Zone tree find returned node that was not in the tree!");
		errors++;
	}

	if (knot_zone_tree_get(tree, alien_dname, &found_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree get with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != NULL) {
		diag("Zone tree get returned node that was not in the tree!");
		errors++;
	}

	return (errors == 0);
}

static int test_tree_finding_less_or_equal()
{
	int errors = 0;
	int lived = 0;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);
	knot_node_t *node =
		knot_node_new(knot_dname_new_from_str("a.ns.nic.cz."),
	                                              NULL, 0);
	assert(node);

	lives_ok({
		if (knot_zone_tree_find_less_or_equal(NULL,
	                                              NULL,
	                                              NULL,
	                                              NULL) !=
	            KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_find_less_or_equal(tree, NULL,
		                                      NULL, NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_find_less_or_equal(tree,
		                                      node->owner,
		                                      NULL,
		                                      NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		knot_node_t *found_node = NULL;
		lived = 0;
		if (knot_zone_tree_find_less_or_equal(NULL, node->owner,
		                        &found_node, NULL) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		knot_node_t *previous_node = NULL;
		lived = 0;
		if (knot_zone_tree_find_less_or_equal(tree, NULL,
		                        &found_node,
		                        &previous_node) !=
		    KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "tree find less or equal NULL tests");
	if (errors) {
		diag("Zone tree find did not return KNOT_EBADARG "
		     "when given wrong arguments");
	}

	knot_node_t *previous_node = NULL;

	/* Insert node - exact match. */
	assert(knot_zone_tree_insert(tree, node) == KNOT_EOK);

	dnslib_node_t *found_node = NULL;
	if (knot_zone_tree_find_less_or_equal(tree,
	                                      node->onwer,
	                                      &found_node,
	                                      &previous_node) <= 0) {
		diag("Calling zone tree find with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree find did not return right node");
		errors++;
	}

	if (knot_zone_tree_get_less_or_equal(tree, node->owner, &found_node,
	                                     &previous_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree get with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree get did not return right node");
		errors++;
	}

	knot_dname_t *less_dname =
		knot_dname_new_from_str("abcdef.a.ns.nic.cz.",
		                        strlen("abcdef.a.ns.nic.cz."),
		                        NULL);

	if (knot_zone_tree_find_less_or_equal(tree,
	                                      less_dname,
	                                      &found_node,
	                                      &previous_node) <= 0) {
		diag("Calling zone tree find with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree find did not return right node");
		errors++;
	}

	if (knot_zone_tree_get_less_or_equal(tree, less_dname, &found_node,
	                                     &previous_node) !=
	    KNOT_EOK) {
		diag("Calling zone tree get with valid arguments did "
		     "not return KNOT_EOK");
		errors++;
	}

	if (found_node != node) {
		diag("Zone tree get did not return right node");
		errors++;
	}

	/* Try to search for node not in tree. */
	knot_dname_t *alien_dname =
		knot_dname_new_from_str("this.name.is.not.in.the.tree.",
	                                strlen("this.name.is.not.in.the.tree."),
	                                NULL);

	if (knot_zone_tree_find_less_or_equal(tree, alien_dname,
	                                      &found_node,
	                                      &previous_node) !=
	    0) {
		diag("Calling zone tree find with valid arguments did "
		     "not return 0");
		errors++;
	}

	if (knot_zone_tree_get_less_or_equal(tree,
	                                     alien_dname,
	                                     &found_node,
	                                     &previous_node) !=
	    0) {
		diag("Calling zone tree get with valid arguments did "
		     "not return -");
		errors++;
	}

	/* Set node previous label. */
	knot_node_t *tmp_node =
		knot_node_new(knot_dname_new_from_str("ns.nic.cz.",
	                                              strlen("ns.nic.cz"),
	                                              NULL), NULL, 0);
	assert(tmp_node);
	knot_node_set_parent(node, tmp_node);

	if (knot_zone_tree_find_less_or_equal(tree, node->owner,
	                                      &found_node,
	                                      &previous_node) <=
	    0) {
		diag("Calling zone tree find with valid arguments did "
		     "not return > 0");
		errors++;
	}

	if (found_node != node || previous_node != tmp_node) {
		diag("Zone tree find did not return valid nodes!");
		errors++;
	}


	if (knot_zone_tree_get_less_or_equal(tree, node->owner,
	                                    &found_node,
	                                      &previous_node) <=
	    0) {
		diag("Calling zone tree get with valid arguments did "
		     "not return > 0");
		errors++;
	}

	if (found_node != node || previous_node != tmp_node) {
		diag("Zone tree find did not return valid nodes!");
		errors++;
	}

	return (errors == 0);
}

static int test_tree_remove()
{
	int errors = 0;
	int lived = 0;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);
	knot_node_t *node =
		knot_node_new(knot_dname_new_from_str("a.ns.nic.cz."),
	                                              NULL, 0);
	assert(node);

	/* Add node. */
	assert(knot_zone_tree_insert(tree, node) == 0);

	lives_ok({
		if (knot_zone_tree_remove(NULL, NULL, NULL) !=
		    KNOT_EBADARG)
			 errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_remove(zone, NULL, NULL) !=
		     KNOT_EBADARG)
			  errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_remove(zone, node->owner, NULL) !=
		     KNOT_EBADARG)
			  errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_remove(NULL, node->owner, NULL) !=
		     KNOT_EBADARG)
			  errors++;
		}
		lived = 1;
		knot_node_t *deleted_node = NULL;
		lived = 0;
		if (knot_zone_tree_remove(NULL, node->owner, &deleted_node) !=
		     KNOT_EBADARG)
			  errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_remove(zone, NULL, &deleted_node) !=
		     KNOT_EBADARG)
			  errors++;
		}
		lived = 1;
	}, "tree find less or equal NULL tests");
	if (errors) {
		diag("Zone tree remove did not return KNOT_EBADARG "
		     "when given wrong arguments");
	}

	errors += lived != 1;

	knot_node_t *removed_node = NULL;

	/* Remove previously inserted node. */
	if (knot_zone_tree_remove(tree, node->owner, &removed_node) !=
	    DNSLIB_EOK) {
		diag("Could not remove previously inserted node!");
		errors++;
	}

	if (removed_node != node) {
		diag("Wrong node was removed!");
		errors++;
	}

	/*
	 * Try remove the node again - it should not be there and
	 * removed_node should be NULL.
	 */

	if (knot_zone_tree_remove(tree, node->owner, &removed_node) !=
	    DNSLIB_EOK) {
		diag("Could not remove previously inserted node!");
		errors++;
	}

	if (removed_node != NULL) {
		diag("Zone tree remove returned previously removed node!");
		errors++;
	}

	return (errors == 0);

}

struct test_zone_tree_args {
	knot_node_t **array[10 * 1024];
	size_t count;
};

static void add_to_array(knot_node_t *node, void *data)
{
	struct test_zone_tree_args *args =
		(struct test_zone_tree_args *)data;
	args->array[args->count++] = node;
}

static int test_traversal(knot_node_t **nodes,
                          size_t node_count,
                          uint code)
{
	int errors = 0;
	int lived = 0;

	void (*trav_func)(knot_zone_tree_t *,
	                  void (*)(knot_node_t *, void *),
	                  void *);

	trav_func = (code) ? knot_zone_tree_reverse_apply_inorder :
	                     knot_zone_tree_forward_apply_inorder;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);

	lives_ok({
		if (trav_func(NULL, NULL, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (trav_func(zone, NULL, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (trav_func(NULL, add_to_array, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "traversal NULL tests");

	if (errors) {
		diag("Traversal function did not return KNOT_EBADARG "
		     "when given NULL parameters");
	}

	errors += lived != 1;

	/* Add nodes to tree. */
	for (int i = 0; i < node_count; i++) {
		assert(knot_zone_tree_insert(tree, nodes[i]) == KNOT_EOK);
	}

	struct test_zone_tree_args args;
	args.count = 0;

	trav_func(tree, add_to_array, args);

	if (args->count - 1 != node_count) {
		diag("Traversal function traversed more nodes than it "
		     "should have!");
		return ++errors;
	}

	for (int i = 0; i < node_count; i++) {
		int match = nodes[i] == args->array[i];
		if (!match) {
			diag("Traversal function returned nodes in wrong "
			     "order!");
			errors++;
		}
	}

	return errors;
}

static int test_tree_traversals()
{
	/*!< \todo I can test inorder and reverse inorder, but I don't know
	 * how to test others. It is somehow tested in zone tests. */
	int errors == 0;

	/* Create few nodes. (5 should be enough) */
	knot_node_t *nodes[5];
	for (int i = 0; i < 5; i++) {
		char *owner_string[20];
		owner_string[0] = i - '0';
		memcpy(owner_string + 1, "ns.test.cz.");
		nodes[i] =
			knot_node_new(knot_dname_new_from_str(owner_string,
							strlen(owner_string),
							NULL), NULL, 0);
	}

	if (test_traversal(nodes, 5, 0)) {
		diag("Inorder traversal failed");
		errors++;
	}

	for (int i = 4; i >= 0; i++) {
		char *owner_string[20];
		owner_string[0] = i - '0';
		memcpy(owner_string + 1, "ns.test.cz.");
		nodes[i] =
			knot_node_new(knot_dname_new_from_str(owner_string,
							strlen(owner_string),
							NULL), NULL, 0);
	}

	if (test_traversal(nodes, 5, 1)) {
		diag("Reverse inorder traversal failed");
		errors++;
	}

	return (errors == 0);
}

static int test_tree_shallow_copy()
{
	int errors == 0;
	int lived = 0;

	knot_zone_tree_t *tree = malloc(sizeof(knot_zone_tree_t));
	assert(tree);
	knot_zone_tree_init(tree);

	lives_ok({
		if (knot_zone_tree_shallow_copy(NULL, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_shallow_copy(tree, NULL) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
		lived = 0;
		if (knot_zone_tree_shallow_copy(NULL, tree) != KNOT_EBADARG) {
			errors++;
		}
		lived = 1;
	}, "Zone tree shallow copy NULL tests");
	if (errors) {
		diag("Zone tree shallow copy did not return KNOT_EBADARG when "
		     "given NULL arguments");
	}
	errors += lived != 1;

	/* Create few nodes. (5 should be enough) */
	knot_node_t *nodes[5];
	for (int i = 0; i < 5; i++) {
		char *owner_string[20];
		owner_string[0] = i - '0';
		memcpy(owner_string + 1, "ns.test.cz.");
		nodes[i] =
			knot_node_new(knot_dname_new_from_str(owner_string,
							strlen(owner_string),
							NULL), NULL, 0);
		/* Insert node to tree. */
		assert(knot_zone_tree_insert(tree, nodes[i]) == KNOT_EOK);
	}

	/* Create shallow copy. */
	knot_zone_tree_t *new_tree = malloc(sizeof(knot_zone_tree_t));
	assert(new_tree);
	knot_zone_tree_init(new_tree);

	if (knot_zone_tree_shallow_copy(tree, new_tree) != KNOT_EOK) {
		diag("Zone tree shallow copy did not return KNOT_EOK "
		     "when executed with valid parameters");
		return 0;
	}

	/* Traverse the tree twice and check that arrays are the same. */
	struct test_zone_tree_args args1;
	args1.count = 0;

	knot_zone_tree_forward_apply_inorder(tree, add_to_array,
	                                     &args1);


	struct test_zone_tree_args args2;
	args2.count = 0;
	knot_zone_tree_forward_apply_inorder(new_tree, add_to_array,
	                                     &args2);

	if (args1.count != args2.count) {
		diag("Zone tree created by shallow copy has wrong count"
		     "of nodes");
		return 0;
	}

	for (int i = 0; i < args1.count; i++) {
		if (args1.array[i] != args2.array[i]) {
			diag("Zone tree created by shallow copy has wrong "
			     "nodes");
		}
		errors++;
	}

	return (errors == 0);

}


static const int KNOT_ZONE_TREE_TEST_COUNT = 0;

static int knot_zone_tree_tests_count(int argc, char *argv[])
{
	return KNOT_ZONE_TREE_TEST_COUNT;
}

static int knot_dname_tests_run(int argc, char *argv[])
{
	ok(test_tree_init(), "zone tree: init");
	ok(test_tree_insert(), "zone tree: insertion");
	ok(test_tree_finding(), "zone tree: finding");
	ok(test_tree_finding_less_or_equal(), "zone tree: find less or equal");
	ok(test_tree_remove(), "zone tree: removal");
	ok(test_tree_traversals(), "zone tree: traversals");
	ok(test_tree_shallow_copy(), "zone tree: shallow copy");

	return 1;
}
