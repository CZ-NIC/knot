#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "dnslib/zone-tree.h"
#include "dnslib/node.h"
#include "dnslib/error.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

// AVL tree functions
TREE_DEFINE(dnslib_zone_tree_node, avl);

/*----------------------------------------------------------------------------*/

static int dnslib_zone_tree_node_compare(dnslib_zone_tree_node_t *node1,
                                         dnslib_zone_tree_node_t *node2)
{
	assert(node1 != NULL);
	assert(node2 != NULL);
	assert(node1->node != NULL);
	assert(node2->node != NULL);
	assert(dnslib_node_owner(node1->node) != NULL);
	assert(dnslib_node_owner(node2->node) != NULL);

	return dnslib_node_compare(node1->node, node2->node);
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_tree_delete_subtree(dnslib_zone_tree_node_t *root)
{
	if (root == NULL) {
		return;
	}

	dnslib_zone_tree_delete_subtree(root->avl.avl_left);
	dnslib_zone_tree_delete_subtree(root->avl.avl_right);
	free(root);
}

/*----------------------------------------------------------------------------*/

static int dnslib_zone_tree_copy_node(dnslib_zone_tree_node_t *from,
                                      dnslib_zone_tree_node_t **to)
{
	if (from == NULL) {
		*to = NULL;
		return DNSLIB_EOK;
	}

	*to = (dnslib_zone_tree_node_t *)
	      malloc(sizeof(dnslib_zone_tree_node_t));
	if (*to == NULL) {
		return DNSLIB_ENOMEM;
	}

	(*to)->node = from->node;
	(*to)->avl.avl_height = from->avl.avl_height;

	int ret = dnslib_zone_tree_copy_node(from->avl.avl_left,
	                                     &(*to)->avl.avl_left);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	ret = dnslib_zone_tree_copy_node(from->avl.avl_right,
	                                 &(*to)->avl.avl_right);
	if (ret != DNSLIB_EOK) {
		dnslib_zone_tree_delete_subtree((*to)->avl.avl_left);
		(*to)->avl.avl_left = NULL;
		return ret;
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

static void dnslib_zone_tree_free_node(dnslib_zone_tree_node_t *node,
                                       int free_data, int free_owner)
{
	if (node == NULL) {
		return;
	}

	dnslib_zone_tree_free_node(node->avl.avl_left, free_data, free_owner);

	dnslib_zone_tree_free_node(node->avl.avl_right, free_data, free_owner);

	if (free_data) {
		dnslib_node_free(&node->node, free_owner, 0);
	}

	free(node);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_init(dnslib_zone_tree_t *tree)
{
	if (tree == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_INIT(tree, dnslib_zone_tree_node_compare);
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_insert(dnslib_zone_tree_t *tree, dnslib_node_t *node)
{
	if (tree == NULL || node == NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_zone_tree_node_t *znode = (dnslib_zone_tree_node_t *)malloc(
	                                       sizeof(dnslib_zone_tree_node_t));
	if (znode == NULL) {
		return DNSLIB_ENOMEM;
	}

	znode->node = node;
	znode->avl.avl_left = NULL;
	znode->avl.avl_right = NULL;
	znode->avl.avl_height = 0;

	/*! \todo How to know if this was successful? */
	TREE_INSERT(tree, dnslib_zone_tree_node, avl, znode);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_find(dnslib_zone_tree_t *tree, const dnslib_dname_t *owner,
                          const dnslib_node_t **found)
{
	dnslib_node_t *f = NULL;
	int ret = dnslib_zone_tree_get(tree, owner, &f);
	*found = f;
	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_get(dnslib_zone_tree_t *tree, const dnslib_dname_t *owner,
                         dnslib_node_t **found)
{
	if (tree == NULL || owner == NULL) {
		return DNSLIB_EBADARG;
	}

	*found = NULL;

	// create dummy node to use for lookup
	dnslib_zone_tree_node_t *tmp = (dnslib_zone_tree_node_t *)malloc(
	                                       sizeof(dnslib_zone_tree_node_t));
	if (tmp == NULL) {
		return DNSLIB_ENOMEM;
	}

	// create dummy data node to use for lookup
	dnslib_node_t *tmp_data = dnslib_node_new(
	                              (dnslib_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	dnslib_zone_tree_node_t *n = TREE_FIND(tree, dnslib_zone_tree_node, avl,
	                                       tmp);

	dnslib_node_free(&tmp_data, 0, 0);
	free(tmp);

	if (n != NULL) {
		*found = n->node;
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_find_less_or_equal(dnslib_zone_tree_t *tree,
                                        const dnslib_dname_t *owner,
                                        const dnslib_node_t **found,
                                        const dnslib_node_t **previous)
{
	dnslib_node_t *f, *p;
	int ret = dnslib_zone_tree_get_less_or_equal(tree, owner, &f, &p);

	*found = f;
	*previous = p;

	return ret;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_get_less_or_equal(dnslib_zone_tree_t *tree,
                                       const dnslib_dname_t *owner,
                                       dnslib_node_t **found,
                                       dnslib_node_t **previous)
{
	if (tree == NULL || owner == NULL || found == NULL
	    || previous == NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_zone_tree_node_t *f = NULL, *prev = NULL;

	// create dummy node to use for lookup
	dnslib_zone_tree_node_t *tmp = (dnslib_zone_tree_node_t *)malloc(
	                                       sizeof(dnslib_zone_tree_node_t));
	if (tmp == NULL) {
		return DNSLIB_ENOMEM;
	}

	// create dummy data node to use for lookup
	dnslib_node_t *tmp_data = dnslib_node_new(
	                              (dnslib_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	int exact_match = TREE_FIND_LESS_EQUAL(
	                  tree, dnslib_zone_tree_node, avl, tmp, &f, &prev);

	dnslib_node_free(&tmp_data, 0, 0);
	free(tmp);

	*found = (exact_match) ? f->node : NULL;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(f != NULL);
		*previous = dnslib_node_get_previous(f->node, 1);
	} else {
		// otherwise check if the previous node is not an empty
		// non-terminal
		*previous = (dnslib_node_rrset_count(prev->node) == 0)
		            ? dnslib_node_get_previous(prev->node, 1)
		            : prev->node;
	}

	return exact_match;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_remove(dnslib_zone_tree_t *tree,
                            const dnslib_dname_t *owner,
                            dnslib_node_t **removed)
{
	if (tree == NULL || owner == NULL) {
		return DNSLIB_EBADARG;
	}

	// create dummy node to use for lookup
	dnslib_zone_tree_node_t *tmp = (dnslib_zone_tree_node_t *)malloc(
	                                       sizeof(dnslib_zone_tree_node_t));
	if (tmp == NULL) {
		return DNSLIB_ENOMEM;
	}

	// create dummy data node to use for lookup
	dnslib_node_t *tmp_data = dnslib_node_new(
	                              (dnslib_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	// we must first find the node, so that it may be destroyed
	dnslib_zone_tree_node_t *n = TREE_FIND(tree, dnslib_zone_tree_node, avl,
	                                       tmp);

	/*! \todo How to know if this was successful? */
	TREE_REMOVE(tree, dnslib_zone_tree_node, avl, tmp);

	dnslib_node_free(&tmp_data, 0, 0);
	free(tmp);

	*removed = n->node;
	free(n);
	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_forward_apply_inorder(dnslib_zone_tree_t *tree,
                                           void (*function)(
                                               dnslib_zone_tree_node_t *node,
                                               void *data),
                                           void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_FORWARD_APPLY(tree, dnslib_zone_tree_node, avl,
	                   function, data);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_forward_apply_postorder(dnslib_zone_tree_t *tree,
                                             void (*function)(
                                                 dnslib_zone_tree_node_t *node,
                                                 void *data),
                                             void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_POST_ORDER_APPLY(tree, dnslib_zone_tree_node, avl,
	                      function, data);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_reverse_apply_inorder(dnslib_zone_tree_t *tree,
                                           void (*function)(
                                               dnslib_zone_tree_node_t *node,
                                               void *data),
                                           void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_REVERSE_APPLY(tree, dnslib_zone_tree_node, avl,
	                   function, data);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_reverse_apply_postorder(dnslib_zone_tree_t *tree,
                                             void (*function)(
                                                 dnslib_zone_tree_node_t *node,
                                                 void *data),
                                             void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_REVERSE_APPLY_POST(tree, dnslib_zone_tree_node, avl,
	                        function, data);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_copy(dnslib_zone_tree_t *from, dnslib_zone_tree_t *to)
{
	/*
	 * This function will copy the tree by hand, so that the nodes
	 * do not have to be inserted the normal way. It should be substantially
	 * faster.
	 */

	to->th_cmp = from->th_cmp;

	return dnslib_zone_tree_copy_node(from->th_root, &to->th_root);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_free(dnslib_zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	dnslib_zone_tree_free_node((*tree)->th_root, 0, 0);
	free(*tree);
	*tree = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_deep_free(dnslib_zone_tree_t **tree, int free_owners)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}
	dnslib_zone_tree_free_node((*tree)->th_root, 1, free_owners);
	free(*tree);
	*tree = NULL;
}

/*----------------------------------------------------------------------------*/
