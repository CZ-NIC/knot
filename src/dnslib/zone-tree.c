#include "dnslib/zone-tree.h"
#include "dnslib/node.h"
#include "dnslib/error.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

// AVL tree functions
TREE_DEFINE(dnslib_zone_tree_node, avl);

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_init(dnslib_zone_tree_t *tree)
{
	TREE_INIT(tree, dnslib_node_compare);
}

/*----------------------------------------------------------------------------*/

int dnslib_zone_tree_insert(dnslib_zone_tree_t *tree, dnslib_node_t *node)
{
	if (tree == NULL || node = NULL) {
		return DNSLIB_EBADARG;
	}

	dnslib_zone_tree_node_t *znode = (dnslib_zone_tree_node_t *)malloc(
	                                       sizeof(dnslib_zone_tree_node_t));
	if (znode == NULL) {
		return DNSLIB_ENOMEM;
	}

	znode->node = node;

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
	dnslib_node_t *tmp_data = dnslib_node_new(owner, NULL);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	dnslib_zone_tree_node_t *n = TREE_FIND(tree, dnslib_zone_tree_node, avl,
	                                       tmp);

	dnslib_node_free(&tmp_data, 0);
	free(tmp);

	*found = n;
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
	if (tree == NULL || owner == NULL || found == NULL || prev == NULL) {
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
	dnslib_node_t *tmp_data = dnslib_node_new(owner, NULL);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	int exact_match = TREE_FIND_LESS_EQUAL(
	                  tree, dnslib_zone_tree_node, avl, tmp, &f, &prev);

	dnslib_node_free(&tmp_data, 0);
	free(tmp);

	*found = (exact_match) ? f : NULL;

	if (prev == NULL) {
		// either the returned node is the root of the tree, or it is
		// the leftmost node in the tree; in both cases node was found
		// set the previous node of the found node
		assert(exact_match);
		assert(f != NULL);
		*previous = dnslib_node_previous(f->node);
	} else {
		// otherwise check if the previous node is not an empty
		// non-terminal
		*previous = (dnslib_node_rrset_count(prev->node) == 0)
		            ? dnslib_node_previous(prev->node)
		            : prev->node;
	}

	return exact_match;
}

/*----------------------------------------------------------------------------*/

dnslib_node_t *dnslib_zone_tree_remove(dnslib_zone_tree_t *tree,
                                       const dnslib_dname_t *owner)
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
	dnslib_node_t *tmp_data = dnslib_node_new(owner, NULL);
	if (tmp_data == NULL) {
		free(tmp);
		return DNSLIB_ENOMEM;
	}
	tmp->node = tmp_data;

	// we must first find the node, so that it may be destroyed
	dnslib_zone_tree_node_t *n = TREE_FIND(tree, dnslib_zone_tree_node, avl,
	                                       tmp);

	/*! \todo How to know if this was successful? */
	TREE_REMOVE(tree, dnslib_zone_node, avl, tmp);

	dnslib_node_free(&tmp_data, 0);
	free(tmp);

	dnslib_node_t *ret = n->node;
	free(n);
	return ret;
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_forward_apply_inorder(dnslib_zone_tree_t *tree,
                                            void (*function)(
                                            dnslib_node_t *node, void *data),
                                            void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_FORWARD_APPLY(tree, dnslib_zone_tree_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_forward_apply_postorder(dnslib_zone_tree_t *tree,
                                              void (*function)(
                                              dnslib_node_t *node, void *data),
                                              void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_POST_ORDER_APPLY(tree, dnslib_zone_tree_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/

void dnslib_zone_tree_reverse_apply_inorder(dnslib_zone_tree_t *tree,
                                            void (*function)(
                                            dnslib_node_t *node, void *data),
                                            void *data)
{
	if (tree == NULL || function == NULL) {
		return DNSLIB_EBADARG;
	}

	TREE_REVERSE_APPLY(tree, dnslib_zone_tree_node, avl, function, data);
}

/*----------------------------------------------------------------------------*/
