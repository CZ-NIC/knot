/* AVL implementation for checking. */

TREE_DEFINE(knot_zone_tree_node, avl);

static int knot_zone_tree_node_compare(knot_zone_tree_node_t *node1,
                                         knot_zone_tree_node_t *node2)
{
        assert(node1 != NULL);
        assert(node2 != NULL);
        assert(node1->node != NULL);
        assert(node2->node != NULL);
        assert(knot_node_owner(node1->node) != NULL);
        assert(knot_node_owner(node2->node) != NULL);

        return knot_node_compare(node1->node, node2->node);
}

static void knot_zone_tree_free_node(knot_zone_tree_node_t *node,
                                       int free_data)
{
        if (node == NULL) {
                return;
        }

        knot_zone_tree_free_node(node->avl.avl_left, free_data);

        knot_zone_tree_free_node(node->avl.avl_right, free_data);

        if (free_data) {
                knot_node_free(&node->node);
        }

        free(node);
}

static void knot_zone_tree_delete_subtree(knot_zone_tree_node_t *root)
{
	if (root == NULL) {
		return;
	}

	knot_zone_tree_delete_subtree(root->avl.avl_left);
	knot_zone_tree_delete_subtree(root->avl.avl_right);
	free(root);
}

static int knot_zone_tree_copy_node(knot_zone_tree_node_t *from,
                                      knot_zone_tree_node_t **to)
{
	if (from == NULL) {
		*to = NULL;
		return KNOT_EOK;
	}

	*to = (knot_zone_tree_node_t *)
	      malloc(sizeof(knot_zone_tree_node_t));
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}

	(*to)->node = from->node;
	(*to)->avl.avl_height = from->avl.avl_height;

	int ret = knot_zone_tree_copy_node(from->avl.avl_left,
	                                     &(*to)->avl.avl_left);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_zone_tree_copy_node(from->avl.avl_right,
	                                 &(*to)->avl.avl_right);
	if (ret != KNOT_EOK) {
		knot_zone_tree_delete_subtree((*to)->avl.avl_left);
		(*to)->avl.avl_left = NULL;
		free(*to);
		*to = NULL;
		return ret;
	}

	return KNOT_EOK;
}


static int knot_zone_tree_deep_copy_node(knot_zone_tree_node_t *from,
                                         knot_zone_tree_node_t **to)
{
	if (from == NULL) {
		*to = NULL;
		return KNOT_EOK;
	}

	*to = (knot_zone_tree_node_t *)malloc(sizeof(knot_zone_tree_node_t));
	if (*to == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = knot_node_shallow_copy(from->node, &(*to)->node);

	if (ret != KNOT_EOK) {
		dbg_zone_verb("Failed to do shallow copy of node.\n");
		free(*to);
		return ret;
	}

	(*to)->avl.avl_height = from->avl.avl_height;

	ret = knot_zone_tree_deep_copy_node(from->avl.avl_left,
	                                    &(*to)->avl.avl_left);
	if (ret != KNOT_EOK) {
		dbg_zone_verb("Failed to do shallow copy of left subtree.\n");
		return ret;
	}

	ret = knot_zone_tree_deep_copy_node(from->avl.avl_right,
	                                    &(*to)->avl.avl_right);
	if (ret != KNOT_EOK) {
		dbg_zone_verb("Failed to do shallow copy of right subtree.\n");
		knot_zone_tree_free_node((*to)->avl.avl_left, 1);
		(*to)->avl.avl_left = NULL;
		knot_node_free(&(*to)->node);
		free(*to);
		*to = NULL;
		return ret;
	}

	knot_node_set_new_node(from->node, (*to)->node);

	return KNOT_EOK;
}

static void avl_create(knot_zone_avl_tree_t *tree)
{
	TREE_INIT(tree, knot_zone_tree_node_compare);
}

static int avl_insert(knot_zone_avl_tree_t *tree, knot_zone_tree_node_t *znode)
{
	znode->avl.avl_left = NULL;
	znode->avl.avl_right = NULL;
	znode->avl.avl_height = 0;

	/*! \todo How to know if this was successful? */
	TREE_INSERT(tree, knot_zone_tree_node, avl, znode);

	return KNOT_EOK;
}


int avl_get(knot_zone_avl_tree_t *tree, const knot_dname_t *owner,
                         knot_node_t **found)
{
	if (tree == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	*found = NULL;

	// create dummy node to use for lookup
	knot_zone_tree_node_t *tmp = (knot_zone_tree_node_t *)malloc(
	                                       sizeof(knot_zone_tree_node_t));
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}

	// create dummy data node to use for lookup
	knot_node_t *tmp_data = knot_node_new(
	                              (knot_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return KNOT_ENOMEM;
	}
	tmp->node = tmp_data;

	knot_zone_tree_node_t *n = TREE_FIND(tree, knot_zone_tree_node, avl,
	                                       tmp);

	knot_node_free(&tmp_data);
	free(tmp);

	if (n != NULL) {
		*found = n->node;
	}

	return KNOT_EOK;
}

int avl_get_less_or_equal(knot_zone_avl_tree_t *tree,
                                       const knot_dname_t *owner,
                                       knot_node_t **found,
                                       knot_node_t **previous)
{
	if (tree == NULL || owner == NULL || found == NULL
	    || previous == NULL) {
		return KNOT_EINVAL;
	}

	knot_zone_tree_node_t *f = NULL, *prev = NULL;

	// create dummy node to use for lookup
	knot_zone_tree_node_t *tmp = (knot_zone_tree_node_t *)malloc(
	                                       sizeof(knot_zone_tree_node_t));
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}

	// create dummy data node to use for lookup
	knot_node_t *tmp_data = knot_node_new(
	                              (knot_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return KNOT_ENOMEM;
	}
	tmp->node = tmp_data;

	int exact_match = TREE_FIND_LESS_EQUAL(
	                  tree, knot_zone_tree_node, avl, tmp, &f, &prev);

	knot_node_free(&tmp_data);
	free(tmp);

	*found = (exact_match > 0) ? f->node : NULL;
	
	dbg_zone_exec_detail(
			char *name = knot_dname_to_str(owner);
			char *name_f = (*found != NULL)
				? knot_dname_to_str(knot_node_owner(*found))
				: "none";
	
			dbg_zone_detail("Searched for owner %s in zone tree.\n",
					name);
			dbg_zone_detail("Found node: %p: %s.\n", *found, name_f);
			dbg_zone_detail("Previous node: %p.\n", *previous);
	
			free(name);
			if (*found != NULL) {
				free(name_f);
			}
	);

	if (exact_match < 0) {
		// previous is not really previous but should be the leftmost
		// node in the tree; take it's previous
		assert(prev != NULL);
		*previous = knot_node_get_previous(prev->node);
		exact_match = 0;
	} else if (prev == NULL) {
		// either the returned node is the root of the tree, or
		// it is the leftmost node in the tree; in both cases
		// node was found set the previous node of the found
		// node
		assert(exact_match > 0);
		assert(f != NULL);
		*previous = knot_node_get_previous(f->node);
	} else {
		// otherwise check if the previous node is not an empty
		// non-terminal
		/*! \todo Here we assume that the 'prev' pointer always points
		 *        to an empty non-terminal.
		 */
		/*! \todo What did I mean by the previous TODO??
		 *        Nevertheless, it seems to me that node->prev can be
		 *        an empty non-terminal too, cannot it?
		 */
		dbg_zone_detail("Previous: %p\n", prev->node);
		*previous = (knot_node_rrset_count(prev->node) == 0)
		            ? knot_node_get_previous(prev->node)
		            : prev->node;
		dbg_zone_detail("Previous: %p, is empty: %d\n", *previous,
		                (*previous) ? knot_node_is_empty(*previous)
		                            : -1);
	}

	assert(exact_match >= 0);

	return exact_match;
}

int avl_remove(knot_zone_avl_tree_t *tree,
                            const knot_dname_t *owner,
                            knot_zone_tree_node_t **removed)
{
	if (tree == NULL || owner == NULL || removed == NULL) {
		return KNOT_EINVAL;
	}

	// create dummy node to use for lookup
	knot_zone_tree_node_t *tmp = (knot_zone_tree_node_t *)malloc(
	                                       sizeof(knot_zone_tree_node_t));
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}

	// create dummy data node to use for lookup
	knot_node_t *tmp_data = knot_node_new(
	                              (knot_dname_t *)owner, NULL, 0);
	if (tmp_data == NULL) {
		free(tmp);
		return KNOT_ENOMEM;
	}
	tmp->node = tmp_data;

	// we must first find the node, so that it may be destroyed
	knot_zone_tree_node_t *n = TREE_FIND(tree, knot_zone_tree_node, avl,
	                                       tmp);

	/*! \todo How to know if this was successful? */
	TREE_REMOVE(tree, knot_zone_tree_node, avl, tmp);

	knot_node_free(&tmp_data);
	free(tmp);

	*removed = n;
	
	return KNOT_EOK;
}

int  avl_forward_apply_inorder(knot_zone_avl_tree_t *tree,
                                           void (*function)(
                                               knot_zone_tree_node_t *node,
                                               void *data),
                                           void *data)
{
	if (tree == NULL || function == NULL) {
		return KNOT_EINVAL;
	}

	TREE_FORWARD_APPLY(tree, knot_zone_tree_node, avl,
	                   function, data);

	return KNOT_EOK;
}

int avl_forward_apply_postorder(knot_zone_avl_tree_t *tree,
                                             void (*function)(
                                                 knot_zone_tree_node_t *node,
                                                 void *data),
                                             void *data)
{
	if (tree == NULL || function == NULL) {
		return KNOT_EINVAL;
	}

	TREE_POST_ORDER_APPLY(tree, knot_zone_tree_node, avl,
	                      function, data);

	return KNOT_EOK;
}

int avl_shallow_copy(knot_zone_avl_tree_t *from,
                                  knot_zone_avl_tree_t *to)
{
	if (to == NULL || from == NULL) {
		return KNOT_EINVAL;
	}
	/*
	 * This function will copy the tree by hand, so that the nodes
	 * do not have to be inserted the normal way. It should be substantially
	 * faster.
	 */

	to->th_cmp = from->th_cmp;

	return knot_zone_tree_copy_node(from->th_root, &to->th_root);
}

int avl_deep_copy(knot_zone_avl_tree_t *from,
                  knot_zone_avl_tree_t *to)
{
	if (to == NULL || from == NULL) {
		return KNOT_EINVAL;
	}
	/*
	 * This function will copy the tree by hand, so that the nodes
	 * do not have to be inserted the normal way. It should be substantially
	 * faster.
	 */

	to->th_cmp = from->th_cmp;

	return knot_zone_tree_deep_copy_node(from->th_root, &to->th_root);
}

void avl_free(knot_zone_avl_tree_t *tree)
{
	if (tree == NULL) {
		return;
	}
	knot_zone_tree_free_node(tree->th_root, 0);
}


