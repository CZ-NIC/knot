/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>

#include "knot/zone/zone-tree.h"
#include "libknot/consts.h"
#include "libknot/errcode.h"
#include "contrib/macros.h"

zone_tree_t *zone_tree_create(void)
{
	return trie_create(NULL);
}

int zone_tree_insert(zone_tree_t *tree, trie_cow_t *cow, zone_node_t *node)
{
	if (tree == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	assert(node->owner);
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(node->owner, lf_storage);
	assert(lf);

	if (cow != NULL) {
		*trie_get_cow(cow, (char *)lf + 1, *lf) = node;
	} else {
		*trie_get_ins(tree, (char *)lf + 1, *lf) = node;
	}

	return KNOT_EOK;
}

zone_node_t *zone_tree_get(zone_tree_t *tree, const knot_dname_t *owner)
{
	if (owner == NULL) {
		return NULL;
	}

	if (zone_tree_is_empty(tree)) {
		return NULL;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(owner, lf_storage);
	assert(lf);

	trie_val_t *val = trie_get_try(tree, (char *)lf + 1, *lf);
	if (val == NULL) {
		return NULL;
	}

	return *val;
}

int zone_tree_get_less_or_equal(zone_tree_t *tree,
                                const knot_dname_t *owner,
                                zone_node_t **found,
                                zone_node_t **previous)
{
	if (owner == NULL || found == NULL || previous == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_ENONODE;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(owner, lf_storage);
	assert(lf);

	trie_val_t *fval = NULL;
	int ret = trie_get_leq(tree, (char *)lf + 1, *lf, &fval);
	if (fval != NULL) {
		*found = (zone_node_t *)(*fval);
	}

	int exact_match = 0;
	if (ret == KNOT_EOK) {
		if (fval != NULL) {
			*previous = (*found)->prev;
		}
		exact_match = 1;
	} else if (ret == 1) {
		*previous = *found;
		*found = NULL;
	} else {
		/* Previous should be the rightmost node.
		 * For regular zone it is the node left of apex, but for some
		 * cases like NSEC3, there is no such sort of thing (name wise).
		 */
		/*! \todo We could store rightmost node in zonetree probably. */
		trie_it_t *i = trie_it_begin(tree);
		*previous = *(zone_node_t **)trie_it_val(i); /* leftmost */
		*previous = (*previous)->prev; /* rightmost */
		*found = NULL;
		trie_it_free(i);
	}

	return exact_match;
}

/*! \brief Removes node with the given owner from the zone tree. */
static void remove_node(zone_tree_t *tree, trie_cow_t *cow, const knot_dname_t *owner)
{
	assert(owner);

	if (zone_tree_is_empty(tree)) {
		return;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(owner, lf_storage);
	assert(lf);

	trie_val_t *rval = trie_get_try(tree, (char *)lf + 1, *lf);
	if (rval != NULL) {
		if (cow != NULL) {
			trie_del_cow(cow, (char *)lf + 1, *lf, NULL);
		} else {
			trie_del(tree, (char *)lf + 1, *lf, NULL);
		}
	}
}

/*! \brief Clears wildcard child if set in parent node. */
static void fix_wildcard_child(zone_node_t *node, const knot_dname_t *owner)
{
	if ((node->flags & NODE_FLAGS_WILDCARD_CHILD)
	    && knot_dname_is_wildcard(owner)) {
		node->flags &= ~NODE_FLAGS_WILDCARD_CHILD;
	}
}

void zone_tree_delete_empty(zone_tree_t *tree, trie_cow_t *cow, zone_node_t *node)
{
	if (tree == NULL || node == NULL) {
		return;
	}

	if (node->rrset_count == 0 && node->children == 0) {
		zone_node_t *parent_node = node->parent;
		if (parent_node != NULL) {
			parent_node->children--;
			fix_wildcard_child(parent_node, node->owner);
			if (parent_node->parent != NULL) { /* Is not apex */
				// Recurse using the parent node, do not delete possibly empty parent.
				zone_tree_delete_empty(tree, cow, parent_node);
			}
		}

		// Delete node
		remove_node(tree, cow, node->owner);
		node_free(node, NULL);
	}
}

int zone_tree_apply(zone_tree_t *tree, zone_tree_apply_cb_t function, void *data)
{
	if (function == NULL) {
		return KNOT_EINVAL;
	}

	if (zone_tree_is_empty(tree)) {
		return KNOT_EOK;
	}

	return trie_apply(tree, (int (*)(trie_val_t *, void *))function, data);
}

void zone_tree_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	trie_free(*tree);
	*tree = NULL;
}

static int zone_tree_free_node(zone_node_t **node, void *data)
{
	UNUSED(data);

	if (node) {
		node_free(*node, NULL);
	}

	return KNOT_EOK;
}

void zone_tree_deep_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	(void)zone_tree_apply(*tree, zone_tree_free_node, NULL);
	zone_tree_free(tree);
}
