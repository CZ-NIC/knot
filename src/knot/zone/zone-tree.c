/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

int zone_tree_insert(zone_tree_t *tree, zone_node_t *node)
{
	if (tree == NULL || node == NULL) {
		return KNOT_EINVAL;
	}

	assert(node->owner);
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(node->owner, lf_storage);
	assert(lf);

	*trie_get_ins(tree, lf + 1, *lf) = node;

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

	trie_val_t *val = trie_get_try(tree, lf + 1, *lf);
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
	int ret = trie_get_leq(tree, lf + 1, *lf, &fval);
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
		zone_tree_it_t it = { 0 };
		ret = zone_tree_it_begin(tree, &it);
		if (ret != KNOT_EOK) {
			return ret;
		}
		*previous = zone_tree_it_val(&it); /* leftmost */
		*previous = (*previous)->prev; /* rightmost */
		*found = NULL;
		zone_tree_it_free(&it);
	}

	return exact_match;
}

/*! \brief Removes node with the given owner from the zone tree. */
void zone_tree_remove_node(zone_tree_t *tree, const knot_dname_t *owner)
{
	if (zone_tree_is_empty(tree) || owner == NULL) {
		return;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(owner, lf_storage);
	assert(lf);

	trie_val_t *rval = trie_get_try(tree, lf + 1, *lf);
	if (rval != NULL) {
		trie_del(tree, lf + 1, *lf, NULL);
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

void zone_tree_delete_empty(zone_tree_t *tree, zone_node_t *node)
{
	if (tree == NULL || node == NULL) {
		return;
	}

	if (node->rrset_count == 0 && node->children == 0) {
		zone_node_t *parent_node = node->parent;
		if (parent_node != NULL) {
			parent_node->children--;
			fix_wildcard_child(parent_node, node->owner);
			if (!(parent_node->flags & NODE_FLAGS_APEX)) { /* Is not apex */
				// Recurse using the parent node, do not delete possibly empty parent.
				zone_tree_delete_empty(tree, parent_node);
			}
		}

		// Delete node
		zone_tree_remove_node(tree, node->owner);
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

int zone_tree_it_begin(zone_tree_t *tree, zone_tree_it_t *it)
{
	if (it->tree == NULL) {
		it->it = trie_it_begin((trie_t *)tree);
		if (it->it == NULL) {
			return KNOT_ENOMEM;
		}
		it->tree = tree;
	}
	return KNOT_EOK;
}

bool zone_tree_it_finished(zone_tree_it_t *it)
{
	return it->it == NULL || trie_it_finished(it->it);
}

zone_node_t *zone_tree_it_val(zone_tree_it_t *it)
{
	return (zone_node_t *)*trie_it_val(it->it);
}

void zone_tree_it_next(zone_tree_it_t *it)
{
	trie_it_next(it->it);
}

void zone_tree_it_free(zone_tree_it_t *it)
{
	trie_it_free(it->it);
	memset(it, 0, sizeof(*it));
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
