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

static inline zone_node_t *fix_get(zone_node_t *node, const zone_tree_t *tree)
{
	return binode_node(node, (tree->flags & ZONE_TREE_USE_BINODES) && (tree->flags & ZONE_TREE_BINO_SECOND));
}

typedef struct {
	zone_tree_apply_cb_t func;
	void *data;
	const zone_tree_t *tree;
} zone_tree_func_t;

static int tree_apply_cb(trie_val_t *node, void *data)
{
	zone_tree_func_t *f = (zone_tree_func_t *)data;
	zone_node_t *n = fix_get(*node, f->tree);
	return f->func(n, f->data);
}

zone_tree_t *zone_tree_create(bool use_binodes)
{
	zone_tree_t *t = calloc(1, sizeof(*t));
	if (t != NULL) {
		if (use_binodes) {
			t->flags = ZONE_TREE_USE_BINODES;
		}
		t->trie = trie_create(NULL);
		if (t->trie == NULL) {
			free(t);
			t = NULL;
		}
	}
	return t;
}

static void *identity(void *x, knot_mm_t *mm)
{
	UNUSED(mm);
	return x;
}

zone_tree_t *zone_tree_dup(zone_tree_t *from)
{
	zone_tree_t *to = calloc(1, sizeof(*to));
	if (to == NULL) {
		return to;
	}
	to->flags = from->flags ^ ZONE_TREE_BINO_SECOND;
	to->trie = trie_dup(from->trie, identity, NULL);
	if (to->trie == NULL) {
		free(to);
		to = NULL;
	}
	return to;
}

int zone_tree_insert(zone_tree_t *tree, zone_node_t **node)
{
	if (tree == NULL || node == NULL || *node == NULL) {
		return KNOT_EINVAL;
	}

	assert((*node)->owner);
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf((*node)->owner, lf_storage);
	assert(lf);

	assert((bool)((*node)->flags & NODE_FLAGS_BINODE) == (bool)(tree->flags & ZONE_TREE_USE_BINODES));

	*trie_get_ins(tree->trie, lf + 1, *lf) = binode_node(*node, false);

	*node = binode_node(*node, (tree->flags & ZONE_TREE_USE_BINODES) && (tree->flags & ZONE_TREE_BINO_SECOND));

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

	trie_val_t *val = trie_get_try(tree->trie, lf + 1, *lf);
	if (val == NULL) {
		return NULL;
	}
	assert((bool)(((zone_node_t *)*val)->flags & NODE_FLAGS_BINODE) == (bool)(tree->flags & ZONE_TREE_USE_BINODES));

	return fix_get(*val, tree);
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
	int ret = trie_get_leq(tree->trie, lf + 1, *lf, &fval);
	if (fval != NULL) {
		assert((bool)(((zone_node_t *)*fval)->flags & NODE_FLAGS_BINODE) == (bool)(tree->flags & ZONE_TREE_USE_BINODES));
		*found = fix_get(*fval, tree);
	}

	int exact_match = 0;
	if (ret == KNOT_EOK) {
		if (fval != NULL) {
			*previous = node_prev(*found);
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
		*previous = fix_get(*previous, tree);
		*previous = node_prev(*previous); /* rightmost */
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

	trie_val_t *rval = trie_get_try(tree->trie, lf + 1, *lf);
	if (rval != NULL) {
		trie_del(tree->trie, lf + 1, *lf, NULL);
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

void zone_tree_delete_empty(zone_tree_t *tree, zone_node_t *node,
                            node_addrem_cb rem_node_cb, void *rem_node_ctx)
{
	if (tree == NULL || node == NULL) {
		return;
	}

	if (node->rrset_count == 0 && node->children == 0) {
		zone_node_t *parent_node = node_parent(node);
		if (parent_node != NULL) {
			parent_node->children--;
			fix_wildcard_child(parent_node, node->owner);
			if (!(parent_node->flags & NODE_FLAGS_APEX)) { /* Is not apex */
				// Recurse using the parent node, do not delete possibly empty parent.
				zone_tree_delete_empty(tree, parent_node, rem_node_cb, rem_node_ctx);
			}
		}

		// Delete node
		assert(!(node->flags & NODE_FLAGS_DELETED));
		zone_tree_remove_node(tree, node->owner);
		node->flags |= NODE_FLAGS_DELETED;
		if (rem_node_cb != NULL) {
			rem_node_cb(node, rem_node_ctx);
		}
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

	zone_tree_func_t f = {
		.func = function,
		.data = data,
		.tree = tree,
	};

	return trie_apply(tree->trie, tree_apply_cb, &f);
}

int zone_tree_it_begin(zone_tree_t *tree, zone_tree_it_t *it)
{
	if (it->tree == NULL) {
		it->it = trie_it_begin(tree->trie);
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
	return fix_get(*trie_it_val(it->it), it->tree);
}

void zone_tree_it_del(zone_tree_it_t *it)
{
	trie_it_del(it->it);
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

static int binode_unify_cb(zone_node_t *node, void *ctx)
{
	UNUSED(ctx);
	binode_unify(node, true, NULL);
	return KNOT_EOK;
}

#include <stdio.h>
static int check_deleted(zone_node_t *node, void *v)
{
	UNUSED(v);
	if ((node->flags & NODE_FLAGS_DELETED)) {
		bool cdel = (binode_counterpart(node)->flags & NODE_FLAGS_DELETED);
		printf("DELETED %s (counter %d)\n", node->owner, cdel);
	}
	return 0;
}

void zone_trees_unify_binodes(zone_tree_t *nodes, zone_tree_t *nsec3_nodes)
{
	if (nodes != NULL) {
		zone_tree_apply(nodes, binode_unify_cb, NULL);
	}
	if (nsec3_nodes != NULL) {
		zone_tree_apply(nsec3_nodes, binode_unify_cb, NULL);
	}
}

void zone_tree_check_del(zone_tree_t *nodes, zone_tree_t *nsec3_nodes)
{
	if (nodes != NULL) {
		zone_tree_apply(nodes, check_deleted, NULL);
	}
	if (nsec3_nodes != NULL) {
		zone_tree_apply(nsec3_nodes, check_deleted, NULL);
	}
}

void zone_tree_free(zone_tree_t **tree)
{
	if (tree == NULL || *tree == NULL) {
		return;
	}

	trie_free((*tree)->trie);
	free(*tree);
	*tree = NULL;
}
