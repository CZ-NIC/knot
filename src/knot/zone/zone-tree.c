/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "libknot/packet/wire.h"

typedef struct {
	zone_tree_apply_cb_t func;
	void *data;
	int binode_second;
} zone_tree_func_t;

static int tree_apply_cb(trie_val_t *node, void *data)
{
	zone_tree_func_t *f = (zone_tree_func_t *)data;
	zone_node_t *n = (zone_node_t *)(*node) + f->binode_second;
	assert(!f->binode_second || (n->flags & NODE_FLAGS_SECOND));
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

zone_tree_t *zone_tree_cow(zone_tree_t *from)
{
	zone_tree_t *to = calloc(1, sizeof(*to));
	if (to == NULL) {
		return to;
	}
	to->flags = from->flags ^ ZONE_TREE_BINO_SECOND;
	from->cow = trie_cow(from->trie, NULL, NULL);
	to->cow = from->cow;
	to->trie = trie_cow_new(to->cow);
	if (to->trie == NULL) {
		free(to);
		to = NULL;
	}
	return to;
}

static trie_val_t nocopy(const trie_val_t val, _unused_ knot_mm_t *mm)
{
	return val;
}

zone_tree_t *zone_tree_shallow_copy(zone_tree_t *from)
{
	zone_tree_t *to = calloc(1, sizeof(*to));
	if (to == NULL) {
		return to;
	}
	to->flags = from->flags;
	to->trie = trie_dup(from->trie, nocopy, NULL);
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

	if (tree->cow != NULL) {
		*trie_get_cow(tree->cow, lf + 1, *lf) = binode_first(*node);
	} else {
		*trie_get_ins(tree->trie, lf + 1, *lf) = binode_first(*node);
	}

	*node = zone_tree_fix_get(*node, tree);

	return KNOT_EOK;
}

int zone_tree_insert_with_parents(zone_tree_t *tree, zone_node_t *node, bool without_parents)
{
	int ret = KNOT_EOK;
	do {
		ret = zone_tree_insert(tree, &node);
		node = node->parent;
	} while (node != NULL && ret == KNOT_EOK && !without_parents);
	return ret;
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

	return zone_tree_fix_get(*val, tree);
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
		*found = zone_tree_fix_get(*fval, tree);
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
		assert(*previous != NULL); // cppcheck
		*previous = zone_tree_fix_get(*previous, tree);
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
		if (tree->cow != NULL) {
			trie_del_cow(tree->cow, lf + 1, *lf, NULL);
		} else {
			trie_del(tree->trie, lf + 1, *lf, NULL);
		}
	}
}

int zone_tree_add_node(zone_tree_t *tree, zone_node_t *apex, const knot_dname_t *dname,
                       zone_tree_new_node_cb_t new_cb, void *new_cb_ctx, zone_node_t **new_node)
{
	int in_bailiwick = knot_dname_in_bailiwick(dname, apex->owner);
	if (in_bailiwick == 0) {
		*new_node = apex;
		return KNOT_EOK;
	} else if (in_bailiwick < 0) {
		return KNOT_EOUTOFZONE;
	}

	*new_node = zone_tree_get(tree, dname);
	if (*new_node == NULL) {
		*new_node = new_cb(dname, new_cb_ctx);
		if (*new_node == NULL) {
			return KNOT_ENOMEM;
		}
		int ret = zone_tree_insert(tree, new_node);
		assert(!((*new_node)->flags & NODE_FLAGS_DELETED));
		if (ret != KNOT_EOK) {
			return ret;
		}
		zone_node_t *parent = NULL;
		ret = zone_tree_add_node(tree, apex, knot_wire_next_label(dname, NULL), new_cb, new_cb_ctx, &parent);
		if (ret != KNOT_EOK) {
			return ret;
		}
		(*new_node)->parent = parent;
		if (parent != NULL) {
			parent->children++;
			if (knot_dname_is_wildcard(dname)) {
				parent->flags |= NODE_FLAGS_WILDCARD_CHILD;
			}
		}
	}
	return KNOT_EOK;
}

int zone_tree_del_node(zone_tree_t *tree, zone_node_t *node, bool free_deleted)
{
	zone_node_t *parent = node_parent(node);
	bool wildcard = knot_dname_is_wildcard(node->owner);

	node->parent = NULL;
	node->flags |= NODE_FLAGS_DELETED;
	zone_tree_remove_node(tree, node->owner);

	if (free_deleted) {
		node_free(node, NULL);
	}

	int ret = KNOT_EOK;
	if (ret == KNOT_EOK && parent != NULL) {
		parent->children--;
		if (wildcard) {
			parent->flags &= ~NODE_FLAGS_WILDCARD_CHILD;
		}
		if (parent->children == 0 && parent->rrset_count == 0 &&
		    !(parent->flags & NODE_FLAGS_APEX)) {
			ret = zone_tree_del_node(tree, parent, free_deleted);
		}
	}
	return ret;
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
		.binode_second = ((tree->flags & ZONE_TREE_BINO_SECOND) ? 1 : 0),
	};

	return trie_apply(tree->trie, tree_apply_cb, &f);
}

int zone_tree_sub_apply(zone_tree_t *tree, const knot_dname_t *sub_root,
                        bool excl_root, zone_tree_apply_cb_t function, void *data)
{
	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_sub_begin(tree, sub_root, &it);
	if (excl_root && ret == KNOT_EOK && !zone_tree_it_finished(&it)) {
		zone_tree_it_next(&it);
	}
	while (ret == KNOT_EOK && !zone_tree_it_finished(&it)) {
		ret = function(zone_tree_it_val(&it), data);
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	return ret;
}

int zone_tree_it_begin(zone_tree_t *tree, zone_tree_it_t *it)
{
	return zone_tree_it_double_begin(tree, NULL, it);
}

int zone_tree_it_sub_begin(zone_tree_t *tree, const knot_dname_t *sub_root,
                           zone_tree_it_t *it)
{
	if (tree == NULL || sub_root == NULL) {
		return KNOT_EINVAL;
	}
	int ret = zone_tree_it_begin(tree, it);
	if (ret != KNOT_EOK) {
		return ret;
	}
	it->sub_root = knot_dname_copy(sub_root, NULL);
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(sub_root, lf_storage);
	ret = trie_it_get_leq(it->it, lf + 1, *lf);
	if ((ret != KNOT_EOK && ret != KNOT_ENOENT) || it->sub_root == NULL) {
		zone_tree_it_free(it);
		return ret == KNOT_EOK ? KNOT_ENOMEM : ret;
	}
	return KNOT_EOK;
}

int zone_tree_it_double_begin(zone_tree_t *first, zone_tree_t *second, zone_tree_it_t *it)
{
	if (it->tree == NULL) {
		it->it = trie_it_begin(first->trie);
		if (it->it == NULL) {
			return KNOT_ENOMEM;
		}
		if (trie_it_finished(it->it) && second != NULL) { // first tree is empty
			trie_it_free(it->it);
			it->it = trie_it_begin(second->trie);
			it->tree = second;
			it->next_tree = NULL;
		} else {
			it->tree = first;
			it->next_tree = second;
		}
		it->binode_second = ((it->tree->flags & ZONE_TREE_BINO_SECOND) ? 1 : 0);
	}
	return KNOT_EOK;
}

static bool sub_done(zone_tree_it_t *it)
{
	return it->sub_root != NULL &&
	       knot_dname_in_bailiwick(zone_tree_it_val(it)->owner, it->sub_root) < 0;
}

bool zone_tree_it_finished(zone_tree_it_t *it)
{
	return it->it == NULL || it->tree == NULL || trie_it_finished(it->it) || sub_done(it);
}

zone_node_t *zone_tree_it_val(zone_tree_it_t *it)
{
	zone_node_t *node = (zone_node_t *)(*trie_it_val(it->it)) + it->binode_second;
	assert(!it->binode_second || (node->flags & NODE_FLAGS_SECOND));
	return node;
}

void zone_tree_it_del(zone_tree_it_t *it)
{
	trie_it_del(it->it);
}

void zone_tree_it_next(zone_tree_it_t *it)
{
	trie_it_next(it->it);
	if (it->next_tree != NULL && trie_it_finished(it->it)) {
		trie_it_free(it->it);
		it->tree = it->next_tree;
		it->binode_second = ((it->tree->flags & ZONE_TREE_BINO_SECOND) ? 1 : 0);
		it->next_tree = NULL;
		it->it = trie_it_begin(it->tree->trie);
		assert(it->sub_root == NULL);
	}
}

void zone_tree_it_free(zone_tree_it_t *it)
{
	trie_it_free(it->it);
	knot_dname_free(it->sub_root, NULL);
	memset(it, 0, sizeof(*it));
}

int zone_tree_delsafe_it_begin(zone_tree_t *tree, zone_tree_delsafe_it_t *it, bool include_deleted)
{
	it->incl_del = include_deleted;
	it->total = zone_tree_count(tree);
	if (it->total == 0) {
		it->current = 0;
		it->nodes = NULL;
		return KNOT_EOK;
	}
	it->nodes = malloc(it->total * sizeof(*it->nodes));
	if (it->nodes == NULL) {
		return KNOT_ENOMEM;
	}
	it->current = 0;

	zone_tree_it_t tmp = { 0 };
	int ret = zone_tree_it_begin(tree, &tmp);
	if (ret != KNOT_EOK) {
		return ret;
	}
	while (!zone_tree_it_finished(&tmp)) {
		it->nodes[it->current++] = zone_tree_it_val(&tmp);
		zone_tree_it_next(&tmp);
	}
	zone_tree_it_free(&tmp);
	assert(it->total == it->current);

	zone_tree_delsafe_it_restart(it);

	return KNOT_EOK;
}

bool zone_tree_delsafe_it_finished(zone_tree_delsafe_it_t *it)
{
	return (it->current >= it->total);
}

void zone_tree_delsafe_it_restart(zone_tree_delsafe_it_t *it)
{
	it->current = 0;

	while (!it->incl_del && !zone_tree_delsafe_it_finished(it) &&
	       (zone_tree_delsafe_it_val(it)->flags & NODE_FLAGS_DELETED)) {
		it->current++;
	}
}

zone_node_t *zone_tree_delsafe_it_val(zone_tree_delsafe_it_t *it)
{
	return it->nodes[it->current];
}

void zone_tree_delsafe_it_next(zone_tree_delsafe_it_t *it)
{
	do {
		it->current++;
	} while (!it->incl_del && !zone_tree_delsafe_it_finished(it) &&
		 (zone_tree_delsafe_it_val(it)->flags & NODE_FLAGS_DELETED));
}

void zone_tree_delsafe_it_free(zone_tree_delsafe_it_t *it)
{
	free(it->nodes);
	memset(it, 0, sizeof(*it));
}

static int merge_cb(zone_node_t *node, void *ctx)
{
	return zone_tree_insert(ctx, &node);
}

int zone_tree_merge(zone_tree_t *into, zone_tree_t *what)
{
	return zone_tree_apply(what, merge_cb, into);
}

static int binode_unify_cb(zone_node_t *node, void *ctx)
{
	binode_unify(node, *(bool *)ctx, NULL);
	return KNOT_EOK;
}

void zone_trees_unify_binodes(zone_tree_t *nodes, zone_tree_t *nsec3_nodes, bool free_deleted)
{
	if (nodes != NULL) {
		zone_tree_apply(nodes, binode_unify_cb, &free_deleted);
	}
	if (nsec3_nodes != NULL) {
		zone_tree_apply(nsec3_nodes, binode_unify_cb, &free_deleted);
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
