/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "contrib/qp-trie/trie.h"
#include "contrib/ucw/lists.h"
#include "knot/zone/node.h"

enum {
	/*! Indication of a zone tree with bi-nodes (two zone_node_t structures allocated for one node). */
	ZONE_TREE_USE_BINODES = (1 << 0),
	/*! If set, from each bi-node in the zone tree, the second zone_node_t is valid. */
	ZONE_TREE_BINO_SECOND = (1 << 1),
};

typedef struct {
	trie_t *trie;
	trie_cow_t *cow; // non-NULL only during zone update
	uint16_t flags;
} zone_tree_t;

/*!
 * \brief Signature of callback for zone apply functions.
 */
typedef int (*zone_tree_apply_cb_t)(zone_node_t *node, void *data);

typedef zone_node_t *(*zone_tree_new_node_cb_t)(const knot_dname_t *dname, void *ctx);

/*!
 * \brief Zone tree iteration context.
 */
typedef struct {
	zone_tree_t *tree;
	trie_it_t *it;
	int binode_second;

	zone_tree_t *next_tree;
	knot_dname_t *sub_root;
} zone_tree_it_t;

typedef struct {
	zone_node_t **nodes;
	size_t total;
	size_t current;
	bool incl_del;
} zone_tree_delsafe_it_t;

/*!
 * \brief Creates the zone tree.
 *
 * \return created zone tree structure.
 */
zone_tree_t *zone_tree_create(bool use_binodes);

zone_tree_t *zone_tree_cow(zone_tree_t *from);

/*!
 * \brief Create a clone of existing zone_tree.
 *
 * \note Copies only the trie, not individual nodes.
 *
 * \warning Don't use COW in the duplicate.
 */
zone_tree_t *zone_tree_shallow_copy(zone_tree_t *from);

/*!
 * \brief Return number of nodes in the zone tree.
 *
 * \param tree Zone tree.
 *
 * \return number of nodes in tree.
 */
inline static size_t zone_tree_count(const zone_tree_t *tree)
{
	if (tree == NULL) {
		return 0;
	}

	return trie_weight(tree->trie);
}

/*!
 * \brief Checks if the zone tree is empty.
 *
 * \param tree Zone tree to check.
 *
 * \return Nonzero if the zone tree is empty.
 */
inline static bool zone_tree_is_empty(const zone_tree_t *tree)
{
	return zone_tree_count(tree) == 0;
}

inline static zone_node_t *zone_tree_fix_get(zone_node_t *node, const zone_tree_t *tree)
{
	assert(((node->flags & NODE_FLAGS_BINODE) ? 1 : 0) == ((tree->flags & ZONE_TREE_USE_BINODES) ? 1 : 0));
	assert((tree->flags & ZONE_TREE_USE_BINODES) || !(tree->flags & ZONE_TREE_BINO_SECOND));
	return binode_node(node, (tree->flags & ZONE_TREE_BINO_SECOND));
}

inline static zone_node_t *node_new_for_tree(const knot_dname_t *owner, const zone_tree_t *tree, knot_mm_t *mm)
{
	assert((tree->flags & ZONE_TREE_USE_BINODES) || !(tree->flags & ZONE_TREE_BINO_SECOND));
	return node_new(owner, (tree->flags & ZONE_TREE_USE_BINODES), (tree->flags & ZONE_TREE_BINO_SECOND), mm);
}

/*!
 * \brief Inserts the given node into the zone tree.
 *
 * \param tree Zone tree to insert the node into.
 * \param node Node to insert. If it's binode, the pointer will be adjusted to correct node.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_tree_insert(zone_tree_t *tree, zone_node_t **node);

/*!
 * \brief Insert a node together with its parents (iteratively node->parent).
 *
 * \param tree   Zone tree to insert into.
 * \param node   Node to be inserted with parents.
 * \param without_parents   Actually, insert it without parents.
 *
 * \return KNOT_E*
 */
int zone_tree_insert_with_parents(zone_tree_t *tree, zone_node_t *node, bool without_parents);

/*!
 * \brief Finds node with the given owner in the zone tree.
 *
 * \param tree Zone tree to search in.
 * \param owner Owner of the node to find.
 *
 * \retval Found node or NULL.
 */
zone_node_t *zone_tree_get(zone_tree_t *tree, const knot_dname_t *owner);

/*!
 * \brief Tries to find the given domain name in the zone tree and returns the
 *        associated node and previous node in canonical order.
 *
 * \param tree Zone to search in.
 * \param owner Owner of the node to find.
 * \param found Found node.
 * \param previous Previous node in canonical order (i.e. the one directly
 *                 preceding \a owner in canonical order, regardless if the name
 *                 is in the zone or not).
 *
 * \retval > 0 if the domain name was found. In such case \a found holds the
 *             zone node with \a owner as its owner.
 *             \a previous is set properly.
 * \retval 0 if the domain name was not found. \a found may hold any (or none)
 *           node. \a previous is set properly.
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_tree_get_less_or_equal(zone_tree_t *tree,
                                const knot_dname_t *owner,
                                zone_node_t **found,
                                zone_node_t **previous);

/*!
 * \brief Remove a node from a tree with no checks.
 *
 * \param tree  The tree to remove from.
 * \param owner The node to remove.
 */
void zone_tree_remove_node(zone_tree_t *tree, const knot_dname_t *owner);

/*!
 * \brief Create a node in zone tree if not already exists, and also all parent nodes.
 *
 * \param tree         Zone tree to insert into.
 * \param apex         Zone contents apex node.
 * \param dname        Name of the node to be added.
 * \param new_cb       Callback for allocating new node.
 * \param new_cb_ctx   Context to be passed to allocating callback.
 * \param new_node     Output: pointer on added (or existing) node with specified dname.
 *
 * \return KNOT_E*
 */
int zone_tree_add_node(zone_tree_t *tree, zone_node_t *apex, const knot_dname_t *dname,
                       zone_tree_new_node_cb_t new_cb, void *new_cb_ctx, zone_node_t **new_node);

/*!
 * \brief Remove a node in zone tree, removing also empty parents.
 *
 * \param tree          Zone tree to remove from.
 * \param node          Node to be removed.
 * \param free_deleted  Indication to free node.
 *
 * \return KNOT_E*
 */
int zone_tree_del_node(zone_tree_t *tree, zone_node_t *node, bool free_deleted);

/*!
 * \brief Applies the given function to each node in the zone in order.
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int zone_tree_apply(zone_tree_t *tree, zone_tree_apply_cb_t function, void *data);

/*!
 * \brief Applies given function to each node in a subtree.
 *
 * \param tree        Zone tree.
 * \param sub_root    Name denoting the subtree.
 * \param excl_root   Exclude the subtree root.
 * \param function    Callback to be applied.
 * \param data        Callback context.
 *
 * \return KNOT_E*
 */
int zone_tree_sub_apply(zone_tree_t *tree, const knot_dname_t *sub_root,
                        bool excl_root, zone_tree_apply_cb_t function, void *data);

/*!
 * \brief Start zone tree iteration.
 *
 * \param tree   Zone tree to iterate over.
 * \param it     Out: iteration context. It shall be zeroed before.
 *
 * \return KNOT_OK, KNOT_ENOMEM
 */
int zone_tree_it_begin(zone_tree_t *tree, zone_tree_it_t *it);

/*!
 * \brief Start iteration over a subtree.
 *
 * \param tree        Zone tree to iterate in.
 * \param sub_root    Iterate over node of this name and all children.
 * \param it          Out: iteration context, shall be zeroed before.
 *
 * \return KNOT_E*
 */
int zone_tree_it_sub_begin(zone_tree_t *tree, const knot_dname_t *sub_root,
                           zone_tree_it_t *it);

/*!
 * \brief Start iteration of two zone trees.
 *
 * This is useful e.g. for iteration over normal and NSEC3 nodes.
 *
 * \param first    First tree to be iterated over.
 * \param second   Second tree to be iterated over.
 * \param it       Out: iteration context. It shall be zeroed before.
 *
 * \return KNOT_OK, KNOT_ENOMEM
 */
int zone_tree_it_double_begin(zone_tree_t *first, zone_tree_t *second, zone_tree_it_t *it);

/*!
 * \brief Return true iff iteration is finished.
 *
 * \note The iteration context needs to be freed afterwards nevertheless.
 */
bool zone_tree_it_finished(zone_tree_it_t *it);

/*!
 * \brief Return the node, zone iteration is currently pointing at.
 *
 * \note Don't call this when zone_tree_it_finished.
 */
zone_node_t *zone_tree_it_val(zone_tree_it_t *it);

/*!
 * \brief Remove from zone tree the node that iteration is pointing at.
 *
 * \note This doesn't free the node.
 */
void zone_tree_it_del(zone_tree_it_t *it);

/*!
 * \brief Move the iteration to next node.
 */
void zone_tree_it_next(zone_tree_it_t *it);

/*!
 * \brief Free zone iteration context.
 */
void zone_tree_it_free(zone_tree_it_t *it);

/*!
 * \brief Zone tree iteration allowing tree changes.
 *
 * The semantics is the same like for normal iteration.
 * The set of iterated nodes is according to zone tree state on the beginning.
 */
int zone_tree_delsafe_it_begin(zone_tree_t *tree, zone_tree_delsafe_it_t *it, bool include_deleted);
bool zone_tree_delsafe_it_finished(zone_tree_delsafe_it_t *it);
void zone_tree_delsafe_it_restart(zone_tree_delsafe_it_t *it);
zone_node_t *zone_tree_delsafe_it_val(zone_tree_delsafe_it_t *it);
void zone_tree_delsafe_it_next(zone_tree_delsafe_it_t *it);
void zone_tree_delsafe_it_free(zone_tree_delsafe_it_t *it);

/*!
 * \brief Merge all nodes from 'what' to 'into'.
 *
 * \param into  Zone tree to be inserted into..
 * \param what  ...all nodes from this one.
 *
 * \return KNOT_E*
 */
int zone_tree_merge(zone_tree_t *into, zone_tree_t *what);

/*!
 * \brief Unify all bi-nodes in specified trees.
 */
void zone_trees_unify_binodes(zone_tree_t *nodes, zone_tree_t *nsec3_nodes, bool free_deleted);

/*!
 * \brief Destroys the zone tree, not touching the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void zone_tree_free(zone_tree_t **tree);
