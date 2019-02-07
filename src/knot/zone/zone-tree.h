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

#pragma once

#include "contrib/qp-trie/trie.h"
#include "knot/zone/node.h"

typedef trie_t zone_tree_t;

/*!
 * \brief Signature of callback for zone apply functions.
 */
typedef int (*zone_tree_apply_cb_t)(zone_node_t **node, void *data);

/*!
 * \brief Creates the zone tree.
 *
 * \return created zone tree structure.
 */
zone_tree_t *zone_tree_create(void);

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

	return trie_weight(tree);
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

/*!
 * \brief Inserts the given node into the zone tree.
 *
 * \param tree Zone tree to insert the node into.
 * \param node Node to insert.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_tree_insert(zone_tree_t *tree, zone_node_t *node);

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
 * \brief Try to find node with specified owner in zone tree.
 *
 * \param tree     Zone tree to search in.
 * \param owner    Owner name to search for.
 * \param found    Out: itearator to found node.
 *
 * \retval 1   if domain name was found among zone nodes. The iterator points to it.
 * \retval 0   if name was not found. The iterator points to lexicographically previous node.
 * \return KNOT_E* (the iterator is invalid and must not be freed)
 */
int zone_tree_get_it(zone_tree_t *tree, const knot_dname_t *owner, trie_it_t **found);

/*!
 * \brief Returns the zone node the iterator is pointing to.
 *
 * \param it   The iterator.
 *
 * \retval NULL   The iterator is no longer valid, however it sill needs to be freed.
 * \return The pointed node.
 */
zone_node_t *zone_tree_it_deref(trie_it_t *it);

/*!
 * \brief Move the iterator to previous node in zone nodes' loop.
 *
 * \note If it was on very first node in zone, it jumps to last.
 * \note It skips any node which is not authoritative or has zero RRSets.
 *
 * \param it   Iterator to be moved.
 *
 * \return Node pointed by the itearator after moved.
 */
zone_node_t *zone_tree_it_prev(trie_it_t *it);

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
 * \brief Delete a node that has no RRSets and no children.
 *
 * \param tree  The tree to remove from.
 * \param node  The node to remove.
 */
void zone_tree_delete_empty(zone_tree_t *tree, zone_node_t *node);

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
 * \brief Destroys the zone tree, not touching the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void zone_tree_free(zone_tree_t **tree);

/*!
 * \brief Destroys the zone tree, together with the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void zone_tree_deep_free(zone_tree_t **tree);
