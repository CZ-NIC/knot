/*!
 * \file zone-tree.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone tree structure and API for manipulating it.
 *
 * Implemented as AVL tree.
 *
 * \addtogroup libknot
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KNOT_ZONE_TREE_H_
#define _KNOT_ZONE_TREE_H_

#include "common/hattrie/hat-trie.h"
#include "libknot/zone/node.h"

/*----------------------------------------------------------------------------*/

typedef hattrie_t knot_zone_tree_t;

/*!
 * \brief Signature of callback for zone apply functions.
 */
typedef int (*knot_zone_tree_apply_cb_t)(knot_node_t **node, void *data);

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates the zone tree.
 *
 * \return created zone tree structure.
 */
knot_zone_tree_t* knot_zone_tree_create();

/*!
 * \brief Return weight of the zone tree (number of nodes).
 * \param tree Zone tree.
 * \return number of nodes in tree.
 */
size_t knot_zone_tree_weight(knot_zone_tree_t* tree);

/*!
 * \brief Checks if the zone tree is empty.
 *
 * \param tree Zone tree to check.
 *
 * \return Nonzero if the zone tree is empty.
 */
int knot_zone_tree_is_empty(knot_zone_tree_t *tree);

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
int knot_zone_tree_insert(knot_zone_tree_t *tree, knot_node_t *node);

/*!
 * \brief Finds node with the given owner in the zone tree.
 *
 * \param tree Zone tree to search in.
 * \param owner Owner of the node to find.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int knot_zone_tree_find(knot_zone_tree_t *tree,
                          const knot_dname_t *owner,
                          const knot_node_t **found);

/*!
 * \brief Finds node with the given owner in the zone tree.
 *
 * \note This function is identical to knot_zone_tree_find() except that it
 *       returns non-const node.
 *
 * \param tree Zone tree to search in.
 * \param owner Owner of the node to find.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int knot_zone_tree_get(knot_zone_tree_t *tree,
                         const knot_dname_t *owner,
                         knot_node_t **found);

/*!
 * \brief Tries to find the given domain name in the zone tree and returns the
 *        associated node and previous node in canonical order.
 *
 * \param zone Zone to search in.
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
int knot_zone_tree_find_less_or_equal(knot_zone_tree_t *tree,
                                        const knot_dname_t *owner,
                                        const knot_node_t **found,
                                        const knot_node_t **previous);

/*!
 * \brief Tries to find the given domain name in the zone tree and returns the
 *        associated node and previous node in canonical order.
 *
 * \note This function is identical to knot_zone_tree_find_less_or_equal()
 *       except that it returns non-const nodes.
 *
 * \param zone Zone to search in.
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
int knot_zone_tree_get_less_or_equal(knot_zone_tree_t *tree,
                                       const knot_dname_t *owner,
                                       knot_node_t **found,
                                       knot_node_t **previous);

/*!
 * \brief Removes node with the given owner from the zone tree and returns it.
 *
 * \param tree Zone tree to remove the node from.
 * \param owner Owner of the node to find.
 * \param removed The removed node.
 *
 * \retval The removed node.
 */
int knot_zone_tree_remove(knot_zone_tree_t *tree,
                            const knot_dname_t *owner,
                            knot_node_t **removed);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * This function uses in-order depth-first forward traversal, i.e. the function
 * is first recursively applied to left subtree, then to the root and then to
 * the right subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_zone_tree_apply_inorder(knot_zone_tree_t *tree,
                                 knot_zone_tree_apply_cb_t function,
                                 void *data);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * This function visits leafe nodes before their parents.
 * But doesn't maintain any specific ordering.
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_zone_tree_apply_recursive(knot_zone_tree_t *tree,
                                   knot_zone_tree_apply_cb_t function,
                                   void *data);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_zone_tree_apply(knot_zone_tree_t *tree,
                         knot_zone_tree_apply_cb_t function,
                         void *data);

/*!
 * \brief Copies the whole zone tree structure (but not the data contained
 *        within).
 *
 * \warning This function does not check if the target zone tree is empty,
 *          it just replaces the root pointer.
 *
 * \param from Original zone tree.
 * \param to Zone tree to copy the original one into.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ENOMEM
 */
int knot_zone_tree_shallow_copy(knot_zone_tree_t *from,
                                  knot_zone_tree_t **to);

int knot_zone_tree_deep_copy(knot_zone_tree_t *from,
                             knot_zone_tree_t **to);

/*!
 * \brief Destroys the zone tree, not touching the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void knot_zone_tree_free(knot_zone_tree_t **tree);

/*!
 * \brief Destroys the zone tree, together with the saved data.
 *
 * \param tree Zone tree to be destroyed.
 * \param free_owners Set to <> 0 if owners of the nodes should be destroyed
 *                    as well. Set to 0 otherwise.
 */
void knot_zone_tree_deep_free(knot_zone_tree_t **tree);

void hattrie_insert_dname(hattrie_t *tr, knot_dname_t *dname);
knot_dname_t *hattrie_get_dname(hattrie_t *tr, knot_dname_t *dname);

/*----------------------------------------------------------------------------*/

#endif // _KNOT_ZONE_TREE_H_

/*! @} */
