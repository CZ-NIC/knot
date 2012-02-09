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

#include "common/tree.h"
#include "zone/node.h"

/*----------------------------------------------------------------------------*/

typedef struct knot_zone_tree_node {
	/*! \brief Structure for connecting this node to an AVL tree. */
	TREE_ENTRY(knot_zone_tree_node) avl;
	/*! \brief Zone tree data. */
	knot_node_t *node;
	/*! \brief Owner of the node. */
//	knot_dname_t *owner;
} knot_zone_tree_node_t;

/*----------------------------------------------------------------------------*/

typedef TREE_HEAD(knot_zone_tree, knot_zone_tree_node) knot_zone_tree_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Initializes the zone tree.
 *
 * Does not allocate the structure. Must be called before any use of the tree.
 *
 * \param tree Zone tree structure to initialize.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_zone_tree_init(knot_zone_tree_t *tree);

/*!
 * \brief Inserts the given node into the zone tree.
 *
 * \param tree Zone tree to insert the node into.
 * \param node Node to insert.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
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
 * \retval KNOT_EBADARG
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
 * \retval KNOT_EBADARG
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
 * \retval KNOT_EBADARG
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
 * \retval KNOT_EBADARG
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
                            knot_zone_tree_node_t **removed);

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
 * \retval KNOT_EBADARG
 */
int knot_zone_tree_forward_apply_inorder(knot_zone_tree_t *tree,
                                           void (*function)(
                                                  knot_zone_tree_node_t *node,
                                                  void *data),
                                           void *data);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_zone_tree_forward_apply_postorder(knot_zone_tree_t *tree,
                                             void (*function)(
                                                  knot_zone_tree_node_t *node,
                                                  void *data),
                                             void *data);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * This function uses in-order depth-first reverse traversal, i.e. the function
 * is first recursively applied to right subtree, then to the root and then to
 * the left subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_zone_tree_reverse_apply_inorder(knot_zone_tree_t *tree,
                                           void (*function)(
                                                  knot_zone_tree_node_t *node,
                                                  void *data),
                                           void *data);

/*!
 * \brief Applies the given function to each node in the zone.
 *
 * This function uses post-order depth-first reverse traversal, i.e. the
 * function is first recursively applied to right subtree, then to the
 * left subtree and then to the root.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param tree Zone tree to apply the function to.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EBADARG
 */
int knot_zone_tree_reverse_apply_postorder(knot_zone_tree_t *tree,
                                             void (*function)(
                                                  knot_zone_tree_node_t *node,
                                                  void *data),
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
                                  knot_zone_tree_t *to);

int knot_zone_tree_deep_copy(knot_zone_tree_t *from,
                             knot_zone_tree_t *to);

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

/*----------------------------------------------------------------------------*/

#endif // _KNOT_ZONE_TREE_H_

/*! @} */

