/*!
 * \file zone-tree.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone tree structure and API for manipulating it.
 *
 * Implemented as AVL tree.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONE_TREE_H_
#define _KNOT_DNSLIB_ZONE_TREE_H_

#include "common/tree.h"
#include "dnslib/node.h"

/*----------------------------------------------------------------------------*/

typedef struct dnslib_zone_tree_node {
	/*! \brief Structure for connecting this node to an AVL tree. */
	TREE_ENTRY(dnslib_zone_tree_node) avl;
	/*! \brief Zone tree data. */
	dnslib_node_t *node;
	/*! \brief Owner of the node. */
//	dnslib_dname_t *owner;
} dnslib_zone_tree_node_t;

/*----------------------------------------------------------------------------*/

typedef TREE_HEAD(dnslib_zone_tree, dnslib_zone_tree_node) dnslib_zone_tree_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Initializes the zone tree.
 *
 * Does not allocate the structure. Must be called before any use of the tree.
 *
 * \param tree Zone tree structure to initialize.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_zone_tree_init(dnslib_zone_tree_t *tree);

/*!
 * \brief Inserts the given node into the zone tree.
 *
 * \param tree Zone tree to insert the node into.
 * \param node Node to insert.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_insert(dnslib_zone_tree_t *tree, dnslib_node_t *node);

/*!
 * \brief Finds node with the given owner in the zone tree.
 *
 * \param tree Zone tree to search in.
 * \param owner Owner of the node to find.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_find(dnslib_zone_tree_t *tree,
                          const dnslib_dname_t *owner,
                          const dnslib_node_t **found);

/*!
 * \brief Finds node with the given owner in the zone tree.
 *
 * \note This function is identical to dnslib_zone_tree_find() except that it
 *       returns non-const node.
 *
 * \param tree Zone tree to search in.
 * \param owner Owner of the node to find.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_get(dnslib_zone_tree_t *tree,
                         const dnslib_dname_t *owner,
                         dnslib_node_t **found);

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
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_find_less_or_equal(dnslib_zone_tree_t *tree,
                                        const dnslib_dname_t *owner,
                                        const dnslib_node_t **found,
                                        const dnslib_node_t **previous);

/*!
 * \brief Tries to find the given domain name in the zone tree and returns the
 *        associated node and previous node in canonical order.
 *
 * \note This function is identical to dnslib_zone_tree_find_less_or_equal()
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
 * \retval DNSLIB_EBADARG
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_get_less_or_equal(dnslib_zone_tree_t *tree,
                                       const dnslib_dname_t *owner,
                                       dnslib_node_t **found,
                                       dnslib_node_t **previous);

/*!
 * \brief Removes node with the given owner from the zone tree and returns it.
 *
 * \param tree Zone tree to remove the node from.
 * \param owner Owner of the node to find.
 * \param removed The removed node.
 *
 * \retval The removed node.
 */
int dnslib_zone_tree_remove(dnslib_zone_tree_t *tree,
                            const dnslib_dname_t *owner,
                            dnslib_node_t **removed);

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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_zone_tree_forward_apply_inorder(dnslib_zone_tree_t *tree,
                                           void (*function)(
                                           dnslib_node_t *node, void *data),
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_zone_tree_forward_apply_postorder(dnslib_zone_tree_t *tree,
                                             void (*function)(
                                             dnslib_node_t *node, void *data),
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_zone_tree_reverse_apply_inorder(dnslib_zone_tree_t *tree,
                                           void (*function)(
                                           dnslib_node_t *node, void *data),
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EBADARG
 */
int dnslib_zone_tree_reverse_apply_postorder(dnslib_zone_tree_t *tree,
                                             void (*function)(
                                             dnslib_node_t *node, void *data),
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
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOMEM
 */
int dnslib_zone_tree_copy(dnslib_zone_tree_t *from, dnslib_zone_tree_t *to);

/*!
 * \brief Destroys the zone tree, not touching the saved data.
 *
 * \param tree Zone tree to be destroyed.
 */
void dnslib_zone_tree_free(dnslib_zone_tree_t **tree);

/*!
 * \brief Destroys the zone tree, together with the saved data.
 *
 * \param tree Zone tree to be destroyed.
 * \param free_owners Set to <> 0 if owners of the nodes should be destroyed
 *                    as well. Set to 0 otherwise.
 */
void dnslib_zone_tree_deep_free(dnslib_zone_tree_t **tree, int free_owners);

/*----------------------------------------------------------------------------*/

#endif // _KNOT_DNSLIB_ZONE_TREE_H_

/*! @} */

