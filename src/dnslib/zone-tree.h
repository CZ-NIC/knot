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
 * \todo Document me!
 */
void dnslib_zone_tree_init(dnslib_zone_tree_t *tree);

/*!
 * \todo Document me!
 */
int dnslib_zone_tree_insert(dnslib_zone_tree_t *tree, dnslib_node_t *node);

/*!
 * \todo Document me!
 */
const dnslib_node_t *dnslib_zone_tree_find(dnslib_zone_tree_t *tree,
                                           const dnslib_dname_t *owner);

/*!
 * \todo Document me!
 */
dnslib_node_t *dnslib_zone_tree_get(dnslib_zone_tree_t *tree,
                                    const dnslib_dname_t *owner);

/*!
 * \todo Document me!
 */
int dnslib_zone_tree_find_less_or_equal(dnslib_zone_tree_t *tree,
                                        const dnslib_dname_t *owner,
                                        const dnslib_node_t **found,
                                        const dnslib_node_t **previous);

/*!
 * \todo Document me!
 */
int dnslib_zone_tree_get_less_or_equal(dnslib_zone_tree_t *tree,
                                       const dnslib_dname_t *owner,
                                       dnslib_node_t **found,
                                       dnslib_node_t **previous);

/*!
 * \todo Document me!
 */
dnslib_node_t *dnslib_zone_tree_remove(dnslib_zone_tree_t *tree,
                                       const dnslib_dname_t *owner);

/*!
 * \todo Document me!
 */
void dnslib_zone_tree_forward_apply_inorder(dnslib_zone_tree_t *tree,
                                            void (*function)(
                                            dnslib_node_t *node, void *data),
                                            void *data);

/*!
 * \todo Document me!
 */
void dnslib_zone_tree_forward_apply_postorder(dnslib_zone_tree_t *tree,
                                              void (*function)(
                                              dnslib_node_t *node, void *data),
                                              void *data);

/*!
 * \todo Document me!
 */
void dnslib_zone_tree_reverse_apply_inorder(dnslib_zone_tree_t *tree,
                                            void (*function)(
                                            dnslib_node_t *node, void *data),
                                            void *data);

/*----------------------------------------------------------------------------*/

#endif // _KNOT_DNSLIB_ZONE_TREE_H_

/*! @} */

