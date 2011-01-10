/*!
 * \file zone.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone structure and API for manipulating it.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _CUTEDNS_DNSLIB_ZONE_H_
#define _CUTEDNS_DNSLIB_ZONE_H_

#include "node.h"
#include "dname.h"
#include "tree.h"

/*----------------------------------------------------------------------------*/

typedef TREE_HEAD(avl_tree, dnslib_node) avl_tree_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for holding DNS zone.
 *
 * \warning Make sure not to insert the same nodes using both the normal and
 *          NSEC3 functions. Although this will be successfull, it will produce
 *          double-free errors when destroying the zone.
 */
struct dnslib_zone {
	dnslib_node_t *apex;       /*!< Apex node of the zone (holding SOA) */
	avl_tree_t *tree;          /*!< AVL tree for holding zone nodes. */
	avl_tree_t *nsec3_nodes;   /*!< AVL tree for holding NSEC3 nodes. */
};

typedef struct dnslib_zone dnslib_zone_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates new DNS zone.
 *
 * \param apex Node representing the zone apex.
 *
 * \return The initialized zone structure or NULL if an error occured.
 */
dnslib_zone_t *dnslib_zone_new(dnslib_node_t *apex);

/*!
 * \brief Adds a node to the given zone.
 *
 * Checks if the node belongs to the zone, i.e. if its owner is a subdomain of
 * the zone's apex. It thus also forbids adding node with the same name as the
 * zone apex.
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval 0 on success.
 * \retval -1 if one of the parameters is NULL.
 * \retval -2 if \a node does not belong to \a zone.
 */
int dnslib_zone_add_node(dnslib_zone_t *zone, dnslib_node_t *node);

/*!
 * \brief Adds a node holding NSEC3 records to the given zone.
 *
 * Checks if the node belongs to the zone, i.e. if its owner is a subdomain of
 * the zone's apex. It does not check if the node really contains any NSEC3
 * records, nor if the name is a hash (as there is actually no way of
 * determining this).
 *
 * \param zone Zone to add the node into.
 * \param node Node to add into the zone.
 *
 * \retval 0 on success.
 * \retval -1 if one of the parameters is NULL.
 * \retval -2 if \a node does not belong to \a zone.
 */
int dnslib_zone_add_nsec3_node(dnslib_zone_t *zone, dnslib_node_t *node);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
dnslib_node_t *dnslib_zone_get_node(const dnslib_zone_t *zone,
                                    const dnslib_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
dnslib_node_t *dnslib_zone_get_nsec3_node(const dnslib_zone_t *zone,
                                          const dnslib_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \note This function is identical to dnslib_zone_get_node(), only it returns
 *       constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const dnslib_node_t *dnslib_zone_find_node(const dnslib_zone_t *zone,
                                           const dnslib_dname_t *name);

int dnslib_zone_find_dname(const dnslib_zone_t *zone,
                           const dnslib_dname_t *name,
                           const dnslib_node_t **node,
                           const dnslib_node_t **closest_encloser);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \note This function is identical to dnslib_zone_get_nsec3_node(), only it
 *       returns constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const dnslib_node_t *dnslib_zone_find_nsec3_node(const dnslib_zone_t *zone,
                                                 const dnslib_dname_t *name);

/*!
 * \brief Returns the apex node of the zone.
 *
 * \param zone Zone to get the apex of.
 *
 * \return Zone apex node.
 */
const dnslib_node_t *dnslib_zone_apex(const dnslib_zone_t *zone);

/*!
 * \brief Optimizes zone by replacing domain names in RDATA with references to
 *        domain names present in zone (as node owners).
 *
 * \param zone Zone to adjust domain names in.
 */
void dnslib_zone_adjust_dnames(dnslib_zone_t *zone);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses in-order depth-first forward traversal, i.e. the function
 * is first recursively applied to left subtree, then to the root and then to
 * the right subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each regular node in the zone.
 *
 * This function uses in-order depth-first reverse traversal, i.e. the function
 * is first recursively applied to right subtree, then to the root and then to
 * the left subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone Nodes of this zone will be used as parameters for the function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_tree_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses post-order depth-first forward traversal, i.e. the
 * function is first recursively applied to subtrees and then to the root.
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_postorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses in-order depth-first forward traversal, i.e. the function
 * is first recursively applied to left subtree, then to the root and then to
 * the right subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_inorder(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Applies the given function to each NSEC3 node in the zone.
 *
 * This function uses in-order depth-first reverse traversal, i.e. the function
 * is first recursively applied to right subtree, then to the root and then to
 * the left subtree.
 *
 * \note This implies that the zone is stored in a binary tree. Is there a way
 *       to make this traversal independent on the underlying structure?
 *
 * \param zone NSEC3 nodes of this zone will be used as parameters for the
 *             function.
 * \param function Function to be applied to each node of the zone.
 * \param data Arbitrary data to be passed to the function.
 */
void dnslib_zone_nsec3_apply_inorder_reverse(dnslib_zone_t *zone,
                              void (*function)(dnslib_node_t *node, void *data),
                              void *data);

/*!
 * \brief Correctly deallocates the zone structure, without deleting its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 */
void dnslib_zone_free(dnslib_zone_t **zone);

/*!
 * \brief Correctly deallocates the zone structure and all nodes within.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 */
void dnslib_zone_deep_free(dnslib_zone_t **zone);

#endif

/*! @} */
