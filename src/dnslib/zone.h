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
 * \brief Correctly deallocates the zone structure and possibly all its nodes.
 *
 * Also sets the given pointer to NULL.
 *
 * \param zone Zone to be freed.
 * \param free_nodes If 0, the nodes will not be deleted, if <> 0, all nodes
 *                   in the zone are deleted using dnslib_node_free().
 */
void dnslib_zone_free(dnslib_zone_t **zone, int free_nodes);

#endif

/*! @} */
