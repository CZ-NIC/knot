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
/*!
 * \file contents.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone contents structure and API for manipulating it.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include "common-knot/lists.h"
#include "libknot/rrtype/nsec3param.h"
#include "knot/zone/node.h"
#include "knot/zone/zone-tree.h"

struct zone_t;

enum zone_contents_find_dname_result {
	ZONE_NAME_FOUND = 1,
	ZONE_NAME_NOT_FOUND = 0
};

/*----------------------------------------------------------------------------*/

typedef struct zone_contents_t {
	zone_node_t *apex;       /*!< Apex node of the zone (holding SOA) */

	zone_tree_t *nodes;
	zone_tree_t *nsec3_nodes;

	knot_nsec3_params_t nsec3_params;
	size_t size;
} zone_contents_t;

/*!
 * \brief Signature of callback for zone contents apply functions.
 */
typedef int (*zone_contents_apply_cb_t)(zone_node_t *node, void *data);

/*----------------------------------------------------------------------------*/

zone_contents_t *zone_contents_new(const knot_dname_t *apex_name);

int zone_contents_add_rr(zone_contents_t *z, const knot_rrset_t *rr, zone_node_t **n);

int zone_contents_remove_node(zone_contents_t *contents, const knot_dname_t *owner);

int zone_contents_remove_nsec3_node(zone_contents_t *contents, const knot_dname_t *owner);

/*!
 * \brief Tries to find a node with the specified name in the zone.
 *
 * \note This function is identical to zone_contents_get_node(), only it returns
 *       constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const zone_node_t *zone_contents_find_node(const zone_contents_t *contents,
                                           const knot_dname_t *name);

/*!
 * \brief Tries to find domain name in the given zone using AVL tree.
 *
 * \param[in] zone Zone to search for the name.
 * \param[in] name Domain name to search for.
 * \param[out] node The found node (if it was found, otherwise it may contain
 *                  arbitrary node).
 * \param[out] closest_encloser Closest encloser of the given name in the zone.
 * \param[out] previous Previous domain name in canonical order.
 *
 * \retval ZONE_NAME_FOUND if node with owner \a name was found.
 * \retval ZONE_NAME_NOT_FOUND if it was not found.
 * \retval KNOT_EINVAL
 * \retval KNOT_EOUTOFZONE
 */
int zone_contents_find_dname(const zone_contents_t *contents,
                             const knot_dname_t *name,
                             const zone_node_t **node,
                             const zone_node_t **closest_encloser,
                             const zone_node_t **previous);

/*!
 * \brief Finds previous name in canonical order to the given name in the zone.
 *
 * \param zone Zone to search for the name.
 * \param name Domain name to find the previous domain name of.
 *
 * \return Previous node in canonical order, or NULL if some parameter is wrong.
 */
const zone_node_t *zone_contents_find_previous(const zone_contents_t *contents,
                                               const knot_dname_t *name);

/*!
 * \brief Tries to find a node with the specified name among the NSEC3 nodes
 *        of the zone.
 *
 * \note This function is identical to zone_contents_get_nsec3_node(), only it
 *       returns constant reference.
 *
 * \param zone Zone where the name should be searched for.
 * \param name Name to find.
 *
 * \return Corresponding node if found, NULL otherwise.
 */
const zone_node_t *zone_contents_find_nsec3_node(const zone_contents_t *contents,
                                                 const knot_dname_t *name);

/*!
 * \brief Finds NSEC3 node and previous NSEC3 node in canonical order,
 *        corresponding to the given domain name.
 *
 * This functions creates a NSEC3 hash of \a name and tries to find NSEC3 node
 * with the hashed domain name as owner.
 *
 * \param[in] zone Zone to search in.
 * \param[in] name Domain name to get the corresponding NSEC3 nodes for.
 * \param[out] nsec3_node NSEC3 node corresponding to \a name (if found,
 *                        otherwise this may be an arbitrary NSEC3 node).
 * \param[out] nsec3_previous The NSEC3 node immediately preceding hashed domain
 *                            name corresponding to \a name in canonical order.
 *
 * \retval ZONE_NAME_FOUND if the corresponding NSEC3 node was found.
 * \retval ZONE_NAME_NOT_FOUND if it was not found.
 * \retval KNOT_EINVAL
 * \retval KNOT_ENSEC3PAR
 * \retval KNOT_ECRYPTO
 * \retval KNOT_ERROR
 */
int zone_contents_find_nsec3_for_name(const zone_contents_t *contents,
                                      const knot_dname_t *name,
                                      const zone_node_t **nsec3_node,
                                      const zone_node_t **nsec3_previous);

const zone_node_t *zone_contents_find_wildcard_child(const zone_contents_t *contents,
                                                     const zone_node_t *parent);

/*!
 * \brief Sets parent and previous pointers and node flags. (cheap operation)
 *        For both normal and NSEC3 tree
 */
int zone_contents_adjust_pointers(zone_contents_t *contents);

/*!
 * \brief Sets parent and previous pointers, sets node flags and NSEC3 links.
 *        This has to be called before the zone can be served.
 *
 * \param first_nsec3_node First node in NSEC3 tree - needed in sem. checks.
 *        Will not be saved if set to NULL.
 * \param last_nsec3_node Last node in NSEC3 tree - needed in sem. checks.
 *        Will not be saved if set to NULL.
 * \param zone Zone to adjust domain names in.
 */
int zone_contents_adjust_full(zone_contents_t *contents,
                              zone_node_t **first_nsec3_node,
                              zone_node_t **last_nsec3_node);

/*!
 * \brief Parses the NSEC3PARAM record stored in the zone.
 *
 * This function properly fills in the nsec3_params field of the zone structure
 * according to data stored in the NSEC3PARAM record. This is necessary to do
 * before any NSEC3 operations on the zone are requested, otherwise they will
 * fail (error KNOT_ENSEC3PAR).
 *
 * \note If there is no NSEC3PARAM record in the zone, this function clears
 *       the nsec3_params field of the zone structure (fills it with zeros).
 *
 * \param zone Zone to get the NSEC3PARAM record from.
 */
int zone_contents_load_nsec3param(zone_contents_t *contents);

/*!
 * \brief Returns the parsed NSEC3PARAM record of the zone.
 *
 * \note You must parse the NSEC3PARAM record prior to calling this function
 *       (zone_contents_load_nsec3param()).
 *
 * \param zone Zone to get the NSEC3PARAM record from.
 *
 * \return Parsed NSEC3PARAM from the zone or NULL if the zone does not use
 *         NSEC3 or the record was not parsed before.
 *
 * \see zone_contents_load_nsec3param()
 */
const knot_nsec3_params_t *zone_contents_nsec3params(const zone_contents_t *contents);

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
int zone_contents_tree_apply_inorder(zone_contents_t *zone,
                                     zone_contents_apply_cb_t function, void *data);

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
int zone_contents_nsec3_apply_inorder(zone_contents_t *zone,
                                      zone_contents_apply_cb_t function, void *data);

/*!
 * \brief Creates a shallow copy of the zone (no stored data are copied).
 *
 * This function creates a new zone structure in \a to, creates new trees for
 * regular nodes and for NSEC3 nodes, creates new hash table and a new domain
 * table. It also fills these structures with the exact same data as the
 * original zone is - no copying of stored data is done, just pointers are
 * copied.
 *
 * \param from Original zone.
 * \param to Copy of the zone.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_ENOMEM
 */
int zone_contents_shallow_copy(const zone_contents_t *from, zone_contents_t **to);

void zone_contents_free(zone_contents_t **contents);

void zone_contents_deep_free(zone_contents_t **contents);

/*! \brief Return zone SOA rdataset. */
const knot_rdataset_t *zone_contents_soa(const zone_contents_t *zone);

/*!
 * \brief Fetch zone serial.
 *
 * \param zone Zone.
 *
 * \return serial or 0
 */
uint32_t zone_contents_serial(const zone_contents_t *zone);


/*! \brief Calculate next serial. */
uint32_t zone_contents_next_serial(const zone_contents_t *zone, int policy);

/*!
 * \brief Return true if zone is signed.
 */
bool zone_contents_is_signed(const zone_contents_t *zone);

/*!
 * \brief Return true if zone is empty.
 */
bool zone_contents_is_empty(const zone_contents_t *zone);

zone_node_t *zone_contents_get_node_for_rr(zone_contents_t *zone, const knot_rrset_t *rrset);

zone_node_t *zone_contents_find_node_for_rr(zone_contents_t *zone, const knot_rrset_t *rrset);

/*!
 * \brief Measure zone contents size.
 *
 * Size is measured in uncompressed wire format. Measured size is saved into
 * zone contents structure.
 * \return Measured size
 */
size_t zone_contents_measure_size(zone_contents_t *zone);

/*! @} */
