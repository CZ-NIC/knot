/*!
 * \file zonedb.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Zone database structure and API for manipulating it.
 *
 * Zone database groups several zones and provides functions for finding
 * suitable zone for a domain name, for searching in a particular zone, etc.
 *
 * \addtogroup dnslib
 * @{
 */

#ifndef _KNOT_DNSLIB_ZONEDB_H_
#define _KNOT_DNSLIB_ZONEDB_H_

#include "common/general-tree.h"
#include "dnslib/zone.h"
#include "dnslib/node.h"
#include "dnslib/dname.h"

/*!
 * \brief Zone database structure. Contains all zones managed by the server.
 */
struct knot_zonedb {
	general_tree_t *zone_tree; /*!< AVL tree of zones. */
	size_t zone_count;
};

typedef struct knot_zonedb knot_zonedb_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure or NULL if an error
 *         occured.
 */
knot_zonedb_t *knot_zonedb_new();

/*!
 * \brief Adds new zone to the database.
 *
 * \param db Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EZONEIN
 */
int knot_zonedb_add_zone(knot_zonedb_t *db, knot_zone_t *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \note Assumes that the zone was adjusted using knot_zone_adjust_dnames().
 *       If it was not, it may leak some memory due to checks used in
 *       knot_rdata_deep_free().
 *
 * \param db Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 * \param destroy_zone Set to <> 0 if you do want the function to destroy the
 *                     zone after removing from zone database. Set to 0
 *                     otherwise.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOZONE
 */
int knot_zonedb_remove_zone(knot_zonedb_t *db, knot_dname_t *zone_name,
                              int destroy_zone);

//knot_zone_t *knot_zonedb_replace_zone(knot_zonedb_t *db,
//                                          knot_zone_t *zone);

/*!
 * \brief Finds zone exactly matching the given zone name.
 *
 * \param db Zone database to search in.
 * \param zone_name Domain name representing the zone name.
 *
 * \return Zone with \a zone_name being the owner of the zone apex or NULL if
 *         not found.
 */
knot_zone_t *knot_zonedb_find_zone(const knot_zonedb_t *db,
                                       const knot_dname_t *zone_name);


/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param db Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present or NULL if no such
 *         zone is found.
 */
const knot_zone_t *knot_zonedb_find_zone_for_name(knot_zonedb_t *db,
                                                   const knot_dname_t *dname);

size_t knot_zonedb_zone_count(const knot_zonedb_t *db);
knot_zone_t **knot_zonedb_zones(const knot_zonedb_t *db);

/*!
 * \brief Destroys and deallocates the zone database structure (but not the
 *        zones within).
 *
 * \param db Zone database to be destroyed.
 */
void knot_zonedb_free(knot_zonedb_t **db);

/*!
 * \brief Destroys and deallocates the whole zone database including the zones.
 *
 * \note Assumes that the zone was adjusted using knot_zone_adjust_dnames().
 *       If it was not, it may leak some memory due to checks used in
 *       knot_rdata_deep_free().
 *
 * \param db Zone database to be destroyed.
 */
void knot_zonedb_deep_free(knot_zonedb_t **db);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_DNSLIB_ZONEDB_H_ */

/*! @} */
