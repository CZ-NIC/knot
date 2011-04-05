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

#include "common/skip-list.h"
#include "dnslib/zone.h"
#include "dnslib/node.h"
#include "dnslib/dname.h"

/*!
 * \brief Zone database structure. Contains all zones managed by the server.
 */
struct dnslib_zonedb {
	skip_list_t *zones; /*!< Skip-list of zones. */
};

typedef struct dnslib_zonedb dnslib_zonedb_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure or NULL if an error
 *         occured.
 */
dnslib_zonedb_t *dnslib_zonedb_new();

/*!
 * \brief Adds new zone to the database.
 *
 * \param database Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_EZONEIN
 */
int dnslib_zonedb_add_zone(dnslib_zonedb_t *db, dnslib_zone_t *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \param db Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 *
 * \retval DNSLIB_EOK
 * \retval DNSLIB_ENOZONE
 */
int dnslib_zonedb_remove_zone(dnslib_zonedb_t *db, dnslib_dname_t *zone_name);

/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param database Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present or NULL if no such
 *         zone is found.
 */
const dnslib_zone_t *dnslib_zonedb_find_zone_for_name(dnslib_zonedb_t *db,
                                                   const dnslib_dname_t *dname);

/*!
 * \brief Copies the zone database structure (but not the zones within).
 *
 * \param db Zone database to copy.
 *
 * \return A new zone database structure containing the same zones as \a db or
 *         NULL if an error occured.
 */
dnslib_zonedb_t *dnslib_zonedb_copy(const dnslib_zonedb_t *db);

/*!
 * \brief Destroys and deallocates the zone database structure (but not the
 *        zones within).
 *
 * \param database Zone database to be destroyed.
 */
void dnslib_zonedb_free(dnslib_zonedb_t **db);

/*!
 * \brief Destroys and deallocates the whole zone database including the zones.
 *
 * \param database Zone database to be destroyed.
 */
void dnslib_zonedb_deep_free(dnslib_zonedb_t **db);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_DNSLIB_ZONEDB_H_ */

/*! @} */
