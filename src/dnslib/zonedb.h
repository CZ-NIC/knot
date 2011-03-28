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

#include "lib/skip-list.h"
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
 * The removal of a zone is synchronized using RCU mechanism, so the zone data
 * will not be destroyed while some thread may be using it.
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
 * \brief Destroys and deallocates the whole zone database.
 *
 * \param database Pointer to pointer to the zone database to be destroyed.
 *
 * The zones are destroyed one-by-one and the process is synchronized using
 * RCU mechanism, so the zone data will not be destroyed while some thread may
 * be using it.
 */
void dnslib_zonedb_deep_free(dnslib_zonedb_t **db);

/*----------------------------------------------------------------------------*/

#endif /* _KNOT_DNSLIB_ZONEDB_H_ */

/*! @} */
