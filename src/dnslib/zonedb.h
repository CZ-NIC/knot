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

#ifndef _CUTEDNS_DNSLIB_ZONEDB_H_
#define _CUTEDNS_DNSLIB_ZONEDB_H_

#include "skip-list.h"
#include "zone.h"
#include "node.h"
#include "dname.h"

struct dnslib_zonedb {
	skip_list_t *zones;
};

typedef struct dnslib_zonedb dnslib_zonedb_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Allocates and initializes the zone database structure.
 *
 * \return Pointer to the created zone database structure.
 */
dnslib_zonedb_t *dnslib_zonedb_new();

/*!
 * \brief Adds new zone to the database.
 *
 * \param database Zone database to store the zone.
 * \param zone Parsed zone.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
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
 * \retval 0 On success.
 * \retval -1 If the zone was not found.
 */
int dnslib_zonedb_remove_zone(dnslib_zonedb_t *db, dnslib_dname_t *zone_name);

/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param database Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present.
// *
// * \note As the zones are ordered in reverse canonical order, a possible parent
// *       of the returned zone may be retrieved easily as it is the next item
// *       in the linked list (zdb_zone.next).
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
// *
// * \todo Destroy nodes which are not hashed into the table. Best will be to
// *       destroy zone nodes from the list and tell zds_destroy() not to destroy
// *       the stored items.
 */
void dnslib_zonedb_deep_free(dnslib_zonedb_t **db);

/*----------------------------------------------------------------------------*/

#endif /* _CUTEDNS_DNSLIB_ZONEDB_H_ */

/*! @} */
