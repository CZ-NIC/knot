/*!
 * \file zone-database.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Contains structures for keeping all zones the server manages and some
 *        basic routines for using them.
 *
 * As for now, the database uses only simple one-way linked list of zones. For
 * individual zones, an underlying data structure with generic API is used (the
 * API is provided in the zone-data-structure.h header).
 *
 * \note Some kind of tree will be probably best for the zone database,
 *       though crippling the performance in case of a lot of zones.
 *       We need the tree structure in order to find the appropriate zone where
 *       to search.
 * \todo Consider using one large hash table for all zones for searching and
 *       the zone structure only for some additional issues. If we can avoid
 *       using the zone structure during each query, it may be worth it.
 *       Moreover it may save some space - less empty items in one large hash
 *       table than in several smaller.
 *
 * \addtogroup zonedb
 * @{
 */
#ifndef _CUTEDNS_ZONE_DATABASE_H_
#define _CUTEDNS_ZONE_DATABASE_H_

#include <sys/types.h>

#include <ldns/rdata.h>
#include <ldns/zone.h>

#include "common.h"
#include "zone-data-structure.h"

/*----------------------------------------------------------------------------*/
/*!
 * \brief Structure for storing one zone. Uses zds_zone structure for data.
 */
typedef struct zdb_zone {
	/*! \brief Zone name in wire format (i.e. a null-terminated string). */
	ldns_rdf *zone_name;

	zds_zone *zone; /*!< Zone data structure. */

	/*! \brief Zone apex. First item in a linked list of zone nodes. */
	zn_node_t *apex;

	struct zdb_zone *next; /*!< Next item pointer. */
} zdb_zone;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Zone database structure.
 */
typedef struct zdb_database {
	/*! \brief Pointer to the first item in the linked list of zones. */
	zdb_zone *head;
} zdb_database;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Allocates and initializes the zone database structure.
 */
zdb_database *zdb_create();

/*!
 * \brief Adds new empty zone to the given database.
 *
 * \param database Zone database to store the zone.
 * \param zone_name Zone name in wire format  (i.e. a null-terminated string).
 * \param items Number of items in the zone. Is used for creating the zone data
 *              structure of appropriate size.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int zdb_create_zone(zdb_database *database, ldns_rdf *zone_name, uint items);

/*!
 * \brief Adds new zone stored in a ldns_zone structure to the database.
 *
 * \param database Zone database to store the zone.
 * \param zone Parsed zone in ldns_zone format.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int zdb_add_zone(zdb_database *database, ldns_zone *zone);

/*!
 * \brief Removes the given zone from the database if it exists.
 *
 * \param database Zone database to remove from.
 * \param zone_name Name of the zone to be removed.
 *
 * The removal of a zone is synchronized using RCU mechanism, so the zone data
 * will not be destroyed while some thread may be using it.
 *
 * \retval 0 On success.
 * \retval -1 If the zone was not found.
 */
int zdb_remove_zone(zdb_database *database, ldns_rdf *zone_name);

/*!
 * \brief Inserts one zone node to the given zone in the database.
 *
 * \param database Zone database to insert the node into.
 * \param zone_name Name of the zone to insert the node into.
 * \param node The zone node to be inserted.
 *
 * \retval 0 On success.
 * \retval -2 If the zone was not found.
 * \retval -1 If an error occured during insertion to the zone.
 */
int zdb_insert_name(zdb_database *database, ldns_rdf *zone_name, zn_node_t *node);

/*!
 * \brief Finds zone the given domain name should belong to.
 *
 * \param database Zone database to search in.
 * \param dname Domain name to find zone for.
 *
 * \retval Zone in which the domain name should be present.
 *
 * \note As the zones are ordered in reverse canonical order, a possible parent
 *       of the returned zone may be retrieved easily as it is the next item
 *       in the linked list (zdb_zone.next).
 */
const zdb_zone *zdb_find_zone_for_name(zdb_database *database,
                                       const ldns_rdf *dname);

/*!
 * \brief Finds the given name in the zone database and returns corresponding
 *        zone node.
 *
 * \param database Zone database to search in.
 * \param dname Domain name to find, in wire format (i.e. a null-terminated
 *              string).
 *
 * \return Proper zone node for the given name or NULL if not found.
 */
const zn_node_t *zdb_find_name_in_zone(const zdb_zone *zone,
                                     const ldns_rdf *dname);

/*!
 * \brief Destroys and deallocates the whole zone database.
 *
 * \param database Pointer to pointer to the zone database to be destroyed.
 *
 * The zones are destroyed one-by-one and the process is synchronized using
 * RCU mechanism, so the zone data will not be destroyed while some thread may
 * be using it.
 *
 * \todo Destroy nodes which are not hashed into the table. Best will be to
 *       destroy zone nodes from the list and tell zds_destroy() not to destroy
 *       the stored items.
 */
void zdb_destroy(zdb_database **database);

/*----------------------------------------------------------------------------*/

#endif /* _CUTEDNS_ZONE_DATABASE_H_ */

/*! @} */
