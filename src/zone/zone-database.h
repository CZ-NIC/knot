/*!
 * @file zone-database.h
 *
 * Contains structures for keeping all zones the server manages and some basic
 * routines for using them.
 *
 * As for now, the database uses only simple one-way linked list of zones. For
 * individual zones, an underlying data structure with generic API is used (the
 * API is provided in the zone-data-structure.h header).
 *
 * @note Some kind of tree will be probably best for the zone database,
 *       though crippling the performance in case of a lot of zones.
 *       We need the tree structure in order to find the appropriate zone where
 *       to search.
 * @todo Consider using one large hash table for all zones for searching and
 *       the zone structure only for some additional issues. If we can avoid
 *       using the zone structure during each query, it may be worth it.
 *		 Moreover it may save some space - less empty items in one large hash
 *		 table than in several smaller.
 */
#ifndef ZONE_DATABASE
#define ZONE_DATABASE

#include "common.h"
#include "dns-simple.h"
#include "zone-data-structure.h"

/*----------------------------------------------------------------------------*/
/*!
 * @brief Structure for storing one zone. Uses zds_zone structure for data.
 */
typedef struct zdb_zone {
	/*! @brief Zone name in wire format (i.e. a null-terminated string). */
    dnss_dname_wire zone_name;

	/*! @brief Pointer to the zone data structure. */
    zds_zone *zone;

	/*! @brief Next item pointer. */
    struct zdb_zone *next;
} zdb_zone;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Zone database structure.
 */
typedef struct zdb_database {
	/*! @brief Pointer to the first item in the linked list of zones. */
    zdb_zone *head;
} zdb_database;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Allocates and initializes the zone database structure.
 */
zdb_database *zdb_create();

/*!
 * @brief Adds new zone to the given database.
 *
 * @param database Zone database to store the zone.
 * @param zone_name Zone name in wire format  (i.e. a null-terminated string).
 * @param items Number of items in the zone. Is used for creating the zone data
 *              structure of appropriate size.
 *
 * @retval 0 On success.
 * @retval -1 On failure.
 */
int zdb_create_zone( zdb_database *database, dnss_dname_wire zone_name,
                     uint items );

/*!
 * @brief Removes the given zone from the database if it exists.
 *
 * @param database Zone database to remove from.
 * @param zone_name Name of the zone to be removed.
 *
 * The removal of a zone is synchronized using RCU mechanism, so the zone data
 * will not be destroyed while some thread may be using it.
 *
 * @retval 0 On success.
 * @retval -1 If the zone was not found.
 */
int zdb_remove_zone( zdb_database *database, dnss_dname_wire zone_name );

/*!
 * @brief Inserts one zone node to the given zone in the database.
 *
 * @param database Zone database to insert the node into.
 * @param zone_name Name of the zone to insert the node into.
 * @param dname Domain name of the node.
 * @param node The zone node to be inserted.
 *
 * @retval 0 On success.
 * @retval 1 If the zone was not found.
 * @retval -1 If an error occured during insertion to the zone.
 */
int zdb_insert_name( zdb_database *database, dnss_dname_wire zone_name,
                     dnss_dname_wire dname, zn_node *node );

/*!
 * @brief Finds the given name in the zone database and returns corresponding
 *        zone node.
 *
 * @param database Zone database to search in.
 * @param dname Domain name to find, in wire format (i.e. a null-terminated
 *              string).
 *
 * @return Proper zone node for the given name or NULL if not found.
 */
const zn_node *zdb_find_name( zdb_database *database, dnss_dname_wire dname );

/*!
 * @brief Destroys and deallocates the whole zone database.
 *
 * @param database Pointer to pointer to the zone database to be destroyed.
 *
 * The zones are destroyed one-by-one and the process is synchronized using
 * RCU mechanism, so the zone data will not be destroyed while some thread may
 * be using it.
 */
void zdb_destroy( zdb_database **database );

/*----------------------------------------------------------------------------*/

#endif // ZONE_DATABASE
