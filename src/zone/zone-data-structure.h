/*!
 * @file zone-data-structure.h
 *
 * Provides generic interface to data structure for representing DNS zone. This
 * allows to easily change the underlying data structure without affecting the
 * rest of the code.
 *
 * The API contains functions for creating and destroying zones as well as for
 * inserting, removing and searching for domain names.
 */
#ifndef ZONE_DATA_STRUCTURE
#define ZONE_DATA_STRUCTURE

#include "common.h"
#include "cuckoo-hash-table.h"
#include "zone-node.h"
#include <ldns/rdata.h>

/*----------------------------------------------------------------------------*/
/*!
 * @brief Zone data structure implemented as a cuckoo hash table.
 *
 * @see ck-hash-table.h.
 */
typedef ck_hash_table zds_zone;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Allocates and initializes the structure.
 *
 * @param item_count Number of items in the zone. It may be used to create a
 *                   structure of appropriate size if the underlying structure
 *                   supports it.
 *
 * @return Pointer to the created zone data structure.
 */
zds_zone *zds_create( uint item_count );

/*!
 * @brief Inserts one zone node to the given zone.
 *
 * @param zone Zone data structure to insert into.
 * @param contents The zone node to be inserted.
 *
 * @retval 0 On success.
 * @retval -1 If an error occured during insertion to the zone.
 */
int zds_insert( zds_zone *zone, zn_node *node );

/*!
 * @brief Tries to find the given name in the zone and returns corresponding
 *        zone node.
 *
 * @param zone Zone data structure to search in.
 * @param owner Domain name to find, in wire format (i.e. a null-terminated
 *              string).
 *
 * @return Proper zone node for the given name or NULL if not found.
 */
zn_node *zds_find( zds_zone *zone, const ldns_rdf *owner );

/*!
 * @brief Removes zone node corresponding to the given domain name from the
 *        given zone if such name exists in the zone.
 *
 * @param zone Zone data structure to remove from.
 * @param owner Domain name of the node to be removed.
 *
 * @retval 0 On success.
 * @retval -1 If the name was not found in the zone.
 *
 * @todo Maybe return the removed node?
 */
int zds_remove( zds_zone *zone, ldns_rdf *owner );

/*!
 * @brief Properly destroys the given zone data structure.
 */
void zds_destroy( zds_zone **zone, void (*dtor_zone_node)( void *value ) );

#endif
