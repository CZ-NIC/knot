/*!
 * @note Some kind of tree will be probably best for the zone database,
 *       though crippling the performance in case of a lot of zones.
 *       We need the tree structure in order to find the appropriate zone where
 *       to search.
 * @todo Consider using one large hash table for all zones for searching and
 *       the zone structure only for some additional issues. If we can avoid
 *       using the zone structure during each query, it may be worth it.
 */

#ifndef ZONE_DATABASE
#define ZONE_DATABASE

#include "common.h"
#include "dns-simple.h"
#include "zone-data-structure.h"

/*----------------------------------------------------------------------------*/

typedef struct zdb_database {

} zdb_database;

/*----------------------------------------------------------------------------*/

zdb_database *zdb_create();

int zdb_insert_name( zdb_database *database, dnss_dname_wire dname,
                     zn_node *node );

int zdb_create_zone( zdb_database *database, dnss_dname_wire zone_name,
                     uint items );

const zds_node *zdb_find_name( zdb_database *database, dnss_dname_wire dname );

void zdb_destroy( zdb_database **database );

/*----------------------------------------------------------------------------*/

#endif // ZONE_DATABASE
