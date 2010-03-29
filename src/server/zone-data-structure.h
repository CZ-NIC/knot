#ifndef ZONE_DATA_STRUCTURE
#define ZONE_DATA_STRUCTURE

#include "common.h"
#include "cuckoo-hash-table.h"
#include "dns-simple.h"
#include "zone-node.h"

/*----------------------------------------------------------------------------*/

typedef ck_hash_table zds_zone;

/*----------------------------------------------------------------------------*/

zds_zone *zds_create( uint item_count );

int zds_insert( zds_zone *zone, dnss_dname_wire owner,
                zn_node *contents );

zn_node *zds_find( zds_zone *zone, dnss_dname_wire owner );

int zds_remove( zds_zone *zone, dnss_dname_wire owner );

void zds_destroy( zds_zone **zone );

#endif
