#include "zone-data-structure.h"

#include "cuckoo-hash-table.h"
#include "zone-node.h"
#include <assert.h>
#include <stdio.h>

/*----------------------------------------------------------------------------*/

zds_zone *zds_create( uint item_count )
{
    ck_hash_table *table = ck_create_table(item_count, zn_destructor);
    return table;
}

/*----------------------------------------------------------------------------*/

int zds_insert( zds_zone *zone, dnss_dname_wire owner,
                       zn_node *contents )
{
    return ck_insert_item(zone, owner, dnss_dname_wire_length(owner), contents);
}

/*----------------------------------------------------------------------------*/

zn_node *zds_find( zds_zone *zone, dnss_dname_wire owner )
{
    const ck_hash_table_item *item = ck_find_item(zone, owner,
                                            dnss_dname_wire_length(owner));
    if (item == NULL) {
        return NULL;
    }

    return item->value;
}

/*----------------------------------------------------------------------------*/

int zds_remove( zds_zone *zone, dnss_dname_wire owner )
{
    printf("zds_remove(): Not implemented.\n");
    return -1;
}

/*----------------------------------------------------------------------------*/

void zds_destroy( zds_zone **zone )
{
    ck_destroy_table(zone);
}
