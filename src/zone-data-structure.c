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

/*! @todo Should return positive integer when the item was inserted, but
 *        something went wrong. Otherwise negative.
 */
int zds_insert( zds_zone *zone, dnss_dname_wire owner,
                       zn_node *contents )
{
    return ck_insert_item(zone, owner, dnss_dname_wire_length(owner) - 1,
                          contents);
}

/*----------------------------------------------------------------------------*/

zn_node *zds_find( zds_zone *zone, dnss_dname_wire owner )
{
    const ck_hash_table_item *item = ck_find_item(zone, owner,
                                        dnss_dname_wire_length(owner) - 1);
    if (item == NULL) {
        return NULL;
    }

    printf("Item found\n");

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
