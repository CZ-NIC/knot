#include "zone-data-structure.h"

#include "cuckoo-hash-table.h"
#include "zone-node.h"
#include <assert.h>
#include <stdio.h>
#include <ldns/rdata.h>

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
int zds_insert( zds_zone *zone, ldns_rdf *owner, zn_node *node )
{
	assert(ldns_rdf_get_type(owner) == LDNS_RDF_TYPE_DNAME);
	return ck_insert_item(zone, (char *)ldns_rdf_data(owner),
						  ldns_rdf_size(owner), node);
}

/*----------------------------------------------------------------------------*/

zn_node *zds_find( zds_zone *zone, ldns_rdf *owner )
{
	assert(ldns_rdf_get_type(owner) == LDNS_RDF_TYPE_DNAME);
	const ck_hash_table_item *item = ck_find_item(zone,
										(char *)ldns_rdf_data(owner),
										ldns_rdf_size(owner));
    if (item == NULL) {
        return NULL;
    }

    debug_zdb("Item found\n");

    return item->value;
}

/*----------------------------------------------------------------------------*/

int zds_remove( zds_zone *zone, ldns_rdf *owner )
{
	assert(ldns_rdf_get_type(owner) == LDNS_RDF_TYPE_DNAME);
	if (ck_remove_item(zone, (char *)ldns_rdf_data(owner),
					   ldns_rdf_size(owner)) != 0) {
		log_info("Trying to remove non-existing item: %s\n",
				 ldns_rdf_data(owner));
		return -1;
	}
	return 0;
}

/*----------------------------------------------------------------------------*/

void zds_destroy( zds_zone **zone )
{
    ck_destroy_table(zone);
}
