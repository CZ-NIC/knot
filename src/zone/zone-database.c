#include "zone-database.h"
#include "common.h"

#include <stdio.h>
#include <assert.h>
#include <ldns/rdata.h>
#include <ldns/dname.h>
#include <urcu.h>

#include "dns-utils.h"

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/

void zdb_find_zone( zdb_database *database, ldns_rdf *zone_name,
					zdb_zone **zone, zdb_zone **prev )
{
	*zone = database->head;
	*prev = NULL;

	// start of RCU reader critical section
	rcu_read_lock();

	while ((*zone) != NULL
		   && ldns_dname_compare((*zone)->zone_name, zone_name)) {
		(*prev) = (*zone);
		(*zone) = (*zone)->next;
	}

	// end of RCU reader critical section
	rcu_read_unlock();
}

/*----------------------------------------------------------------------------*/

void zdb_disconnect_zone( zdb_database *database, zdb_zone *z, zdb_zone *prev )
{
	// disconect the zone from the list
	if (prev != NULL) {
		prev->next = z->next;
	} else {
		database->head = z->next;
	}
}

/*----------------------------------------------------------------------------*/

zdb_zone *zdb_find_zone_for_name( zdb_database *database, ldns_rdf *dname )
{
	zdb_zone *z = database->head, *best = NULL;
	uint most_matched = 0;

	// start of RCU reader critical section
	// maybe not needed, called only from zdb_find_name()
	rcu_read_lock();

	while (z != NULL) {
		uint matched = dnsu_subdomain_labels(dname, z->zone_name);
		if (matched > most_matched) {
			most_matched = matched;
			best = z;
		}
		z = z->next;
	}

	// end of RCU reader critical section
	rcu_read_unlock();

	return best;
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

zdb_database *zdb_create()
{
    zdb_database *db = malloc(sizeof(zdb_database));

    if (db == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    db->head = NULL;
    return db;
}

/*----------------------------------------------------------------------------*/

int zdb_create_zone( zdb_database *database, ldns_rdf *zone_name, uint items )
{
	// add some lock to avoid multiple zone creations?
	// add some check if the zone is not already in db?

    zdb_zone *zone = malloc(sizeof(zdb_zone));

    if (zone == NULL) {
        ERR_ALLOC_FAILED;
        return -1;
    }

	zone->zone_name = ldns_rdf_clone(zone_name);

    if (zone->zone_name == NULL) {
        ERR_ALLOC_FAILED;
        free(zone);
        return -1;
    }

    zone->zone = zds_create(items);

    if (zone->zone == NULL) {
		log_error("Could not create zone data structure for zone %s\n",
				  ldns_rdf_data(zone_name));
		ldns_rdf_deep_free(zone->zone_name);
        free(zone);
        return -1;
    }

    // insert it to the beginning of the list
    zone->next = database->head;
    database->head = zone;

    return 0;
}
/*----------------------------------------------------------------------------*/

int zdb_remove_zone( zdb_database *database, ldns_rdf *zone_name )
{
	// add some lock to avoid multiple removals

    zdb_zone *z = NULL, *zp = NULL;
    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
        return -1;
    }

	zdb_disconnect_zone(database, z, zp);

	// wait for all readers to finish
	synchronize_rcu();

    zds_destroy(&z->zone);
    assert(z->zone == NULL);
	ldns_rdf_deep_free(z->zone_name);
    free(z);

    return 0;
}

/*----------------------------------------------------------------------------*/

int zdb_insert_name( zdb_database *database, ldns_rdf *zone_name,
					 ldns_rdf *dname, zn_node *node )
{
    zdb_zone *z = NULL, *zp = NULL;

	// start of RCU reader critical section (the zone should not be removed)
	rcu_read_lock();

    zdb_find_zone(database, zone_name, &z, &zp);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
		return 1;
    }

	debug_zdb("Found zone: %*s\n", ldns_rdf_size(z->zone_name),
			  ldns_rdf_data(z->zone_name));

	int res = zds_insert(z->zone, dname, node);

	// end of RCU reader critical section
	rcu_read_unlock();
	return res;
}

/*----------------------------------------------------------------------------*/

const zn_node *zdb_find_name( zdb_database *database, ldns_rdf *dname )
{
	// start of RCU reader critical section
	rcu_read_lock();

    zdb_zone *z = zdb_find_zone_for_name(database, dname);

    if (z == NULL) {
        debug_zdb("Zone not found!\n");
        return NULL;
    }

	debug_zdb("Found zone: %*s\n", ldns_rdf_size(z->zone_name),
			  ldns_rdf_data(z->zone_name));

	const zn_node *found = zds_find(z->zone, dname);

	// end of RCU reader critical section
	rcu_read_unlock();

	return found;
}

/*----------------------------------------------------------------------------*/

void zdb_destroy( zdb_database **database )
{
	// add some lock to avoid multiple destroys

	zdb_zone *z;

	while ((*database)->head != NULL) {
		z = (*database)->head;
		// disconnect the first zone
		(*database)->head = z->next;
		// wait for all readers to finish
		synchronize_rcu();
		// destroy zone
		zds_destroy(&z->zone);
		ldns_rdf_deep_free(z->zone_name);
		free(z);
    }
}
