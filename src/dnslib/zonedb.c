#include <config.h>
#include <stdlib.h>
#include <assert.h>

#include <urcu.h>

#include "common.h"
#include "dnslib/zonedb.h"
#include "lib/skip-list.h"
#include "dnslib/zone.h"
#include "dnslib/dname.h"
#include "dnslib/node.h"
#include "conf/conf.h"
#include "dnslib/error.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int dnslib_zonedb_compare_zone_names(void *d1, void *d2)
{
	const dnslib_dname_t *dname1 = (const dnslib_dname_t *)d1;
	const dnslib_dname_t *dname2 = (const dnslib_dname_t *)d2;

	int ret = dnslib_dname_compare(dname1, dname2);

DEBUG_DNSLIB_ZONEDB(
	char *name1 = dnslib_dname_to_str(dname1);
	char *name2 = dnslib_dname_to_str(dname2);
	debug_dnslib_zonedb("Compared names %s and %s, result: %d.\n",
			    name1, name2, ret);
	free(name1);
	free(name2);
);

	return (ret);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

dnslib_zonedb_t *dnslib_zonedb_new()
{
	dnslib_zonedb_t *db =
		(dnslib_zonedb_t *)malloc(sizeof(dnslib_zonedb_t));
	CHECK_ALLOC_LOG(db, NULL);

	db->zones = skip_create_list(dnslib_zonedb_compare_zone_names);
	if (db->zones == NULL) {
		free(db);
		return NULL;
	}

	return db;
}

/*----------------------------------------------------------------------------*/

int dnslib_zonedb_add_zone(dnslib_zonedb_t *db, dnslib_zone_t *zone)
{
DEBUG_DNSLIB_ZONEDB(
	char *name = dnslib_dname_to_str(zone->apex->owner);
	debug_dnslib_zonedb("Inserting zone %s into zone db.\n", name);
	free(name);
);
	dnslib_zone_load_nsec3param(zone);

	int ret = skip_insert(db->zones, zone->apex->owner, zone, NULL);
	assert(ret == 0 || ret == 1 || ret == -1);
	return (ret != 0) ? DNSLIB_EZONEIN : DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zonedb_remove_zone(dnslib_zonedb_t *db, dnslib_dname_t *zone_name)
{
	// add some lock to avoid multiple removals
	dnslib_zone_t *z = (dnslib_zone_t *)skip_find(db->zones, zone_name);

	if (z == NULL) {
		return DNSLIB_ENOZONE;
	}

	// remove the zone from the skip list, but do not destroy it
	int ret = skip_remove(db->zones, zone_name, NULL, NULL);
	assert(ret == 0);

	// wait for all readers to finish
	synchronize_rcu();

	// properly destroy the zone and all its contents
	dnslib_zone_deep_free(&z);

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

const dnslib_zone_t *dnslib_zonedb_find_zone_for_name(dnslib_zonedb_t *db,
						    const dnslib_dname_t *dname)
{
	rcu_read_lock();

	dnslib_zone_t *zone = skip_find_less_or_equal(db->zones, (void *)dname);

DEBUG_DNSLIB_ZONEDB(
	char *name = dnslib_dname_to_str(dname);
	debug_ns("Found zone for name %s: %p\n", name, zone);
	free(name);
);
	if (zone != NULL
	    && dnslib_dname_compare(zone->apex->owner, dname) != 0
	    && !dnslib_dname_is_subdomain(dname, zone->apex->owner)) {
		zone = NULL;
	}
	rcu_read_unlock();

	return zone;
}

/*----------------------------------------------------------------------------*/

void dnslib_zonedb_deep_free(dnslib_zonedb_t **db)
{
	const skip_node_t *zn = skip_first((*db)->zones);
	dnslib_zone_t *zone = NULL;

	while (zn != NULL) {
		zone = (dnslib_zone_t *)zn->value;
		assert(zone != NULL);

		// remove the zone from the database
		skip_remove((*db)->zones, zn->key, NULL, NULL);
		// wait for all readers to finish
		synchronize_rcu();
		// destroy the zone
		dnslib_zone_deep_free(&zone);

		zn = skip_first((*db)->zones);
	}

	assert(skip_is_empty((*db)->zones));

	skip_destroy_list(&(*db)->zones, NULL, NULL);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

