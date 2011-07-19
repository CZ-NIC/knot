#include <config.h>
#include <stdlib.h>
#include <assert.h>

#include <urcu.h>

#include "dnslib/dnslib-common.h"
#include "dnslib/zonedb.h"
#include "dnslib/zone.h"
#include "dnslib/dname.h"
#include "dnslib/node.h"
#include "dnslib/error.h"
#include "dnslib/debug.h"
#include "common/skip-list.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/
/*!
 * \brief Compares the two arguments interpreted as zone names (domain names).
 *
 * Use this function with generic data structures (such as the skip list).
 *
 * \param d1 First zone name.
 * \param d2 Second zone name.
 *
 * \retval 0 if the two zone names are equal.
 * \retval < 0 if \a d1 is before \a d2 in canonical order.
 * \retval > 0 if \a d1 is after \a d2 in canonical order.
 */
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

//static int dnslib_zonedb_replace_zone_in_list(void **list_item, void **new_zone)
//{
//	assert(list_item != NULL);
//	assert(*list_item != NULL);
//	assert(new_zone != NULL);
//	assert(*new_zone != NULL);

//	debug_dnslib_zonedb("Replacing list item %p with new zone %p\n",
//	                    *list_item, *new_zone);

//	*list_item = *new_zone;

//	return 0;
//}

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
	if (db == NULL || zone == NULL || zone->contents == NULL
	    || zone->contents->apex == NULL) {
		return DNSLIB_EBADARG;
	}
DEBUG_DNSLIB_ZONEDB(
	char *name = dnslib_dname_to_str(zone->apex->owner);
	debug_dnslib_zonedb("Inserting zone %s into zone db.\n", name);
	free(name);
);
	int ret = dnslib_zone_load_nsec3param(zone);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	ret = skip_insert(db->zones, zone->contents->apex->owner, zone, NULL);
	assert(ret == 0 || ret == 1 || ret == -1);
	return (ret != 0) ? DNSLIB_EZONEIN : DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_zonedb_remove_zone(dnslib_zonedb_t *db, dnslib_dname_t *zone_name,
                              int destroy_zone)
{
	// add some lock to avoid multiple removals
	dnslib_zone_t *z = (dnslib_zone_t *)skip_find(db->zones, zone_name);

	if (z == NULL) {
		return DNSLIB_ENOZONE;
	}

	// remove the zone from the skip list, but do not destroy it
	int ret = skip_remove(db->zones, zone_name, NULL, NULL);
	assert(ret == 0);

	if (destroy_zone) {
		// properly destroy the zone and all its contents
		dnslib_zone_deep_free(&z, 0);
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zonedb_replace_zone(dnslib_zonedb_t *db,
                                          dnslib_zone_t *zone)
{
	dnslib_zone_t *z = dnslib_zonedb_find_zone(db,
		dnslib_node_owner(dnslib_zone_apex(zone)));
	if (z == NULL) {
		return NULL;
	}

	debug_dnslib_zonedb("Found zone: %p\n", z);

	int ret = skip_remove(db->zones,
	                      (void *)dnslib_node_owner(dnslib_zone_apex(zone)),
	                      NULL, NULL);
	if (ret != 0) {
		return NULL;
	}

	debug_dnslib_zonedb("Removed zone, return value: %d\n", ret);
	debug_dnslib_zonedb("Old zone: %p\n", z);

	ret = skip_insert(db->zones,
	                  (void *)dnslib_node_owner(dnslib_zone_apex(zone)),
	                  (void *)zone, NULL);

	debug_dnslib_zonedb("Inserted zone, return value: %d\n", ret);

	if (ret != 0) {
		// return the removed zone back
		skip_insert(db->zones,
		            (void *)dnslib_node_owner(dnslib_zone_apex(z)),
		            (void *)z, NULL);
		/*! \todo There may be problems and the zone may remain
		          removed. */
		return NULL;
	}

	return z;
}

/*----------------------------------------------------------------------------*/

dnslib_zone_t *dnslib_zonedb_find_zone(const dnslib_zonedb_t *db,
                                       const dnslib_dname_t *zone_name)
{
	return (dnslib_zone_t *)skip_find(db->zones, (void *)zone_name);
}

/*----------------------------------------------------------------------------*/

const dnslib_zone_t *dnslib_zonedb_find_zone_for_name(dnslib_zonedb_t *db,
                                                    const dnslib_dname_t *dname)
{
	if (db == NULL || dname == NULL) {
		return NULL;
	}

	dnslib_zone_t *zone = skip_find_less_or_equal(db->zones, (void *)dname);

DEBUG_DNSLIB_ZONEDB(
	char *name = dnslib_dname_to_str(dname);
	debug_dnslib_zonedb("Found zone for name %s: %p\n", name, zone);
	free(name);
);
	if (zone != NULL
	    && dnslib_dname_compare(zone->contents->apex->owner, dname) != 0
	    && !dnslib_dname_is_subdomain(dname, zone->contents->apex->owner)) {
		zone = NULL;
	}

	return zone;
}

/*----------------------------------------------------------------------------*/

dnslib_zonedb_t *dnslib_zonedb_copy(const dnslib_zonedb_t *db)
{
	dnslib_zonedb_t *db_new =
		(dnslib_zonedb_t *)malloc(sizeof(dnslib_zonedb_t));
	CHECK_ALLOC_LOG(db_new, NULL);

	db_new->zones = skip_copy_list(db->zones);
	if (db_new->zones == NULL) {
		free(db_new);
		return NULL;
	}

	return db_new;
}

/*----------------------------------------------------------------------------*/

void dnslib_zonedb_free(dnslib_zonedb_t **db)
{
	skip_destroy_list(&(*db)->zones, NULL, NULL);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

void dnslib_zonedb_deep_free(dnslib_zonedb_t **db)
{
	debug_dnslib_zonedb("Deleting zone db (%p).\n", *db);
	debug_dnslib_zonedb("Is it empty (%p)? %s\n",
	       (*db)->zones, skip_is_empty((*db)->zones) ? "yes" : "no");

	const skip_node_t *zn = skip_first((*db)->zones);
	dnslib_zone_t *zone = NULL;

DEBUG_DNSLIB_ZONEDB(
	int i = 1;
	char *name = NULL;
	while (zn != NULL) {
		debug_dnslib_zonedb("%d. zone: %p, key: %p\n", i, zn->value,
		                    zn->key);
		assert(zn->key == ((dnslib_zone_t *)zn->value)->apex->owner);
		name = dnslib_dname_to_str((dnslib_dname_t *)zn->key);
		debug_dnslib_zonedb("    zone name: %s\n", name);
		free(name);

		zn = skip_next(zn);
	}

	zn = skip_first((*db)->zones);
);

	while (zn != NULL) {
		zone = (dnslib_zone_t *)zn->value;
		assert(zone != NULL);

		// remove the zone from the database
		skip_remove((*db)->zones, zn->key, NULL, NULL);
		// wait for all readers to finish
		synchronize_rcu();
		// destroy the zone
		dnslib_zone_deep_free(&zone, 0);

		zn = skip_first((*db)->zones);
	}

	assert(skip_is_empty((*db)->zones));

	skip_destroy_list(&(*db)->zones, NULL, NULL);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

