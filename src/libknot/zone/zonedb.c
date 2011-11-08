/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <assert.h>

#include <urcu.h>

#include "common.h"
#include "zone/zone.h"
#include "zone/zonedb.h"
#include "dname.h"
#include "zone/node.h"
#include "util/error.h"
#include "util/debug.h"
#include "common/general-tree.h"

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
static int knot_zonedb_compare_zone_names(void *p1, void *p2)
{
	const knot_zone_t *zone1 = (const knot_zone_t *)p1;
	const knot_zone_t *zone2 = (const knot_zone_t *)p2;

	int ret = knot_dname_compare(zone1->name, zone2->name);

dbg_zonedb_exec(
	char *name1 = knot_dname_to_str(zone1->name);
	char *name2 = knot_dname_to_str(zone2->name);
	dbg_zonedb("Compared names %s and %s, result: %d.\n",
			    name1, name2, ret);
	free(name1);
	free(name2);
);

	return (ret);
}

/*----------------------------------------------------------------------------*/

//static int knot_zonedb_replace_zone_in_list(void **list_item, void **new_zone)
//{
//	assert(list_item != NULL);
//	assert(*list_item != NULL);
//	assert(new_zone != NULL);
//	assert(*new_zone != NULL);

//	dbg_zonedb("Replacing list item %p with new zone %p\n",
//	                    *list_item, *new_zone);

//	*list_item = *new_zone;

//	return 0;
//}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zonedb_t *knot_zonedb_new()
{
	knot_zonedb_t *db =
		(knot_zonedb_t *)malloc(sizeof(knot_zonedb_t));
	CHECK_ALLOC_LOG(db, NULL);

	db->zone_tree = gen_tree_new(knot_zonedb_compare_zone_names);
	if (db->zone_tree == NULL) {
		free(db);
		return NULL;
	}
	
	db->zone_count = 0;

	return db;
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_add_zone(knot_zonedb_t *db, knot_zone_t *zone)
{
	if (db == NULL || zone == NULL) {
		return KNOT_EBADARG;
	}
dbg_zonedb_exec(
	char *name = knot_dname_to_str(zone->name);
	dbg_zonedb("Inserting zone %s into zone db.\n", name);
	free(name);
);

	int ret = KNOT_EOK;
	if (knot_zone_contents(zone)) {
		ret = knot_zone_contents_load_nsec3param(
				knot_zone_get_contents(zone));
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	ret = gen_tree_add(db->zone_tree, zone, NULL);

	if (ret == 0) {
		db->zone_count++;
	}

	return (ret != 0) ? KNOT_EZONEIN : KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_remove_zone(knot_zonedb_t *db,
                                     const knot_dname_t *zone_name)
{
	knot_zone_t dummy_zone;
	memset(&dummy_zone, 0, sizeof(knot_zone_t));
	dummy_zone.name = (knot_dname_t *)zone_name;

	// add some lock to avoid multiple removals
	knot_zone_t *z = (knot_zone_t *)gen_tree_find(db->zone_tree,
	                                                  &dummy_zone);

	if (z == NULL) {
		return NULL;
	}

	// remove the zone from the skip list, but do not destroy it
	gen_tree_remove(db->zone_tree, &dummy_zone);

//	if (destroy_zone) {
//		// properly destroy the zone and all its contents
//		knot_zone_deep_free(&z, 0);
//	}

	db->zone_count--;

	//return KNOT_EOK;
	return z;
}

/*----------------------------------------------------------------------------*/

//knot_zone_t *knot_zonedb_replace_zone(knot_zonedb_t *db,
//                                          knot_zone_t *zone)
//{
//	knot_zone_t *z = knot_zonedb_find_zone(db,
//		knot_node_owner(knot_zone_apex(zone)));
//	if (z == NULL) {
//		return NULL;
//	}
	
//	/*! \todo The replace should be atomic!!! */

//	dbg_zonedb("Found zone: %p\n", z);

//	int ret = skip_remove(db->zones,
//	                      (void *)knot_node_owner(knot_zone_apex(zone)),
//	                      NULL, NULL);
//	if (ret != 0) {
//		return NULL;
//	}

//	dbg_zonedb("Removed zone, return value: %d\n", ret);
//	dbg_zonedb("Old zone: %p\n", z);

//	ret = skip_insert(db->zones,
//	                  (void *)knot_node_owner(knot_zone_apex(zone)),
//	                  (void *)zone, NULL);

//	dbg_zonedb("Inserted zone, return value: %d\n", ret);

//	if (ret != 0) {
//		// return the removed zone back
//		skip_insert(db->zones,
//		            (void *)knot_node_owner(knot_zone_apex(z)),
//		            (void *)z, NULL);
//		/*! \todo There may be problems and the zone may remain
//		          removed. */
//		return NULL;
//	}

//	return z;
//}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find_zone(const knot_zonedb_t *db,
                                       const knot_dname_t *zone_name)
{
	knot_zone_t dummy_zone;
	dummy_zone.name = (knot_dname_t *)zone_name;
	return (knot_zone_t *)gen_tree_find(db->zone_tree, &dummy_zone);
}

/*----------------------------------------------------------------------------*/

const knot_zone_t *knot_zonedb_find_zone_for_name(knot_zonedb_t *db,
                                                    const knot_dname_t *dname)
{
	if (db == NULL || dname == NULL) {
		return NULL;
	}

	knot_zone_t dummy_zone;
	dummy_zone.name = (knot_dname_t *)dname;
	void *found = NULL;
	int exact_match = gen_tree_find_less_or_equal(db->zone_tree,
	                                              &dummy_zone,
	                                              &found);
	UNUSED(exact_match);

	knot_zone_t *zone = (found) ? (knot_zone_t *)found : NULL;

dbg_zonedb_exec(
	char *name = knot_dname_to_str(dname);
	dbg_zonedb("Found zone for name %s: %p\n", name, zone);
	free(name);
);
	if (zone != NULL && zone->contents != NULL
	    && knot_dname_compare(zone->contents->apex->owner, dname) != 0
	    && !knot_dname_is_subdomain(dname, zone->contents->apex->owner)) {
		zone = NULL;
	}

	return zone;
}

/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zonedb_expire_zone(knot_zonedb_t *db,
                                              const knot_dname_t *zone_name)
{
	if (db == NULL || zone_name == NULL) {
		return NULL;
	}

	// Remove the contents from the zone, but keep the zone in the zonedb.

	knot_zone_t *zone = knot_zonedb_find_zone(db, zone_name);
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_switch_contents(zone, NULL);
}

/*----------------------------------------------------------------------------*/

knot_zonedb_t *knot_zonedb_copy(const knot_zonedb_t *db)
{
	knot_zonedb_t *db_new =
		(knot_zonedb_t *)malloc(sizeof(knot_zonedb_t));
	CHECK_ALLOC_LOG(db_new, NULL);

	db_new->zone_tree = gen_tree_shallow_copy(db->zone_tree);
	if (db_new->zone_tree == NULL) {
		free(db_new);
		return NULL;
	}

	return db_new;
}

size_t knot_zonedb_zone_count(const knot_zonedb_t *db)
{
	return db->zone_count;
}

struct knot_zone_db_tree_arg {
	const knot_zone_t **zones;
	size_t count;
};

static void save_zone_to_array(void *node, void *data)
{
	knot_zone_t *zone = (knot_zone_t *)node;
	struct knot_zone_db_tree_arg *args =
		(struct knot_zone_db_tree_arg *)data;
	assert(data);
	args->zones[args->count++] = zone;
}

const knot_zone_t **knot_zonedb_zones(const knot_zonedb_t *db)
{
	struct knot_zone_db_tree_arg args;
	args.zones = malloc(sizeof(knot_zone_t) * db->zone_count);
	args.count = 0;
	CHECK_ALLOC_LOG(args.zones, NULL);

	gen_tree_apply_inorder(db->zone_tree, save_zone_to_array,
	                       &args);
	assert(db->zone_count == args.count);

	return args.zones;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_free(knot_zonedb_t **db)
{
	gen_tree_destroy(&((*db)->zone_tree), NULL ,NULL);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

static void delete_zone_from_db(void *node, void *data)
{
	UNUSED(data);
	knot_zone_t *zone = (knot_zone_t *)node;
	assert(zone);
	synchronize_rcu();
	knot_zone_deep_free(&zone, 0);
}

void knot_zonedb_deep_free(knot_zonedb_t **db)
{
	dbg_zonedb("Deleting zone db (%p).\n", *db);
//	dbg_zonedb("Is it empty (%p)? %s\n",
//	       (*db)->zones, skip_is_empty((*db)->zones) ? "yes" : "no");

//dbg_zonedb_exec(
//	int i = 1;
//	char *name = NULL;
//	while (zn != NULL) {
//		dbg_zonedb("%d. zone: %p, key: %p\n", i, zn->value,
//		                    zn->key);
//		assert(zn->key == ((knot_zone_t *)zn->value)->apex->owner);
//		name = knot_dname_to_str((knot_dname_t *)zn->key);
//		dbg_zonedb("    zone name: %s\n", name);
//		free(name);

//		zn = skip_next(zn);
//	}

//	zn = skip_first((*db)->zones);
//);

//	while (zn != NULL) {
//		zone = (knot_zone_t *)zn->value;
//		assert(zone != NULL);

//		// remove the zone from the database
//		skip_remove((*db)->zones, zn->key, NULL, NULL);
//		// wait for all readers to finish
//		synchronize_rcu;
//		// destroy the zone
//		knot_zone_deep_free(&zone, 0);

//		zn = skip_first((*db)->zones);
//	}

//	assert(skip_is_empty((*db)->zones));

//	skip_destroy_list(&(*db)->zones, NULL, NULL);
	gen_tree_destroy(&((*db)->zone_tree), delete_zone_from_db, NULL);
	assert((*db)->zone_tree == NULL);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

