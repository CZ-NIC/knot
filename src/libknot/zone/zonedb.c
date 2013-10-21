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

#include "libknot/common.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zonedb.h"
#include "libknot/dname.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zonedb_t *knot_zonedb_new()
{
	knot_zonedb_t *db =
		(knot_zonedb_t *)malloc(sizeof(knot_zonedb_t));
	CHECK_ALLOC_LOG(db, NULL);

	db->zone_tree = hattrie_create();
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
		return KNOT_EINVAL;
	}

	/*! \todo Why is this check here? */
	int ret = KNOT_EOK;
	if (knot_zone_contents(zone)) {
		ret = knot_zone_contents_load_nsec3param(
				knot_zone_get_contents(zone));
		if (ret != KNOT_EOK) {
			log_zone_error("NSEC3 signed zone has invalid or no "
			               "NSEC3PARAM record.\n");
			return ret;
		}
	}

	/* Insert new record. */
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, zone->name, NULL);
	*hattrie_get(db->zone_tree, (char*)lf+1, *lf) = zone;

	db->zone_count++;

	return ret;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_remove_zone(knot_zonedb_t *db,
                                     const knot_dname_t *zone_name)
{
	/* Fetch if exists. */
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, zone_name, NULL);

	value_t *old_zone = hattrie_tryget(db->zone_tree, (char*)lf+1, *lf);
	if (old_zone == NULL)
		return NULL;

	/* Remove from db. */
	if (hattrie_del(db->zone_tree, (char*)lf+1, *lf) < 0)
		return NULL;

	--db->zone_count;
	return (knot_zone_t *)*old_zone;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find_zone(const knot_zonedb_t *db,
                                       const knot_dname_t *zone_name)
{
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, zone_name, NULL);
	value_t *val = hattrie_tryget(db->zone_tree, (char*)lf+1, *lf);
	if (val)
		return (knot_zone_t *)*val;

	return NULL;
}

/*----------------------------------------------------------------------------*/

const knot_zone_t *knot_zonedb_find_zone_for_name(knot_zonedb_t *db,
                                                    const knot_dname_t *dname)
{
	if (db == NULL || dname == NULL) {
		return NULL;
	}

	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, dname, NULL);

	/* Attempt to find longest matching prefix.
	 * as zones are stored as \x00com\x00lake\x00
	 * the longest matching prefix is essentially a best match,
	 * as it is guaranteed that inserted names end in \x00
	 */
	value_t *val = NULL;
	int len = hattrie_find_lpr(db->zone_tree, (char*)lf+1, *lf, &val);
	if (len > -1) {
		return (const knot_zone_t *)*val;
	}

	return NULL;
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

	db_new->zone_tree = hattrie_dup(db->zone_tree, NULL);
	if (db_new->zone_tree == NULL) {
		free(db_new);
		return NULL;
	}

	return db_new;
}

/*----------------------------------------------------------------------------*/

size_t knot_zonedb_zone_count(const knot_zonedb_t *db)
{
	return db->zone_count;
}

/*----------------------------------------------------------------------------*/

struct knot_zone_db_tree_arg {
	const knot_zone_t **zones;
	size_t count;
};

/*----------------------------------------------------------------------------*/

static void save_zone_to_array(void *node, void *data)
{
	knot_zone_t *zone = (knot_zone_t *)node;
	struct knot_zone_db_tree_arg *args =
		(struct knot_zone_db_tree_arg *)data;
	assert(data);
	args->zones[args->count++] = zone;
}

/*----------------------------------------------------------------------------*/

const knot_zone_t **knot_zonedb_zones(const knot_zonedb_t *db)
{
	struct knot_zone_db_tree_arg args;
	args.zones = malloc(sizeof(knot_zone_t *) * db->zone_count);
	args.count = 0;
	CHECK_ALLOC_LOG(args.zones, NULL);

	hattrie_iter_t *i = hattrie_iter_begin(db->zone_tree, 1);
	while(!hattrie_iter_finished(i)) {
		save_zone_to_array(*hattrie_iter_val(i), &args);
		hattrie_iter_next(i);
	}
	hattrie_iter_free(i);

	assert(db->zone_count == args.count);

	return args.zones;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_free(knot_zonedb_t **db)
{
	hattrie_free((*db)->zone_tree);
	free(*db);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

static int delete_zone_from_db(value_t *node, void *data)
{
	UNUSED(data);
	assert(node);
	if (*node != NULL) {
		knot_zone_t *zone = (knot_zone_t *)(*node);
		synchronize_rcu();
		knot_zone_set_flag(zone, KNOT_ZONE_DISCARDED, 1);
		knot_zone_release(zone);
		*node = NULL;
	}

	return KNOT_EOK;
}

void knot_zonedb_deep_free(knot_zonedb_t **db)
{
	dbg_zonedb("Deleting zone db (%p).\n", *db);
	hattrie_apply_rev((*db)->zone_tree, delete_zone_from_db, NULL);
	hattrie_free((*db)->zone_tree);
	free(*db);
	*db = NULL;
}
