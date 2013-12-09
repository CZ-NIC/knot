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
#include "libknot/util/wire.h"
#include "libknot/zone/node.h"
#include "libknot/util/debug.h"
#include "common/mempattern.h"
#include "common/mempool.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

/*! \brief Discard zone in zone database. */
static void delete_zone_from_db(knot_zone_t *zone)
{
	synchronize_rcu();
	knot_zone_set_flag(zone, KNOT_ZONE_DISCARDED, 1);
	knot_zone_release(zone);
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_zonedb_t *knot_zonedb_new(uint32_t size)
{
	/* Create memory pool context. */
	mm_ctx_t mm;
	mm.ctx = mp_new(4096);
	mm.alloc = (mm_alloc_t)mp_alloc;
	mm.free = mm_nofree;
	knot_zonedb_t *db = mm.alloc(mm.ctx, sizeof(knot_zonedb_t));
	if (db == NULL) {
		return NULL;
	}

	db->maxlabels = 0;
	db->hash = hhash_create_mm((size + 1) * 2, &mm);
	if (db->hash == NULL) {
		mm.free(db);
		return NULL;
	}

	memcpy(&db->mm, &mm, sizeof(mm_ctx_t));
	return db;
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_insert(knot_zonedb_t *db, knot_zone_t *zone)
{
	if (db == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	int name_size = knot_dname_size(zone->name);
	return hhash_insert(db->hash, (const char*)zone->name, name_size, zone);
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_del(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	if (db == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Can't guess maximum label count now. */
	db->maxlabels = KNOT_DNAME_MAXLABELS;
	/* Attempt to remove zone. */
	int name_size = knot_dname_size(zone_name);
	return hhash_del(db->hash, (const char*)zone_name, name_size);
}

/*----------------------------------------------------------------------------*/

int knot_zonedb_build_index(knot_zonedb_t *db)
{
	/* Rebuild order index. */
	hhash_build_index(db->hash);

	/* Calculate maxlabels. */
	db->maxlabels = 0;
	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(db, &it);
	while (!knot_zonedb_iter_finished(&it)) {
		knot_zone_t *zone = knot_zonedb_iter_val(&it);
		db->maxlabels = MAX(db->maxlabels, knot_dname_labels(zone->name, NULL));
		knot_zonedb_iter_next(&it);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	if (!db || !zone_name) {
		return NULL;
	}

	int name_size = knot_dname_size(zone_name);
	value_t *ret = hhash_find(db->hash, (const char*)zone_name, name_size);
	if (ret == NULL) {
		return NULL;
	}

	return *ret;
}

/*----------------------------------------------------------------------------*/

knot_zone_t *knot_zonedb_find_suffix(knot_zonedb_t *db, const knot_dname_t *dname)
{
	if (db == NULL || dname == NULL) {
		return NULL;
	}
	
	/* We know we have at most N label zones, so let's compare only those
	 * N last labels. */
	int zone_labels = knot_dname_labels(dname, NULL);
	while (zone_labels > db->maxlabels) {
		dname = knot_wire_next_label(dname, NULL);
		--zone_labels;
	}

	/* Compare possible suffixes. */
	knot_zone_t *ret = NULL;
	while (zone_labels > -1) { /* Include root label. */
		ret = knot_zonedb_find(db, dname);
		if (ret != NULL) {
			break;
		}
		dname = knot_wire_next_label(dname, NULL);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

knot_zone_contents_t *knot_zonedb_expire_zone(knot_zonedb_t *db,
                                              const knot_dname_t *zone_name)
{
	
	if (db == NULL || zone_name == NULL) {
		return NULL;
	}

	// Remove the contents from the zone, but keep the zone in the zonedb.

	knot_zone_t *zone = knot_zonedb_find(db, zone_name);
	if (zone == NULL) {
		return NULL;
	}

	return knot_zone_switch_contents(zone, NULL);
}

/*----------------------------------------------------------------------------*/

size_t knot_zonedb_size(const knot_zonedb_t *db)
{
	return db->hash->weight;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_free(knot_zonedb_t **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	mp_delete((*db)->mm.ctx);
	*db = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_zonedb_deep_free(knot_zonedb_t **db)
{
	/* Reindex for iteration. */
	knot_zonedb_build_index(*db);
	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(*db, &it);
	while (!knot_zonedb_iter_finished(&it)) {
		delete_zone_from_db(knot_zonedb_iter_val(&it));
		knot_zonedb_iter_next(&it);
	}

	knot_zonedb_free(db);
}
