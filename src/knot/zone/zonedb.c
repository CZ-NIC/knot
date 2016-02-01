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

#include <stdlib.h>
#include <assert.h>

#include "knot/zone/zonedb.h"
#include "libknot/packet/wire.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

/*! \brief Discard zone in zone database. */
static void discard_zone(zone_t *zone)
{
	char *journal_file = conf_journalfile(conf(), zone->name);

	/* Flush if bootstrapped or if the journal doesn't exist. */
	if (zone->zonefile_mtime == 0 || !journal_exists(journal_file)) {
		pthread_mutex_lock(&zone->journal_lock);
		zone_flush_journal(conf(), zone);
		pthread_mutex_unlock(&zone->journal_lock);
	}

	free(journal_file);

	zone_free(&zone);
}

knot_zonedb_t *knot_zonedb_new(uint32_t size)
{
	/* Create memory pool context. */
	knot_mm_t mm = {0};
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);
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

	memcpy(&db->mm, &mm, sizeof(knot_mm_t));
	return db;
}

int knot_zonedb_insert(knot_zonedb_t *db, zone_t *zone)
{
	if (db == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	int name_size = knot_dname_size(zone->name);
	if (name_size < 0) {
		return KNOT_EINVAL;
	}

	return hhash_insert(db->hash, (const char*)zone->name, name_size, zone);
}

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

int knot_zonedb_build_index(knot_zonedb_t *db)
{
	if (db == NULL) {
		return KNOT_EINVAL;
	}

	/* Rebuild order index. */
	hhash_build_index(db->hash);

	/* Calculate maxlabels. */
	db->maxlabels = 0;
	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(db, &it);
	while (!knot_zonedb_iter_finished(&it)) {
		zone_t *zone = knot_zonedb_iter_val(&it);
		db->maxlabels = MAX(db->maxlabels, knot_dname_labels(zone->name, NULL));
		knot_zonedb_iter_next(&it);
	}

	return KNOT_EOK;
}

static value_t *find_name(knot_zonedb_t *db, const knot_dname_t *dname, uint16_t size)
{
	assert(db);
	assert(dname);

	return hhash_find(db->hash, (const char*)dname, size);
}

zone_t *knot_zonedb_find(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	int name_size = knot_dname_size(zone_name);
	if (!db || name_size < 1) {
		return NULL;
	}

	value_t *ret = find_name(db, zone_name, name_size);
	if (ret == NULL) {
		return NULL;
	}

	return *ret;
}

zone_t *knot_zonedb_find_suffix(knot_zonedb_t *db, const knot_dname_t *dname)
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
	value_t *val = NULL;
	int name_size = knot_dname_size(dname);
	while (name_size > 0) { /* Include root label. */
		val = find_name(db, dname, name_size);
		if (val != NULL) {
			return *val;
		}

		/* Next label */
		name_size -= (dname[0] + 1);
		dname = knot_wire_next_label(dname, NULL);
	}

	return NULL;
}

size_t knot_zonedb_size(const knot_zonedb_t *db)
{
	if (db == NULL) {
		return 0;
	}

	return db->hash->weight;
}

void knot_zonedb_free(knot_zonedb_t **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	mp_delete((*db)->mm.ctx);
	*db = NULL;
}

void knot_zonedb_deep_free(knot_zonedb_t **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	/* Reindex for iteration. */
	knot_zonedb_build_index(*db);

	/* Free zones and database. */
	knot_zonedb_foreach(*db, discard_zone);
	knot_zonedb_free(db);
}
