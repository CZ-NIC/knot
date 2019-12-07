/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdlib.h>

#include "knot/journal/journal_metadata.h"
#include "knot/zone/zonedb.h"
#include "libknot/packet/wire.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/mempool.h"

/*! \brief Discard zone in zone database. */
static void discard_zone(zone_t *zone, bool abort_txn)
{
	// Don't flush if removed zone (no previous configuration available).
	if (conf_rawid_exists(conf(), C_ZONE, zone->name, knot_dname_size(zone->name))) {
		uint32_t journal_serial, zone_serial = zone_contents_serial(zone->contents);
		bool exists;

		// Flush if bootstrapped or if the journal doesn't exist.
		if (!zone->zonefile.exists || journal_info(
			zone_journal(zone), &exists, NULL, NULL, &journal_serial, NULL, NULL, NULL, NULL
		    ) != KNOT_EOK || !exists || journal_serial != zone_serial) {
			zone_flush_journal(conf(), zone, false);
		}
	}

	if (abort_txn) {
		zone_control_clear(zone);
	}
	zone_free(&zone);
}

knot_zonedb_t *knot_zonedb_new(void)
{
	knot_zonedb_t *db = calloc(1, sizeof(knot_zonedb_t));
	if (db == NULL) {
		return NULL;
	}

	mm_ctx_mempool(&db->mm, MM_DEFAULT_BLKSIZE);

	db->trie = trie_create(&db->mm);
	if (db->trie == NULL) {
		mp_delete(db->mm.ctx);
		free(db);
		return NULL;
	}

	return db;
}

int knot_zonedb_insert(knot_zonedb_t *db, zone_t *zone)
{
	if (db == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	assert(zone->name);
	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone->name, lf_storage);
	assert(lf);

	*trie_get_ins(db->trie, lf + 1, *lf) = zone;

	return KNOT_EOK;
}

int knot_zonedb_del(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	if (db == NULL || zone_name == NULL) {
		return KNOT_EINVAL;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone_name, lf_storage);
	assert(lf);

	trie_val_t *rval = trie_get_try(db->trie, lf + 1, *lf);
	if (rval == NULL) {
		return KNOT_ENOENT;
	}

	return trie_del(db->trie, lf + 1, *lf, NULL);
}

zone_t *knot_zonedb_find(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	if (db == NULL) {
		return NULL;
	}

	knot_dname_storage_t lf_storage;
	uint8_t *lf = knot_dname_lf(zone_name, lf_storage);
	assert(lf);

	trie_val_t *val = trie_get_try(db->trie, lf + 1, *lf);
	if (val == NULL) {
		return NULL;
	}

	return *val;
}

zone_t *knot_zonedb_find_suffix(knot_zonedb_t *db, const knot_dname_t *zone_name)
{
	if (db == NULL || zone_name == NULL) {
		return NULL;
	}

	while (true) {
		knot_dname_storage_t lf_storage;
		uint8_t *lf = knot_dname_lf(zone_name, lf_storage);
		assert(lf);

		trie_val_t *val = trie_get_try(db->trie, lf + 1, *lf);
		if (val != NULL) {
			return *val;
		} else if (zone_name[0] == 0) {
			return NULL;
		}

		zone_name = knot_wire_next_label(zone_name, NULL);
	}
}

size_t knot_zonedb_size(const knot_zonedb_t *db)
{
	if (db == NULL) {
		return 0;
	}

	return trie_weight(db->trie);
}

void knot_zonedb_free(knot_zonedb_t **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	mp_delete((*db)->mm.ctx);
	free(*db);
	*db = NULL;
}

void knot_zonedb_deep_free(knot_zonedb_t **db, bool abort_txn)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	knot_zonedb_foreach(*db, discard_zone, abort_txn);
	knot_zonedb_free(db);
}
