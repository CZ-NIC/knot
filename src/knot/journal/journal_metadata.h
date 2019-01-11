/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/journal/journal_basic.h"

typedef struct {
	uint32_t first_serial;
	uint32_t serial_to;
	uint32_t flushed_upto;
	uint32_t merged_serial;
	uint32_t changeset_count;
	uint32_t flags; // a bitmap of flags, see enum below
	bool _new_zone; // private: if there were no metadata at all previously
} journal_metadata_t;

enum journal_metadata_flags {
	JOURNAL_LAST_FLUSHED_VALID   = (1 << 0), // deprecated
	JOURNAL_SERIAL_TO_VALID      = (1 << 1),
	JOURNAL_MERGED_SERIAL_VALID  = (1 << 2),
};

typedef int (*journals_walk_cb_t)(const knot_dname_t *zone, void *ctx);

/*!
 * \brief Update the computation of DB resources used by each zone.
 *
 * Because the amount of used space is bigger than sum of changesets' serialized_sizes,
 * journal uses a complicated way to compute each zone's used space: there is a metadata
 * showing always the previously-inserting zone. Before the next insert, it is computed
 * how the total usage of the DB changed during the previous insert (or delete), and the
 * usage increase (or decrease) is accounted on the bill of the previous inserter.
 *
 * \param txn            Journal DB transaction.
 * \param new_inserter   Name of the zone that is going to insert now. Might be NULL if no insert nor delete will be done.
 */
void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter);

/* \brief Return the journal database usage by given zone. */
uint64_t journal_get_occupied(knot_lmdb_txn_t *txn, const knot_dname_t *zone);

/*!
 * \brief Load the metadata from DB into structure.
 *
 * \param txn    Journal DB transaction.
 * \param zone   Zone name.
 * \param md     Output: metadata structure.
 */
void journal_load_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, journal_metadata_t *md);

/*!
 * \brief Store the metadata from structure into DB.
 *
 * \param txn    Journal DB transaction.
 * \param zone   Zone name.
 * \param md     Metadata structure.
 */
void journal_store_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const journal_metadata_t *md);

/*!
 * \brief Update metadata according to what was deleted.
 *
 * \param md              Metadata structure to be updated.
 * \param deleted_upto    Serial-to of the last deleted changeset.
 * \param deleted_count   Number of deleted changesets.
 */
void journal_metadata_after_delete(journal_metadata_t *md, uint32_t deleted_upto,
                                   size_t deleted_count);

/*!
 * \brief Update metadata according to what was merged.
 *
 * \param md                   Metadata structure to be updated.
 * \param merged_zij           True if it was a merge into zone-in-journal.
 * \param merged_serial        Serial-from of the merged changeset (ignored if 'merged_zij').
 * \param merged_serial_to     Serial-to of the merged changeset.
 * \param original_serial_to   Previous serial-to of the merged changeset before the merge.
 */
void journal_metadata_after_merge(journal_metadata_t *md, bool merged_zij, uint32_t merged_serial,
                                  uint32_t merged_serial_to, uint32_t original_serial_to);

/*!
 * \brief Update metadata according to what was inserted.
 *
 * \param md          Metadata structure to be updated.
 * \param serial      Serial-from of the inserted changeset.
 * \param serial_to   Serial-to of the inserted changeset.
 */
void journal_metadata_after_insert(journal_metadata_t *md, uint32_t serial, uint32_t serial_to);

/*!
 * \brief Completely delete all journal records belonging to this zone, including metadata.
 *
 * \param j   Journal to be scraped.
 *
 * \return KNOT_E*
 */
int journal_scrape_with_md(zone_journal_t j);

/*!
 * \brief Update the metadata stored in journal DB after a zone flush.
 *
 * \param j   Journal to be notified about flush.
 *
 * \return KNOT_E*
 */
int journal_set_flushed(zone_journal_t j);

/*!
 * \brief Obtain information about the zone's journal from the DB (mostly metadata).
 *
 * \param j                Zone journal.
 * \param exists           Output: bool if the zone exists in the journal.
 * \param first_serial     Optional output: serial-from of the first changeset in journal.
 * \param serial_to        Optional output: serial.to of the last changeset in journal.
 * \param has_merged       Optional output: bool if there is a special (non zone-in-journal) merged changeset.
 * \param merged_serial    Optional output: serial-from of the merged changeset.
 * \param occupied         Optional output: DB space occupied by this zones.
 * \param occupied_total   Optional output: DB space occupied in total by all zones.
 *
 * \return KNOT_E*
 */
int journal_info(zone_journal_t j, bool *exists, uint32_t *first_serial,
                 uint32_t *serial_to, bool *has_merged, uint32_t *merged_serial,
                 uint64_t *occupied, uint64_t *occupied_total);

/*! \brief Return true if this zone exists in journal DB. */
inline static bool journal_is_existing(zone_journal_t j) {
	bool ex = false;
	journal_info(j, &ex, NULL, NULL, NULL, NULL, NULL, NULL);
	return ex;
}

/*!
 * \brief Call a function for each zone being in the journal DB.
 *
 * \param db    Journal database.
 * \param cb    Callback to be called for each zone-name found.
 * \param ctx   Arbitrary context to be passed to the callback.
 *
 * \return An error code from either journal operations or from the callback.
 */
int journals_walk(knot_lmdb_db_t *db, journals_walk_cb_t cb, void *ctx);
