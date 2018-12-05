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
#include "knot/journal/journal_metadata.h"

/*!
 * \brief Serialize a changeset into chunks and write it into DB with no checks and metadata update.
 *
 * \param txn   Journal DB transaction.
 * \param ch    Changeset to be written.
 */
void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch);

/*!
 * \brief Merge all following changeset into one of journal changeset.
 *
 * \param j                    Zone journal.
 * \param txn                  Journal DB transaction.
 * \param merge_zij            True if we shall merge into zone-in-journal.
 * \param merge_serial         Serial-from of the changeset to be merged into (ignored if 'merge_zij').
 * \param original_serial_to   Output: previous serial-to of the merged changeset before merge.
 *
 * \note The error code will be in thx->ret.
 */
void journal_merge(zone_journal_t j, knot_lmdb_txn_t *txn, bool merge_zij,
                   uint32_t merge_serial, uint32_t *original_serial_to);

/*!
 * \brief Delete soem journal changeset in attept to fulfill usage quotas.
 *
 * \param txn              Journal DB transaction.
 * \param from             Serial-from of the first cangeset to be deleted.
 * \param zone             Zone name.
 * \param tofree_size      Amount of data (in bytes) to be at least deleted.
 * \param tofree_count     Number of changesets to be at least deleted.
 * \param stop_at_serial   Must not delete the changeset with this serial-from.
 * \param freed_size       Output: amount of data really deleted.
 * \param freed_count      Output: number of changesets really freed.
 * \param stopped_at       Output: serial-to of the last deleted changeset.
 *
 * \return True if something was deleted (not necessarily fulfilling tofree_*).
 */
bool journal_delete(knot_lmdb_txn_t *txn, uint32_t from, const knot_dname_t *zone,
                    size_t tofree_size, size_t tofree_count, uint32_t stop_at_serial,
                    size_t *freed_size, size_t *freed_count, uint32_t *stopped_at);

/*!
 * \brief Perform a merge or zone flush in order to enable deleting more changesets.
 *
 * \param j     Zone journal.
 * \param txn   Journal DB transaction.
 * \param md    Jounral metadata.
 *
 * \note It might set txn->ret to KNOT_EBUSY to fail out from this operation and let the zone flush itself.
 */
void journal_try_flush(zone_journal_t j, knot_lmdb_txn_t *txn, journal_metadata_t *md);

/*!
 * \brief Perform delete/merge/flush operations to fulfill configured journal quotas.
 *
 * \param j           Zone journal.
 * \param txn         Journal DB transaction.
 * \param md          Journal metadata.
 * \param max_usage   Configured maximum usage (in bytes) of journal DB by this zone.
 * \param max_count   Configured maximum number of changesets.
 */
void journal_fix_occupation(zone_journal_t j, knot_lmdb_txn_t *txn, journal_metadata_t *md,
			    int64_t max_usage, ssize_t max_count);

/*!
 * \brief Store zone-in-journal into the journal, update metadata.
 *
 * \param j    Zone journal.
 * \param ch   Changeset containing zone-in-journal.
 *
 * \return KNOT_E*
 */
int journal_insert_zone(zone_journal_t j, const changeset_t *ch);

/*!
 * \brief Store changeset into journal, fulfilling quotas and updating metadata.
 *
 * \param j    Zone journal.
 * \param ch   Changeset to be stored.
 *
 * \return KNOT_E*
 */
int journal_insert(zone_journal_t j, const changeset_t *ch);
