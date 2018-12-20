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

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch);

void journal_merge(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_changeset_id_t into);

bool journal_delete(knot_lmdb_txn_t *txn, journal_changeset_id_t from, const knot_dname_t *zone,
                    size_t tofree_size, size_t tofree_count, uint32_t stop_at_serial,
                    size_t *freed_size, size_t *freed_count, uint32_t *stopped_at);

void journal_try_flush(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_metadata_t *md);

void journal_fix_occupation(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_metadata_t *md,
			    int64_t max_usage, ssize_t max_count);

int journal_insert_zone(zone_journal_t *j, const changeset_t *ch);

int journal_insert(zone_journal_t *j, const changeset_t *ch);
