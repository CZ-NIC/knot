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

#include "knot/journal/knot_lmdb.h"
#include "knot/updates/changesets.h"
#include "libknot/dname.h"

typedef struct {
	bool zone_in_journal;
	uint32_t serial;
} journal_changeset_id_t;

typedef struct {
	knot_lmdb_db_t db;
	knot_dname_t *zone;
} zone_journal_t;

#define JOURNAL_CHUNK_MAX (70 * 1024)
#define JOURNAL_HEADER_SIZE (32)

MDB_val journal_changeset_id_to_key(journal_changeset_id_t id, const knot_dname_t *zone);

MDB_val journal_changeset_to_chunk_key(const changeset_t *ch, uint32_t chunk_id);

void journal_make_header(void *chunk, const changeset_t *ch);

uint32_t journal_next_serial(const MDB_val *chunk);

bool journal_serial_to(knot_lmdb_txn_t *txn, journal_changeset_id_t from, const knot_dname_t *zone,
                       uint32_t *serial_to);

void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter);

bool journal_have_zone_in_j(knot_lmdb_txn_t *txn, const knot_dname_t *zone, uint32_t *serial_to);
