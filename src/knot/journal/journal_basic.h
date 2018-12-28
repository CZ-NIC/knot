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

#include "knot/conf/schema.h"
#include "knot/journal/knot_lmdb.h"
#include "knot/updates/changesets.h"
#include "libknot/dname.h"

typedef struct {
	knot_lmdb_db_t *db;
	const knot_dname_t *zone;
} zone_journal_t;

#define JOURNAL_CHUNK_MAX (70 * 1024)
#define JOURNAL_HEADER_SIZE (32)

inline static unsigned journal_env_flags(int journal_mode)
{
	return journal_mode == JOURNAL_MODE_ASYNC ? (MDB_WRITEMAP | MDB_MAPASYNC) : 0;
}

MDB_val journal_changeset_id_to_key(bool zone_in_journal, uint32_t serial, const knot_dname_t *zone);

MDB_val journal_changeset_to_chunk_key(const changeset_t *ch, uint32_t chunk_id);

void journal_make_header(void *chunk, const changeset_t *ch);

uint32_t journal_next_serial(const MDB_val *chunk);

bool journal_serial_to(knot_lmdb_txn_t *txn, bool zij, uint32_t serial,
                       const knot_dname_t *zone, uint32_t *serial_to);

inline static bool journal_contains(knot_lmdb_txn_t *txn, bool zone, uint32_t serial, const knot_dname_t *zone_name)
{
	return journal_serial_to(txn, zone, serial, zone_name, NULL);
}

void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter);

bool journal_allow_flush(zone_journal_t j);

size_t journal_conf_max_usage(zone_journal_t j);

size_t journal_conf_max_changesets(zone_journal_t j);
