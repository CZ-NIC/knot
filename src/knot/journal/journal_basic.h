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

inline static MDB_val journal_changeset_id_to_key(journal_changeset_id_t id, const knot_dname_t *zone)
{
	if (id.zone_in_journal) {
		return knot_lmdb_make_key("NIS", zone, (uint32_t)0, "bootstrap");
	} else {
		return knot_lmdb_make_key("NII", zone, (uint32_t)0, id.serial);
	}
}

inline static MDB_val journal_changeset_to_chunk_key(const changeset_t *ch, uint32_t chunk_id)
{
	if (ch->soa_from == NULL) {
		return knot_lmdb_make_key("NISI", ch->add->apex->owner, (uint32_t)0, "bootstrap", chunk_id);
	} else {
		return knot_lmdb_make_key("NIII", ch->add->apex->owner, (uint32_t)0, changeset_from(ch), chunk_id);
	}
}

inline static void journal_make_header(void *chunk, const changeset_t *ch)
{
	knot_lmdb_make_key_part(chunk, JOURNAL_HEADER_SIZE, "IILLL", changeset_from(ch),
	                        (uint32_t)0 /* we no longer care for # of chunks */,
	                        (uint64_t)0, (uint64_t)0, (uint64_t)0);
}

inline static uint32_t journal_next_serial(const MDB_val *chunk)
{
	return be32toh(*(uint32_t *)chunk->mv_data);
}
