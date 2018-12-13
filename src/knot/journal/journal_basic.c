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

#include "knot/journal/journal_basic.h"

#include "libknot/error.h"

MDB_val journal_changeset_id_to_key(journal_changeset_id_t id, const knot_dname_t *zone)
{
	if (id.zone_in_journal) {
		return knot_lmdb_make_key("NIS", zone, (uint32_t)0, "bootstrap");
	} else {
		return knot_lmdb_make_key("NII", zone, (uint32_t)0, id.serial);
	}
}

MDB_val journal_changeset_to_chunk_key(const changeset_t *ch, uint32_t chunk_id)
{
	if (ch->soa_from == NULL) {
		return knot_lmdb_make_key("NISI", ch->add->apex->owner, (uint32_t)0, "bootstrap", chunk_id);
	} else {
		return knot_lmdb_make_key("NIII", ch->add->apex->owner, (uint32_t)0, changeset_from(ch), chunk_id);
	}
}

void journal_make_header(void *chunk, const changeset_t *ch)
{
	knot_lmdb_make_key_part(chunk, JOURNAL_HEADER_SIZE, "IILLL", changeset_from(ch),
	                        (uint32_t)0 /* we no longer care for # of chunks */,
	                        (uint64_t)0, (uint64_t)0, (uint64_t)0);
}

uint32_t journal_next_serial(const MDB_val *chunk)
{
	return be32toh(*(uint32_t *)chunk->mv_data);
}

bool journal_serial_to(knot_lmdb_txn_t *txn, journal_changeset_id_t from, const knot_dname_t *zone,
                       uint32_t *serial_to)
{
	MDB_val key = journal_changeset_id_to_key(from, zone);
	bool found = knot_lmdb_find(txn, &key, KNOT_LMDB_GEQ);
	if (found) {
		*serial_to = journal_next_serial(&txn->cur_val);
	}
	free(key.mv_data);
	return found;
}

bool journal_have_zone_in_j(knot_lmdb_txn_t *txn, const knot_dname_t *zone, uint32_t *serial_to)
{
	journal_changeset_id_t id = { true, 0 };
	MDB_val key = journal_changeset_id_to_key(id, zone);
	bool found = knot_lmdb_find(txn, &key, KNOT_LMDB_GEQ);
	if (found && serial_to != NULL) {
		*serial_to = journal_next_serial(&txn->cur_val);
	}
	free(key.mv_data);
	return found;
}
