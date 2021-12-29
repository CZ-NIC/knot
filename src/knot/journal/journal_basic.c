/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/journal/journal_metadata.h"
#include "libknot/error.h"

MDB_val journal_changeset_id_to_key(bool zone_in_journal, uint32_t serial, const knot_dname_t *zone)
{
	if (zone_in_journal) {
		return knot_lmdb_make_key("NIS", zone, (uint32_t)0, "bootstrap");
	} else {
		return knot_lmdb_make_key("NII", zone, (uint32_t)0, serial);
	}
}

MDB_val journal_make_chunk_key(const knot_dname_t *apex, uint32_t ch_from, bool zij, uint32_t chunk_id)
{
	if (zij) {
		return knot_lmdb_make_key("NISI", apex, (uint32_t)0, "bootstrap", chunk_id);
	} else {
		return knot_lmdb_make_key("NIII", apex, (uint32_t)0, ch_from, chunk_id);
	}
}

MDB_val journal_zone_prefix(const knot_dname_t *zone)
{
	return knot_lmdb_make_key("NI", zone, (uint32_t)0);
}

void journal_del_zone(knot_lmdb_txn_t *txn, const knot_dname_t *zone)
{
	assert(txn->is_rw);
	MDB_val prefix = journal_zone_prefix(zone);
	knot_lmdb_del_prefix(txn, &prefix);
	free(prefix.mv_data);
}

void journal_make_header(void *chunk, uint32_t ch_serial_to)
{
	knot_lmdb_make_key_part(chunk, JOURNAL_HEADER_SIZE, "IILLL", ch_serial_to,
	                        (uint32_t)0 /* we no longer care for # of chunks */,
	                        (uint64_t)0, (uint64_t)0, (uint64_t)0);
}

uint32_t journal_next_serial(const MDB_val *chunk)
{
	return knot_wire_read_u32(chunk->mv_data);
}

bool journal_serial_to(knot_lmdb_txn_t *txn, bool zij, uint32_t serial,
                       const knot_dname_t *zone, uint32_t *serial_to)
{
	MDB_val key = journal_changeset_id_to_key(zij, serial, zone);
	bool found = knot_lmdb_find_prefix(txn, &key);
	if (found && serial_to != NULL) {
		*serial_to = journal_next_serial(&txn->cur_val);
	}
	free(key.mv_data);
	return found;
}

bool journal_allow_flush(zone_journal_t j)
{
	conf_val_t val = conf_zone_get(j.conf, C_ZONEFILE_SYNC, j.zone);
	return conf_int(&val) >= 0;
}

size_t journal_conf_max_usage(zone_journal_t j)
{
	conf_val_t val = conf_zone_get(j.conf, C_JOURNAL_MAX_USAGE, j.zone);
	return conf_int(&val);
}

size_t journal_conf_max_changesets(zone_journal_t j)
{
	conf_val_t val = conf_zone_get(j.conf, C_JOURNAL_MAX_DEPTH, j.zone);
	return conf_int(&val);
}
