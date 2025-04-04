/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

bool journal_correct_prefix(MDB_val *prefix, MDB_val *found_key)
{
	return knot_lmdb_is_prefix_of2(prefix, found_key, sizeof(uint32_t) /* chunk_id */);
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

void journal_make_header(void *chunk, uint32_t ch_serial_to, uint64_t now)
{
	knot_lmdb_make_key_part(chunk, JOURNAL_HEADER_SIZE, "IILLL", ch_serial_to,
	                        (uint32_t)0 /* we no longer care for # of chunks */,
	                        (uint64_t)0, now, (uint64_t)0);
}

uint32_t journal_next_serial(const MDB_val *chunk)
{
	return knot_wire_read_u32(chunk->mv_data);
}

uint64_t journal_ch_timestamp(const MDB_val *chunk)
{
	return knot_wire_read_u64(chunk->mv_data + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint64_t));
}

bool journal_serial_to(knot_lmdb_txn_t *txn, bool zij, uint32_t serial,
                       const knot_dname_t *zone, uint32_t *serial_to)
{
	MDB_val key = journal_make_chunk_key(zone, serial, zij, 0);
	bool found = knot_lmdb_find(txn, &key, KNOT_LMDB_EXACT);
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
