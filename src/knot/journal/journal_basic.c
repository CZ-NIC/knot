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

static void fix_endian(void *data, size_t data_size, bool in)
{
	uint8_t tmp[data_size];
	memcpy(tmp, data, data_size);
	switch (data_size) {
	case sizeof(uint16_t):
		*(uint16_t *)data = in ? be16toh(*(uint16_t *)tmp) : htobe16(*(uint16_t *)tmp);
		break;
	case sizeof(uint32_t):
		*(uint32_t *)data = in ? be32toh(*(uint32_t *)tmp) : htobe32(*(uint32_t *)tmp);
		break;
	case sizeof(uint64_t):
		*(uint64_t *)data = in ? be64toh(*(uint64_t *)tmp) : htobe64(*(uint64_t *)tmp);
		break;
	default:
		assert(0);
	}
}

static MDB_val metadata_key(const knot_dname_t *zone, const char *metadata)
{
	if (zone == NULL) {
		return knot_lmdb_make_key("IS", (uint32_t)0, metadata);
	} else {
		return knot_lmdb_make_key("NIS", zone, (uint32_t)0, metadata);
	}
}

static bool get_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const char *metadata)
{
	MDB_val key = metadata_key(zone, metadata);
	bool ret = knot_lmdb_find(txn, &key, KNOT_LMDB_EXACT);
	free(key.mv_data);
	return ret;
}

static bool get_metadata_numeric(knot_lmdb_txn_t *txn, const knot_dname_t *zone,
                                 const char *metadata, void *result, size_t result_size)
{
	if (get_metadata(txn, zone, metadata)) {
		if (txn->cur_val.mv_size == result_size) {
			memcpy(result, txn->cur_val.mv_data, result_size);
			fix_endian(result, result_size, true);
			return true;
		} else {
			txn->ret = KNOT_EMALF;
		}
	}
	return false;
}

bool get_metadata32(knot_lmdb_txn_t *txn, const knot_dname_t *zone,
                    const char *metadata, uint32_t *result)
{
	return get_metadata_numeric(txn, zone, metadata, result, sizeof(*result));
}

bool get_metadata64(knot_lmdb_txn_t *txn, const knot_dname_t *zone,
                    const char *metadata, uint64_t *result)
{
	return get_metadata_numeric(txn, zone, metadata, result, sizeof(*result));
}

void set_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const char *metadata,
                  const void *valp, size_t val_size, bool numeric)
{
	MDB_val key = metadata_key(zone, metadata);
	MDB_val val = { val_size, NULL };
	knot_lmdb_insert(txn, &key, &val);
	if (txn->ret == KNOT_EOK) {
		memcpy(val.mv_data, valp, val_size);
		if (numeric) {
			fix_endian(val.mv_data, val_size, false);
		}
	}
	free(key.mv_data);
}

void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter)
{
	uint64_t occupied_now = knot_lmdb_usage(txn), occupied_last = 0, lis_occupied = 0;
	(void)get_metadata64(txn, NULL, "last_total_occupied", &occupied_last);
	knot_dname_t *last_inserter = get_metadata(txn, NULL, "last_inserter_zone") ?
	                              knot_dname_copy(txn->cur_val.mv_data, NULL) : NULL;
	if (occupied_now == occupied_last || last_inserter == NULL) {
		goto update_inserter;
	}
	(void)get_metadata64(txn, last_inserter, "occupied", &lis_occupied);
	if (lis_occupied + occupied_now > occupied_last) {
		lis_occupied += occupied_now;
		lis_occupied -= occupied_last;
	} else {
		lis_occupied = 0;
	}
	set_metadata(txn, last_inserter, "occupied", &lis_occupied, sizeof(lis_occupied), true);

update_inserter:
	if (last_inserter == NULL || knot_dname_cmp(last_inserter, new_inserter) != 0) {
		set_metadata(txn, NULL, "last_inserter_zone", new_inserter, knot_dname_size(new_inserter), false);
	}
	free(last_inserter);
	set_metadata(txn, NULL, "last_total_occupied", &occupied_now, sizeof(occupied_now), true);
}
