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

#include "knot/journal/journal_write.h"

#include "knot/journal/journal_read.h"
#include "libknot/error.h"

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

static uint32_t metadata32(knot_lmdb_txn_t *txn)
{
	if (txn->cur_val.mv_size == sizeof(uint32_t)) {
		return be32toh(*(uint32_t *)txn->cur_val.mv_data);
	} else {
		if (txn->ret == KNOT_EOK) {
			txn->ret = KNOT_EMALF;
		}
		return 0;
	}
}

static uint64_t metadata64(knot_lmdb_txn_t *txn)
{
	if (txn->cur_val.mv_size == sizeof(uint64_t)) {
		return be64toh(*(uint64_t *)txn->cur_val.mv_data);
	} else {
		if (txn->ret == KNOT_EOK) {
			txn->ret = KNOT_EMALF;
		}
		return 0;
	}
}

static void set_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const char *metadata,
                         const void *valp, size_t val_size)
{
	MDB_val key = metadata_key(zone, metadata);
	MDB_val val = { val_size, (void *)valp };
	knot_lmdb_insert(txn, &key, &val);
	free(key.mv_data);
}

static void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter)
{
	uint64_t occupied_now = knot_lmdb_usage(txn);
	uint64_t occupied_last = get_metadata(txn, NULL, "last_total_occupied") ?
	                         metadata64(txn) : 0;
	knot_dname_t *last_inserter = get_metadata(txn, NULL, "last_inserter_zone") ?
	                              knot_dname_copy(txn->cur_val.mv_data, NULL) : NULL;
	if (occupied_now == occupied_last || last_inserter == NULL) {
		goto update_inserter;
	}
	uint64_t lis_occupied = get_metadata(txn, last_inserter, "occupied") ?
	                        metadata64(txn) : 0;
	if (lis_occupied + occupied_now > occupied_last) {
		lis_occupied += occupied_now;
		lis_occupied -= occupied_last;
		lis_occupied = htobe64(lis_occupied);
	} else {
		lis_occupied = 0;
	}
	set_metadata(txn, last_inserter, "occupied", &lis_occupied, sizeof(lis_occupied));

update_inserter:
	if (last_inserter == NULL || knot_dname_cmp(last_inserter, new_inserter) != 0) {
		set_metadata(txn, NULL, "last_inserter_zone", new_inserter, knot_dname_size(new_inserter));
	}
	free(last_inserter);
	occupied_now = htobe64(occupied_now);
	set_metadata(txn, NULL, "last_total_occupied", &occupied_now, sizeof(occupied_now));
}

static bool delete_one(knot_lmdb_txn_t *txn, journal_changeset_id_t from, const knot_dname_t *zone,
                       size_t *freed, uint32_t *next_serial)
{
	*freed = 0;
	MDB_val prefix = journal_changeset_id_to_key(from, zone);
	knot_lmdb_foreach(txn, &prefix) {
		*freed += txn->cur_val.mv_size;
		*next_serial = journal_next_serial(&txn->cur_val);
		knot_lmdb_del_cur(txn);
	}
	return (*freed > 0);
}
