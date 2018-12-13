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

#include "knot/journal/journal_metadata.h"

#include "libknot/error.h"

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

static bool del_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const char *metadata)
{
	MDB_val key = metadata_key(zone, metadata);
	if (key.mv_data != NULL) {
		knot_lmdb_del_prefix(txn, &key);
		free(key.mv_data);
	}
	return (key.mv_data != NULL);
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
	if (new_inserter == NULL) {
		del_metadata(txn, NULL, "last_inserter_zone");
	} else if (last_inserter == NULL || knot_dname_cmp(last_inserter, new_inserter) != 0) {
		set_metadata(txn, NULL, "last_inserter_zone", new_inserter, knot_dname_size(new_inserter), false);
	}
	free(last_inserter);
	set_metadata(txn, NULL, "last_total_occupied", &occupied_now, sizeof(occupied_now), true);
}

static int first_digit(char * of)
{
	unsigned maj, min;
	return sscanf(of, "%u.%u", &maj, &min) == 2 ? maj : -1;
}

void journal_load_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, journal_metadata_t *md)
{
	memset(md, 0, sizeof(*md));
	(void)get_metadata(txn, NULL, "version");
	switch (first_digit(txn->cur_val.mv_data)) {
	case 3:
		// TODO warning about downgrade
		// FALLTHROUGH
	case 1:
		// still supported
		// FALLTHROUGH
	case 2:
		// normal operation
		break;
	default:
		txn->ret = KNOT_ENOTSUP;
		return;
	}
	md->_new_zone = !get_metadata32(txn, zone, "flags", &md->flags);
	(void)get_metadata32(txn, zone, "first_serial",    &md->first_serial);
	//(void)get_metadata32(txn, zone, "last_serial",     &md->last_serial);
	(void)get_metadata32(txn, zone, "last_serial_to",  &md->serial_to);
	(void)get_metadata32(txn, zone, "merged_serial",   &md->merged_serial);
	(void)get_metadata32(txn, zone, "changeset_count", &md->changeset_count);
	if (!get_metadata32(txn, zone, "flushed_upto", &md->flushed_upto)) {
		// importing from version 1.0
		if ((md->flags & LAST_FLUSHED_VALID)) {
			journal_changeset_id_t last_flushed = { false, 0 };
			if (!get_metadata32(txn, zone, "last_flushed", &last_flushed.serial) ||
			    !journal_serial_to(txn, last_flushed, zone, &md->flushed_upto)) {
				txn->ret = KNOT_EMALF;
			} else {
				md->flags &= ~LAST_FLUSHED_VALID;
			}
		} else {
			md->flushed_upto = md->first_serial;
		}
	}

}

void journal_store_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const journal_metadata_t *md)
{
	set_metadata(txn, zone, "first_serial",    &md->first_serial,    sizeof(md->first_serial),    true);
	//set_metadata(txn, zone, "last_serial",     &md->last_serial,     sizeof(md->last_serial),     true);
	set_metadata(txn, zone, "last_serial_to",  &md->serial_to,       sizeof(md->serial_to),       true);
	set_metadata(txn, zone, "flushed_upto",    &md->flushed_upto,    sizeof(md->flushed_upto),    true);
	set_metadata(txn, zone, "merged_serial",   &md->merged_serial,   sizeof(md->merged_serial),   true);
	set_metadata(txn, zone, "changeset_count", &md->changeset_count, sizeof(md->changeset_count), true);
	set_metadata(txn, zone, "flags",           &md->flags,           sizeof(md->flags),           true);
	set_metadata(txn, NULL, "version", "2.0", 4, false);
	if (md->_new_zone) {
		uint64_t journal_count;
		(void)get_metadata64(txn, NULL, "journal_count", &journal_count);
		++journal_count;
		set_metadata(txn, NULL, "journal_count", &journal_count, sizeof(journal_count), true);
	}
}

void journal_metadata_after_delete(journal_metadata_t *md, uint32_t deleted_upto,
                                   size_t deleted_count)
{
	if (deleted_count == 0) {
		return;
	}
	assert((md->flags & SERIAL_TO_VALID));
	assert(md->first_serial != md->flushed_upto); // don't allow deleting in unflushed zone
	if (deleted_upto == md->serial_to) {
		assert(md->flushed_upto == md->serial_to);
		md->flags &= ~SERIAL_TO_VALID;
	} else {
		md->first_serial = deleted_upto;
	}
	md->changeset_count -= deleted_count;
}

void journal_metadata_after_merge(journal_metadata_t *md, uint32_t merged_serial,
                                  uint32_t merged_serial_to)
{
	if ((md->flags & MERGED_SERIAL_VALID)) {
		assert(merged_serial == md->merged_serial);
	} else {
		md->merged_serial = merged_serial;
		md->flags |= MERGED_SERIAL_VALID;
	}
	md->flushed_upto = merged_serial_to;
}

void journal_metadata_after_insert(journal_metadata_t *md, uint32_t serial, uint32_t serial_to)
{
	if ((md->flags & SERIAL_TO_VALID)) {
		assert(serial == md->serial_to);
	} else {
		md->first_serial = serial;
		md->flags |= SERIAL_TO_VALID;
	}
	md->serial_to = serial_to;
}

void journal_scrape(zone_journal_t *j)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(&j->db, &txn, true);
	update_last_inserter(&txn, NULL);
	MDB_val prefix = { knot_dname_size(j->zone), j->zone };
	knot_lmdb_del_prefix(&txn, &prefix);
	knot_lmdb_commit(&txn);
}
