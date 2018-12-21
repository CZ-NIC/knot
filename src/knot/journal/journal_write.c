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

#include "contrib/macros.h"
#include "knot/journal/journal_metadata.h"
#include "knot/journal/journal_read.h"
#include "knot/journal/serialization.h"
#include "libknot/error.h"

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch)
{
	MDB_val chunk;
	serialize_ctx_t *ser = serialize_init(ch);
	if (ser == NULL) {
		txn->ret = KNOT_ENOMEM;
	}
	uint32_t i = 0;
	while (serialize_unfinished(ser) && txn->ret == KNOT_EOK) {
		serialize_prepare(ser, JOURNAL_CHUNK_MAX - JOURNAL_HEADER_SIZE, &chunk.mv_size);
		chunk.mv_size += JOURNAL_HEADER_SIZE;
		chunk.mv_data = NULL;
		MDB_val key = journal_changeset_to_chunk_key(ch, i);
		knot_lmdb_insert(txn, &key, &chunk);
		if (txn->ret == KNOT_EOK) {
			journal_make_header(chunk.mv_data, ch);
			serialize_chunk(ser, chunk.mv_data + JOURNAL_HEADER_SIZE, chunk.mv_size - JOURNAL_HEADER_SIZE);
		}
		free(key.mv_data);
		i++;
	}
	serialize_deinit(ser);
	// return value is in the txn
}

void journal_merge(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_changeset_id_t into)
{
	changeset_t merge;
	journal_read_t *read = NULL;
	bool in_remove_section = false;
	knot_rrset_t rr = { 0 };
	txn->ret = journal_read_begin(j, into, &read);
	if (txn->ret != KNOT_EOK) {
		return;
	}
	journal_read_changeset(read, &merge);
	while (txn->ret == KNOT_EOK && journal_read_rrset(read, &rr, true)) {
		if (rr.type == KNOT_RRTYPE_SOA &&
		    knot_dname_cmp(rr.owner, j->zone) == 0) {
			in_remove_section = !in_remove_section;
		}
		txn->ret = in_remove_section ?
			changeset_add_removal(&merge, &rr, CHANGESET_CHECK) :
			changeset_add_addition(&merge, &rr, CHANGESET_CHECK);
		journal_read_clear_rrset(&rr);
	}
	txn->ret = journal_read_get_error(read, txn->ret);
	journal_read_end(read);
	journal_write_changeset(txn, &merge);
	//knot_rrset_clear(&rr, NULL);
	journal_read_clear_changeset(&merge);
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
	free(prefix.mv_data);
	return (*freed > 0);
}

bool journal_delete(knot_lmdb_txn_t *txn, journal_changeset_id_t from, const knot_dname_t *zone,
                    size_t tofree_size, size_t tofree_count, uint32_t stop_at_serial,
                    size_t *freed_size, size_t *freed_count, uint32_t *stopped_at)
{
	*freed_size = 0;
	*freed_count = 0;
	size_t freed_now;
	while ((from.zone_in_journal || from.serial != stop_at_serial) &&
	       delete_one(txn, from, zone, &freed_now, stopped_at) &&
	       (*freed_size += freed_now, ++(*freed_count), 1) &&
	       (*freed_size < tofree_size || *freed_count < tofree_count)) {
		from.serial = *stopped_at;
		from.zone_in_journal = false;
	}
	return (*freed_count > 0);
}

void journal_try_flush(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_metadata_t *md)
{
	journal_changeset_id_t id = { true, 0 };
	bool flush = journal_allow_flush(j);
	if (journal_have_zone_in_j(txn, j->zone, NULL)) {
		journal_merge(j, txn, id);
		if (!flush) {
			journal_metadata_after_merge(md, id, md->serial_to);
		}
	} else if (!flush) {
		id.zone_in_journal = false;
		id.serial = ((md->flags & JOURNAL_MERGED_SERIAL_VALID) ? md->merged_serial : md->first_serial);
		journal_merge(j, txn, id);
		journal_metadata_after_merge(md, id, md->serial_to);
	}

	if (flush) {
		// delete merged serial if (very unlikely) exists
		if ((md->flags & JOURNAL_MERGED_SERIAL_VALID)) {
			journal_changeset_id_t merged = { false, md->merged_serial };
			size_t unused;
			(void)delete_one(txn, merged, j->zone, &unused, (uint32_t *)&unused);
			md->flags &= ~JOURNAL_MERGED_SERIAL_VALID;
		}

		// commit partial job and ask zone to flush itself
		journal_store_metadata(txn, j->zone, md);
		knot_lmdb_commit(txn);
		if (txn->ret == KNOT_EOK) {
			txn->ret = KNOT_EBUSY;
		}
	}
}

void journal_fix_occupation(zone_journal_t *j, knot_lmdb_txn_t *txn, journal_metadata_t *md,
			    int64_t max_usage, ssize_t max_count)
{
	uint64_t occupied = journal_get_occupied(txn, j->zone), freed;
	int64_t need_tofree = (int64_t)occupied - max_usage;
	size_t count = md->changeset_count, removed;
	ssize_t need_todel = (ssize_t)count - max_count;
	journal_changeset_id_t from = { false, md->first_serial };

	while ((need_tofree > 0 || need_todel > 0) && txn->ret == KNOT_EOK) {
		freed = 0;
		removed = 0;
		journal_delete(txn, from, j->zone, MAX(need_tofree, 0), MAX(need_todel, 0), md->flushed_upto, &freed, &removed, &from.serial);
		if (freed == 0) {
			if (md->flushed_upto != md->serial_to) {
				journal_try_flush(j, txn, md);
			} else {
				break;
			}
		} else {
			journal_metadata_after_delete(md, from.serial, removed);
			need_tofree -= freed;
			need_todel -= removed;
		}
	}
}

int journal_insert_zone(zone_journal_t *j, const changeset_t *ch)
{
	if (ch->remove != NULL) {
		return KNOT_EINVAL;
	}
	int ret = knot_lmdb_open(j->db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(j->db, &txn, true);

	update_last_inserter(&txn, j->zone);
	MDB_val prefix = { knot_dname_size(j->zone), (void *)j->zone };
	knot_lmdb_del_prefix(&txn, &prefix);

	journal_write_changeset(&txn, ch);

	journal_metadata_t md = { 0 };
	md.flags = JOURNAL_SERIAL_TO_VALID;
	md.serial_to = changeset_to(ch);
	md.first_serial = md.serial_to;
	journal_store_metadata(&txn, j->zone, &md);

	knot_lmdb_commit(&txn);
	return txn.ret;
}

int journal_insert(zone_journal_t *j, const changeset_t *ch)
{
	size_t ch_size = changeset_serialized_size(ch);
	size_t max_usage = journal_conf_max_usage(j);
	if (ch_size >= max_usage) {
		return KNOT_ESPACE;
	}
	int ret = knot_lmdb_open(j->db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t txn = { 0 };
	journal_metadata_t md = { 0 };
	knot_lmdb_begin(j->db, &txn, true);
	journal_load_metadata(&txn, j->zone, &md);

	update_last_inserter(&txn, j->zone);
	journal_fix_occupation(j, &txn, &md, max_usage - ch_size, journal_conf_max_changesets(j) - 1);

	// avoid cycle
	journal_changeset_id_t conflict = { false, changeset_to(ch) };
	if (journal_contains(&txn, conflict, j->zone)) {
		journal_fix_occupation(j, &txn, &md, INT64_MAX, 1);
	}

	// avoid discontinuity
	if ((md.flags & JOURNAL_SERIAL_TO_VALID) && md.serial_to != changeset_from(ch)) {
		if (journal_have_zone_in_j(&txn, j->zone, NULL)) {
			return KNOT_ESEMCHECK;
		} else {
			MDB_val prefix = { knot_dname_size(j->zone), (void *)j->zone };
			knot_lmdb_del_prefix(&txn, &prefix);
			memset(&md, 0, sizeof(md));
		}
	}

	journal_write_changeset(&txn, ch);
	journal_metadata_after_insert(&md, changeset_from(ch), changeset_to(ch));

	journal_store_metadata(&txn, j->zone, &md);
	knot_lmdb_commit(&txn);
	return txn.ret;
}
