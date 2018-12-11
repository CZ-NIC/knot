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
#include "knot/journal/serialization.h"
#include "libknot/error.h"

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch)
{
	MDB_val chunk;
	serialize_ctx_t *ser = serialize_init(ch);
	if (ser == NULL) {
		txn->ret = KNOT_ENOMEM;
	}
	list_t chunk_ptrs;
	init_list(&chunk_ptrs);
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
			ptrlist_add(&chunk_ptrs, chunk.mv_data, NULL);
		}
		free(key.mv_data);
		i++;
	}

	// storing the number of chunks into each chunk is no longer needed
	// we just do it for backward compatibility (in case of Knot downgrade)
	// remove this code (whole chunk_ptrs) in the future
	ptrnode_t *chunkp;
	WALK_LIST(chunkp, chunk_ptrs) {
		((uint32_t *)chunkp->d)[1] = htobe32(i);
	}
	ptrlist_free(&chunk_ptrs, NULL);

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
	txn->ret = journal_read_changeset(read, &merge);
	while (txn->ret == KNOT_EOK) {
		txn->ret = journal_read_rrset(read, &rr);
		if (txn->ret != KNOT_EOK) {
			break;
		}
		if (rr.type == KNOT_RRTYPE_SOA &&
		    knot_dname_cmp(rr.owner, j->zone) == 0) {
			in_remove_section = !in_remove_section;
		}
		txn->ret = in_remove_section ?
			changeset_add_removal(&merge, &rr, CHANGESET_CHECK) :
			changeset_add_addition(&merge, &rr, CHANGESET_CHECK);
	}
	journal_read_end(read);
	txn->ret = (txn->ret == JOURNAL_READ_END_READ ? KNOT_EOK : txn->ret);
	journal_write_changeset(txn, &merge);
	knot_rrset_clear(&rr, NULL);
	changeset_clear(&merge);
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
	       *freed_size < tofree_size && *freed_count < tofree_count) {
		from.serial = *stopped_at;
		from.zone_in_journal = false;
	}
	return (*freed_count > 0);
}
