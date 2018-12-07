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

#include "knot/journal/journal_read.h"

#include "knot/journal/knot_lmdb.h"

#include "contrib/wire_ctx.h"
#include "knot/journal/serialization.h"
#include "libknot/error.h"

#include <stdlib.h>

struct journal_read {
	knot_lmdb_txn_t txn;
	MDB_val key_prefix;
	const knot_dname_t *zone;
	wire_ctx_t wire;
};

int journal_read_begin(journal_t *j, journal_changeset_id_t from, journal_read_t **ctx)
{
	journal_read_t *newctx = calloc(1, sizeof(*newctx));
	if (newctx == NULL) {
		return KNOT_ENOMEM;
	}
	newctx->key_prefix = journal_changeset_id_to_key(from, j->zone);
	if (newctx->key_prefix.mv_data == NULL) {
		free(newctx);
		return KNOT_ENOMEM;
	}

	knot_lmdb_begin(&j->db, &newctx->txn, false);
	knot_lmdb_find(&newctx->txn, &newctx->key_prefix, KNOT_LMDB_GEQ);

	if (newctx->txn.ret != KNOT_EOK) {
		journal_read_end(newctx);
	} else {
		newctx->zone = j->zone;
		newctx->wire = wire_ctx_init(newctx->txn.cur_val.mv_data, newctx->txn.cur_val.mv_size);
		*ctx = newctx;
	}

	return newctx->txn.ret;
}

void journal_read_end(journal_read_t *ctx)
{
	free(ctx->key_prefix.mv_data);
	knot_lmdb_abort(&ctx->txn);
	free(ctx);
}

static void make_data_available(journal_read_t *ctx)
{
	if (wire_ctx_available(&ctx->wire) == 0) {
		if (!knot_lmdb_next(&ctx->txn)) {
			return false;
		}
		if (!knot_lmdb_is_prefix_of(&ctx->key_prefix, &ctx->txn.cur_key)) {
			return false;
		}
		ctx->wire = wire_ctx_init_const(ctx->txn.cur_val.mv_data, ctx->txn.cur_val.mv_size);
		wire_ctx_skip(&ctx->wire, JOURNAL_HEADER_SIZE);
	}
	return true;
}

// thoughts for next design of journal serialization:
// - one TTL per rrset
// - endian
// - optionally storing whole rdataset at once?

int journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rrset)
{
	knot_rdataset_clear(&rrset->rrs, NULL);
	memset(rrset, 0, sizeof(*rrset));
	if (!make_data_available(ctx)) {
		return JOURNAL_READ_DONE;
	}
	rrset->owner = ctx->wire.position;
	wire_ctx_skip(&ctx->wire, knot_dname_size(rrset->owner));
	rrset->type = wire_ctx_read_u16(&ctx->wire);
	rrset->rclass = wire_ctx_read_u16(&ctx->wire);
	uint16_t rrs_count = wire_ctx_read_u16(&ctx->wire);
	if (ctx->wire.error != KNOT_EOK) {
		return KNOT_EMALF;
	}
	for (int i = 0; i < rrs_count; i++) {
		if (!make_data_available(ctx)) {
			return KNOT_EFEWDATA;
		}
		// TODO think of how to export serialized rr directly to knot_rdataset_add
		// focus on: even address aligning
		uint32_t ttl = wire_ctx_read_u32(&ctx->wire);
		if (i == 0) {
			rrset->ttl = ttl;
		}
		uint16_t len = wire_ctx_read_u16(&ctx->wire);
		int ret = knot_rrset_add_rdata(rrset, ctx->wire.position, len, NULL);
		wire_ctx_skip(&ctx->wire, len);
		if (ret != KNOT_EOK || ctx->wire.error != KNOT_EOK) {
			knot_rdataset_clear(&rrset->rrs, NULL);
			return (ctx->wire.error == KNOT_EOK ? ret : KNOT_EMALF);
		}
	}
	return KNOT_EOK;
}

static int add_rr_to_contents(zone_contents_t *z, const knot_rrset_t *rrset)
{
	zone_node_t *n = NULL;
	return zone_contents_add_rr(z, rrset, &n);
	// Shall we ignore ETTL ?
}

int journal_read_changeset(journal_read_t *ctx, changeset_t *ch)
{
	int ret = KNOT_EOK;
	zone_contents_t *tree = zone_contents_new(ctx->zone);
	knot_rrset_t *soa = calloc(1, sizeof(*soa)), rr = { 0 };
	if (tree == NULL || soa == NULL) {
		ret = KNOT_ENOMEM;
		goto fail;
	}
	memset(ch, 0, sizeof(*ch));

	ret = journal_read_rrset(ctx, soa);
	while (ret == KNOT_EOK) {
		ret = journal_read_rrset(ctx, &rr);
		if (ret != KNOT_EOK) { // especially, ret might be JOURNAL_READ_DONE
			break;
		}
		if (rr.type == KNOT_RRTYPE_SOA) {
			ch->soa_from = soa;
			ch->remove = tree;
			soa = malloc(sizeof(*soa));
			tree = zone_contents_new(ctx->zone);
			if (tree == NULL || soa == NULL) {
				ret = KNOT_ENOMEM;
				goto fail;
			}
			*soa = rr; // note this tricky assignment
			memset(rr, 0, sizeof(*rr));
		} else {
			ret = add_rr_to_contents(tree, &rr);
		}
	}

	if (ret == JOURNAL_READ_DONE) {
		ch->soa_to = soa;
		ch->add = tree;
		ret = KNOT_EOK;
	} else {
fail:
		knot_rdataset_clear(&rr.rrs, NULL);
		knot_rrset_free(soa, NULL);
		changeset_clear(ch);
		zone_contents_deep_free(tree);
	}

	return ret;
}

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch)
{
	MDB_val chunk = { 0, malloc(JOURNAL_CHUNK_MAX) };
	serialize_ctx_t *ser = serialize_init(ch);
	if (chunk.mv_data == NULL || ser == NULL) {
		txn->ret = KNOT_ENOMEM;
	}

	uint32_t i = 0;
	while (serialize_unfinished(ser) && txn->ret == KNOT_EOK) {
		journal_make_header(chunk.mv_data, ch);
		serialize_prepare(ser, JOURNAL_CHUNK_MAX - JOURNAL_HEADER_SIZE, &chunk.mv_size);
		serialize_chunk(ser, chunk.mv_data + JOURNAL_HEADER_SIZE, chunk.mv_size);
		chunk.mv_size += JOURNAL_HEADER_SIZE;

		MDB_val key = journal_changeset_to_chunk_key(ch, i);
		if (key.mv_data == NULL) {
			txn->ret = KNOT_ENOMEM;
		}

		knot_lmdb_insert(txn, &key, &chunk);
		free(key.mv_data);
		i++;
	}
	serialize_deinit(ser);
	free(chunk.mv_data);
	// return value is in the txn
}

