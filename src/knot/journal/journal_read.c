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
#include "libknot/error.h"

#include <stdlib.h>

// FIXME move
MDB_val journal_changeset_id_to_key(const journal_changeset_id_t *id, const knot_dname_t *zone)
{
	if (id->zone_in_journal) {
		return knot_lmdb_make_key("NIS", zone, (uint32_t)0, "bootstrap");
	} else {
		return knot_lmdb_make_key("NII", zone, (uint32_t)0, id->serial);
	}
}

struct journal_read {
	knot_lmdb_txn_t txn;
	MDB_val key_prefix;
	const knot_dname_t *zone;
	wire_ctx_t wire;
};

int journal_read_begin(journal_t *j, const journal_changeset_id_t *from, journal_read_t **ctx)
{
	journal_read_t *newctx = calloc(1, sizeof(*newctx));
	if (newctx == NULL) {
		return KNOT_ENOMEM;
	}

	knot_lmdb_begin(&j->db, &newctx->txn, false);
	newctx->key_prefix = journal_changeset_id_to_key(from, j->zone);
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

#define make_data_available(ctx) \
	if (wire_ctx_available(&ctx->wire) == 0) { \
		if (!knot_lmdb_next(&ctx->txn)) { \
			return JOURNAL_READ_DONE; \
		} \
		wire_ctx_init(ctx->txn.cur_val.mv_data, ctx->txn.cur_val.mv_size); \
	}


int journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rrset)
{
	memset(rrset, 0, sizeof(*rrset));
	make_data_available(ctx);
	rrset->owner = ctx->wire.position;
	wire_ctx_skip(&ctx->wire, knot_dname_size(rrset->owner));
	rrset->type = wire_ctx_read_u16(&ctx->wire);
	rrset->rclass = wire_ctx_read_u16(&ctx->wire);
	uint16_t rrs_count = wire_ctx_read_u16(&ctx->wire);
	if (ctx->wire.error != KNOT_EOK) {
		return KNOT_EMALF;
	}
	for (int i = 0; i < rrs_count; i++) {
		make_data_available(ctx);
		// ... copy POINTER TO rdata into rrset->rrs
	}

	return KNOT_EOK;
}

int journal_read_changeset(journal_read_t *ctx, changeset_t *ch)
{
	return KNOT_EOK;
}

