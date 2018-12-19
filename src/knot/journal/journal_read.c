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

#include "knot/journal/journal_metadata.h"
#include "knot/journal/knot_lmdb.h"

#include "contrib/ucw/lists.h"
#include "contrib/wire_ctx.h"
#include "libknot/error.h"

#include <stdlib.h>

struct journal_read {
	knot_lmdb_txn_t txn;
	MDB_val key_prefix;
	const knot_dname_t *zone;
	wire_ctx_t wire;
};

static void update_ctx_wire(journal_read_t *ctx)
{
	ctx->wire = wire_ctx_init_const(ctx->txn.cur_val.mv_data, ctx->txn.cur_val.mv_size);
	wire_ctx_skip(&ctx->wire, JOURNAL_HEADER_SIZE);
}

static int go_next_changeset(journal_read_t *ctx, const knot_dname_t *zone, journal_changeset_id_t next_serial)
{
	ctx->key_prefix = journal_changeset_id_to_key(next_serial, zone);
	if (!knot_lmdb_find(&ctx->txn, &ctx->key_prefix, KNOT_LMDB_GEQ)) {
		return JOURNAL_READ_END_READ;
	}
	if (ctx->txn.ret != KNOT_EOK) {
		return ctx->txn.ret;
	}
	update_ctx_wire(ctx);
	return KNOT_EOK;
}

int journal_read_begin(zone_journal_t *j, journal_changeset_id_t from, journal_read_t **ctx)
{
	if (!knot_lmdb_exists(j->db)) {
		return KNOT_ENOENT;
	}

	journal_read_t *newctx = calloc(1, sizeof(*newctx));
	if (newctx == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = knot_lmdb_open(j->db);
	if (ret != KNOT_EOK) {
		return ret;
	}

	newctx->zone = j->zone;

	knot_lmdb_begin(j->db, &newctx->txn, false);

	ret = go_next_changeset(newctx, j->zone, from);
	if (ret == KNOT_EOK) {
		*ctx = newctx;
	} else {
		journal_read_end(newctx);
	}

	return ret == JOURNAL_READ_END_READ ? KNOT_ENOENT : ret;
}

void journal_read_end(journal_read_t *ctx)
{
	free(ctx->key_prefix.mv_data);
	knot_lmdb_abort(&ctx->txn);
	free(ctx);
}

static bool make_data_available(journal_read_t *ctx)
{
	if (wire_ctx_available(&ctx->wire) == 0) {
		if (!knot_lmdb_next(&ctx->txn)) {
			return false;
		}
		if (!knot_lmdb_is_prefix_of(&ctx->key_prefix, &ctx->txn.cur_key)) {
			return false;
		}
		update_ctx_wire(ctx);
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
	journal_changeset_id_t next_serial = { false, journal_next_serial(&ctx->txn.cur_val) };
	if (!make_data_available(ctx)) {
		int ret = go_next_changeset(ctx, ctx->zone, next_serial);
		return ret == KNOT_EOK ? JOURNAL_READ_END_CHANGESET : ret;
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
		goto finish;
	}
	memset(ch, 0, sizeof(*ch));

	ret = journal_read_rrset(ctx, soa);
	while (ret == KNOT_EOK) {
		ret = journal_read_rrset(ctx, &rr);
		if (ret != KNOT_EOK) { // especially, ret might be JOURNAL_READ_DONE
			break;
		}
		if (rr.type == KNOT_RRTYPE_SOA &&
		    knot_dname_cmp(rr.owner, ctx->zone) == 0) {
			ch->soa_from = soa;
			ch->remove = tree;
			soa = malloc(sizeof(*soa));
			tree = zone_contents_new(ctx->zone);
			if (tree == NULL || soa == NULL) {
				ret = KNOT_ENOMEM;
				goto finish;
			}
			*soa = rr; // note this tricky assignment
			memset(&rr, 0, sizeof(rr));
		} else {
			ret = add_rr_to_contents(tree, &rr);
		}
	}

finish:
	switch (ret) {
	case JOURNAL_READ_END_CHANGESET:
		ret = KNOT_EOK;
		// FALLTHROUGH
	case JOURNAL_READ_END_READ:
		ch->soa_to = soa;
		ch->add = tree;
		break;
	default:
		knot_rdataset_clear(&rr.rrs, NULL);
		knot_rrset_free(soa, NULL);
		changeset_clear(ch);
		zone_contents_deep_free(tree);
	}
	return ret;
}

void just_load_md(zone_journal_t *j, journal_metadata_t *md)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(j->db, &txn, false);
	journal_load_metadata(&txn, j->zone, md);
	knot_lmdb_abort(&txn);
}

// beware, this function does not operate in single txn!
int journal_walk(zone_journal_t *j, journal_walk_cb_t cb, void *ctx)
{
	int ret;
	if (!knot_lmdb_exists(j->db)) {
		ret = cb(true, NULL, ctx);
		if (ret == KNOT_EOK) {
			ret = cb(false, NULL, ctx);
		}
		return ret;
	}
	ret = knot_lmdb_open(j->db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	journal_metadata_t md = { 0 };
	journal_read_t *read = NULL;
	changeset_t ch;
	journal_changeset_id_t id = { false, 0 };
	bool at_least_one = false;
	just_load_md(j, &md);
	if (journal_have_zone_in_j(txn, j->zone, NULL)) {
		id.zone_in_journal = true;
		goto read_one_special;
	} else if ((md.flags & MERGED_SERIAL_VALID)) {
		id.serial = md.merged_serial;
read_one_special:
		ret = journal_read_begin(j, id, &read);
		if (ret == KNOT_EOK) {
			ret = journal_read_changeset(read, &ch);
		}
		if (ret == KNOT_EOK) {
			ret = cb(true, &ch, ctx);
		}
		changeset_clear(&ch);
		journal_read_end(read);
		read = NULL;
	} else {
		ret = cb(true, NULL, ctx);
	}

	if ((md.flags & SERIAL_TO_VALID) && md.first_serial != md.serial_to) {
		if (ret == KNOT_EOK || ret == JOURNAL_READ_END_READ) {
			id.zone_in_journal = false;
			id.serial = md.first_serial;
			ret = journal_read_begin(j, id, &read);
		}
		while (ret == KNOT_EOK) {
			ret = journal_read_changeset(read, &ch);
			if (ret == KNOT_EOK) {
				ret = cb(false, &ch, ctx);
				changeset_clear(&ch);
				at_least_one = true;
			}
		}
	}
	ret = (ret == JOURNAL_READ_END_READ ? KNOT_EOK : ret);
	journal_read_end(read);
	if (!at_least_one && ret == KNOT_EOK) {
		ret = cb(false, NULL, ctx);
	}
	return ret;
}

typedef struct {
	size_t observed_count;
	size_t observed_merged;
	uint32_t merged_serial;
	size_t observed_zij;
	uint32_t first_serial;
	bool first_serial_valid;
	uint32_t last_serial;
	bool last_serial_valid;
} check_ctx_t;

static int check_cb(bool special, const changeset_t *ch, void *vctx)
{
	check_ctx_t *ctx = vctx;
	if (special && ch != NULL) {
		if (ch->remove == NULL) {
			ctx->observed_zij++;
			ctx->last_serial = changeset_to(ch);
			ctx->last_serial_valid = true;
		} else {
			ctx->merged_serial = changeset_from(ch);
			ctx->observed_merged++;
		}
	} else if (ch != NULL) {
		if (!ctx->first_serial_valid) {
			ctx->first_serial = changeset_from(ch);
			ctx->first_serial_valid = true;
		}
		ctx->last_serial = changeset_to(ch);
		ctx->last_serial_valid = true;
		ctx->observed_count++;
	}
	return KNOT_EOK;
}

static bool eq(bool a, bool b)
{
	return a ? b : !b;
}

int journal_sem_check(zone_journal_t *j)
{
	check_ctx_t ctx = { 0 };
	journal_metadata_t md = { 0 };

	int ret = just_load_md(j, &md);
	if (ret == KNOT_EOK) {
		ret = journal_walk(j, check_cb, &ctx);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!eq((md.flags & SERIAL_TO_VALID), ctx.last_serial_valid)) {
		return 101;
	}
	if (ctx.last_serial_valid && ctx.last_serial != md.serial_to) {
		return 102;
	}
	if (!eq((md.flags & MERGED_SERIAL_VALID), (ctx.observed_merged > 0))) {
		return 103;
	}
	if (ctx.observed_merged > 1) {
		return 104;
	}
	if (ctx.observed_merged == 1 && ctx.merged_serial != md.merged_serial) {
		return 105;
	}
	if (ctx.observed_zij + ctx.observed_merged > 1) {
		return 106;
	}
	if (!eq(((md.flags & SERIAL_TO_VALID) && md.first_serial != md.serial_to), ctx.first_serial_valid)) {
		return 107;
	}
	if (!eq(ctx.first_serial_valid, (ctx.observed_count > 0))) {
		return 108;
	}
	if (ctx.first_serial_valid && ctx.first_serial != md.first_serial) {
		return 109;
	}
	return KNOT_EOK;
}
