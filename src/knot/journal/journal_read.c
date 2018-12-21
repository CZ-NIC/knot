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

#include "contrib/macros.h"
#include "contrib/ucw/lists.h"
#include "contrib/wire_ctx.h"
#include "libknot/error.h"

#include <stdlib.h>

struct journal_read {
	knot_lmdb_txn_t txn;
	MDB_val key_prefix;
	const knot_dname_t *zone;
	wire_ctx_t wire;
	journal_changeset_id_t next_id;
};

int journal_read_get_error(const journal_read_t *ctx, int another_error)
{
	return (ctx == NULL || ctx->txn.ret == KNOT_EOK ? another_error : ctx->txn.ret);
}

static void update_ctx_wire(journal_read_t *ctx)
{
	ctx->wire = wire_ctx_init_const(ctx->txn.cur_val.mv_data, ctx->txn.cur_val.mv_size);
	wire_ctx_skip(&ctx->wire, JOURNAL_HEADER_SIZE);
}

static bool go_next_changeset(journal_read_t *ctx, const knot_dname_t *zone)
{
	free(ctx->key_prefix.mv_data);
	ctx->key_prefix = journal_changeset_id_to_key(ctx->next_id, zone);
	if (!knot_lmdb_find_prefix(&ctx->txn, &ctx->key_prefix)) {
		return false;
	}
	ctx->next_id.zone_in_journal = false;
	ctx->next_id.serial = journal_next_serial(&ctx->txn.cur_val);
	update_ctx_wire(ctx);
	return true;
}

int journal_read_begin(zone_journal_t *j, journal_changeset_id_t from, journal_read_t **ctx)
{
	*ctx = NULL;
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
	newctx->next_id = from;

	knot_lmdb_begin(j->db, &newctx->txn, false);

	if (go_next_changeset(newctx, j->zone)) {
		*ctx = newctx;
		return KNOT_EOK;
	} else {
		journal_read_end(newctx);
		return KNOT_ENOENT;
	}
}

void journal_read_end(journal_read_t *ctx)
{
	if (ctx != NULL) {
		free(ctx->key_prefix.mv_data);
		knot_lmdb_abort(&ctx->txn);
		free(ctx);
	}
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

bool journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rrset, bool allow_next_changeset)
{
	//knot_rdataset_clear(&rrset->rrs, NULL);
	//memset(rrset, 0, sizeof(*rrset));
	if (!make_data_available(ctx)) {
		if (!allow_next_changeset || !go_next_changeset(ctx, ctx->zone)) {
			return false;
		}
	}
	rrset->owner = knot_dname_copy(ctx->wire.position, NULL);
	wire_ctx_skip(&ctx->wire, knot_dname_size(rrset->owner));
	rrset->type = wire_ctx_read_u16(&ctx->wire);
	rrset->rclass = wire_ctx_read_u16(&ctx->wire);
	uint16_t rrs_count = wire_ctx_read_u16(&ctx->wire);
	for (int i = 0; i < rrs_count && ctx->wire.error == KNOT_EOK; i++) {
		if (!make_data_available(ctx)) {
			ctx->wire.error = KNOT_EFEWDATA;
		}
		// TODO think of how to export serialized rr directly to knot_rdataset_add
		// focus on: even address aligning
		uint32_t ttl = wire_ctx_read_u32(&ctx->wire);
		if (i == 0) {
			rrset->ttl = ttl;
		}
		uint16_t len = wire_ctx_read_u16(&ctx->wire);
		if (ctx->wire.error == KNOT_EOK) {
			ctx->wire.error = knot_rrset_add_rdata(rrset, ctx->wire.position, len, NULL);
		}
		wire_ctx_skip(&ctx->wire, len);
	}
	if (ctx->txn.ret == KNOT_EOK) {
		ctx->txn.ret = ctx->wire.error == KNOT_ERANGE ? KNOT_EMALF : ctx->wire.error;
	}
	if (ctx->txn.ret == KNOT_EOK) {
		return true;
	} else {
		journal_read_clear_rrset(rrset);
		return false;
	}
}

void journal_read_clear_rrset(knot_rrset_t *rr)
{
	knot_rrset_clear(rr, NULL);
}

static int add_rr_to_contents(zone_contents_t *z, const knot_rrset_t *rrset)
{
	zone_node_t *n = NULL;
	return zone_contents_add_rr(z, rrset, &n);
	// Shall we ignore ETTL ?
}

bool journal_read_changeset(journal_read_t *ctx, changeset_t *ch)
{
	zone_contents_t *tree = zone_contents_new(ctx->zone);
	knot_rrset_t *soa = calloc(1, sizeof(*soa)), rr = { 0 };
	if (tree == NULL || soa == NULL) {
		ctx->txn.ret = KNOT_ENOMEM;
		goto fail;
	}
	memset(ch, 0, sizeof(*ch));

	if (!journal_read_rrset(ctx, soa, true)) {
		goto fail;
	}
	while (journal_read_rrset(ctx, &rr, false)) {
		if (rr.type == KNOT_RRTYPE_SOA &&
		    knot_dname_cmp(rr.owner, ctx->zone) == 0) {
			ch->soa_from = soa;
			ch->remove = tree;
			soa = malloc(sizeof(*soa));
			tree = zone_contents_new(ctx->zone);
			if (tree == NULL || soa == NULL) {
				ctx->txn.ret = KNOT_ENOMEM;
				goto fail;
			}
			*soa = rr; // note this tricky assignment
			memset(&rr, 0, sizeof(rr));
		} else {
			ctx->txn.ret = add_rr_to_contents(tree, &rr);
			journal_read_clear_rrset(&rr);
		}
	}

	if (ctx->txn.ret == KNOT_EOK) {
		ch->soa_to = soa;
		ch->add = tree;
		return true;
	} else {
fail:
		journal_read_clear_rrset(&rr);
		journal_read_clear_rrset(soa);
		free(soa);
		changeset_clear(ch);
		zone_contents_deep_free(tree);
		return false;
	}
}

void journal_read_clear_changeset(changeset_t *ch)
{
	changeset_clear(ch);
	memset(ch, 0, sizeof(*ch));
}

static int just_load_md(zone_journal_t *j, journal_metadata_t *md, bool *has_zij)
{
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(j->db, &txn, false);
	journal_load_metadata(&txn, j->zone, md);
	if (has_zij != NULL) {
		uint32_t unused;
		*has_zij = journal_have_zone_in_j(&txn, j->zone, &unused);
	}
	knot_lmdb_abort(&txn);
	return txn.ret;
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
	bool at_least_one = false, zone_in_j = false;
	ret = just_load_md(j, &md, &zone_in_j);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (zone_in_j) {
		id.zone_in_journal = true;
		goto read_one_special;
	} else if ((md.flags & JOURNAL_MERGED_SERIAL_VALID)) {
		id.serial = md.merged_serial;
read_one_special:
		ret = journal_read_begin(j, id, &read);
		if (ret == KNOT_EOK && journal_read_changeset(read, &ch)) {
			ret = cb(true, &ch, ctx);
			journal_read_clear_changeset(&ch);
		}
		ret = journal_read_get_error(read, ret);
		journal_read_end(read);
		read = NULL;
	} else {
		ret = cb(true, NULL, ctx);
	}

	if ((md.flags & JOURNAL_SERIAL_TO_VALID) && md.first_serial != md.serial_to &&
	    ret == KNOT_EOK) {
		id.zone_in_journal = false;
		id.serial = md.first_serial;
		ret = journal_read_begin(j, id, &read);
		while (ret == KNOT_EOK && journal_read_changeset(read, &ch)) {
			ret = cb(false, &ch, ctx);
			at_least_one = true;
			journal_read_clear_changeset(&ch);
		}
		ret = journal_read_get_error(read, ret);
		journal_read_end(read);
	}
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
	bool has_zij = false;

	if (!journal_is_existing(j)) {
		return KNOT_EOK;
	}

	int ret = just_load_md(j, &md, &has_zij);
	if (ret == KNOT_EOK) {
		ret = journal_walk(j, check_cb, &ctx);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!eq((md.flags & JOURNAL_SERIAL_TO_VALID), ctx.last_serial_valid)) {
		return 101;
	}
	if (ctx.last_serial_valid && ctx.last_serial != md.serial_to) {
		return 102;
	}
	if (!eq((md.flags & JOURNAL_MERGED_SERIAL_VALID), (ctx.observed_merged > 0))) {
		return 103;
	}
	if (ctx.observed_merged > 1) {
		return 104;
	}
	if (ctx.observed_merged == 1 && ctx.merged_serial != md.merged_serial) {
		return 105;
	}
	if (!eq(has_zij, (ctx.observed_zij > 0))) {
		return 106;
	}
	if (ctx.observed_zij > 1) {
		return 107;
	}
	if (ctx.observed_zij + ctx.observed_merged > 1) {
		return 108;
	}
	if (!eq(((md.flags & JOURNAL_SERIAL_TO_VALID) && md.first_serial != md.serial_to), ctx.first_serial_valid)) {
		return 109;
	}
	if (!eq(ctx.first_serial_valid, (ctx.observed_count > 0))) {
		return 110;
	}
	if (ctx.first_serial_valid && ctx.first_serial != md.first_serial) {
		return 111;
	}
	if (ctx.observed_count != md.changeset_count) {
		return 112;
	}
	return KNOT_EOK;
}
