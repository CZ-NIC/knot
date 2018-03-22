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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "chgset_ctx.h"

#include "knot/journal/journal.h"
#include "knot/journal/serialization.h"

chgset_ctx_t *chgset_ctx_create(size_t chunk_count)
{
	chgset_ctx_t *ch = calloc(1, sizeof(*ch));
	if (ch != NULL) {
		ch->chunk_count = chunk_count;
		ch->src_chunks = calloc(chunk_count, sizeof(*ch->src_chunks));
		ch->chunk_sizes = calloc(chunk_count, sizeof(*ch->chunk_sizes));
		if (ch->src_chunks == NULL || ch->chunk_sizes == NULL) {
			chgset_ctx_free(ch);
			ch = NULL;
		}
	}
	return ch;
}

void chgset_ctx_free(chgset_ctx_t *ch)
{
	free(ch->src_chunks);
	free(ch->chunk_sizes);
	free(ch);
}

void chgset_ctx_list_close(chgset_ctx_list_t *l)
{
	chgset_ctx_t *ch = NULL, *nxt = NULL;
	WALK_LIST_DELSAFE(ch, nxt, l->l) {
		chgset_ctx_free(ch);
	}
	journal_txn_commit(l->txn);
	free(l->txn);
	memset(l, 0, sizeof(*l));
}

void chgset_ctx_iterate(chgset_ctx_t *ch)
{
	assert(ch->chunk_count > 0);

	ch->curr_chunk = 0;
	ch->wire = wire_ctx_init(ch->src_chunks[0], ch->chunk_sizes[0]);
	ch->phase = CHGSET_CTX_START;
}

int chgset_ctx_next(chgset_ctx_t *ch, knot_rrset_t *rrset)
{
	int ret = deserialize_rrset_chunks(&ch->wire, rrset, ch->src_chunks,
					   ch->chunk_sizes, ch->chunk_count, &ch->curr_chunk);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (ch->phase == CHGSET_CTX_START && rrset->type != KNOT_RRTYPE_SOA) {
		return KNOT_EMALF;
	}

	if (ch->phase == CHGSET_CTX_SOA_FROM || ch->phase == CHGSET_CTX_SOA_TO ||
	    rrset->type == KNOT_RRTYPE_SOA) {
		ch->phase++;
	}

	if (ch->curr_chunk == ch->chunk_count - 1 && wire_ctx_available(&ch->wire) == 0) {
		ch->phase = CHGSET_CTX_DONE;
	} else if (ch->phase == CHGSET_CTX_DONE) {
		return KNOT_EMALF;
	}

	return ret;
}
