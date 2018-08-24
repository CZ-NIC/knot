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

#pragma once

#include "contrib/ucw/lists.h"
#include "contrib/wire_ctx.h"
#include "libknot/rrset.h"

typedef enum {
	CHGSET_CTX_NOITER = 0,
	CHGSET_CTX_START,
	CHGSET_CTX_SOA_FROM,
	CHGSET_CTX_REM,
	CHGSET_CTX_SOA_TO,
	CHGSET_CTX_ADD,
	CHGSET_CTX_DONE,
} chgset_ctx_phase_t;

struct journal_txn; // journal.c

typedef struct {
	node_t n;

	uint8_t **src_chunks;
	size_t *chunk_sizes;
	size_t chunk_count;
	size_t curr_chunk;
	wire_ctx_t wire;
	chgset_ctx_phase_t phase;

	uint32_t serial_from;
	uint32_t serial_to;
} chgset_ctx_t;

typedef struct {
	list_t l;
	struct journal_txn *txn;
} chgset_ctx_list_t;

chgset_ctx_t *chgset_ctx_create(size_t chunk_count);

void chgset_ctx_free(chgset_ctx_t *ch);

void chgset_ctx_list_close(chgset_ctx_list_t *l);

void chgset_ctx_iterate(chgset_ctx_t *ch);

int chgset_ctx_next(chgset_ctx_t *ch, knot_rrset_t *rrset);

