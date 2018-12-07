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

#include "knot/journal/journal_basic.h"

typedef struct journal_read journal_read_t;

#define JOURNAL_READ_DONE (1)

int journal_read_begin(journal_t *j, journal_changeset_id_t from, journal_read_t **ctx);

int journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rr);

int journal_read_changeset(journal_read_t *ctx, changeset_t *ch);

void journal_read_end(journal_read_t *ctx);

void journal_write_changeset(knot_lmdb_txn_t *txn, const changeset_t *ch);
