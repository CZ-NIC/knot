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

typedef int (*journal_read_cb_t)(bool in_remove_section, const knot_rrset_t *rr, void *ctx);

typedef int (*journal_walk_cb_t)(bool special, const changeset_t *ch, void *ctx);

int journal_read_ret(const journal_read_t *ctx);

int journal_read_get_error(const journal_read_t *ctx, int another_error);

int journal_read_begin(zone_journal_t j, bool read_zone, uint32_t serial_from, journal_read_t **ctx);

bool journal_read_rrset(journal_read_t *ctx, knot_rrset_t *rr, bool allow_next_changeset);

// TODO move somewhere. Libknot?
inline static bool rr_is_apex_soa(const knot_rrset_t *rr, const knot_dname_t *apex)
{
	return (rr->type == KNOT_RRTYPE_SOA && knot_dname_cmp(rr->owner, apex) == 0);
}

int journal_read_rrsets(journal_read_t *read, journal_read_cb_t cb, void *ctx);

void journal_read_clear_rrset(knot_rrset_t *rr);

bool journal_read_changeset(journal_read_t *ctx, changeset_t *ch);

void journal_read_clear_changeset(changeset_t *ch);

void journal_read_end(journal_read_t *ctx);

int journal_walk(zone_journal_t j, journal_walk_cb_t cb, void *ctx);

int journal_sem_check(zone_journal_t j);
