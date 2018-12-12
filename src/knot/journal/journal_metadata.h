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

typedef struct {
	uint32_t first_serial;
	//uint32_t last_serial;
	uint32_t serial_to;
	uint32_t flushed_upto;
	uint32_t merged_serial;
	uint32_t changeset_count;
	uint32_t flags; // a bitmap of flags, see enum below
	bool _new_zone; // private: if there were no metadata at all previously
} journal_metadata_t;

enum journal_metadata_flags {
	LAST_FLUSHED_VALID   = (1 << 0), // deprecated
	SERIAL_TO_VALID      = (1 << 1),
	MERGED_SERIAL_VALID  = (1 << 2),
	ZONE_IN_JOURNAL      = (1 << 4),
};

void update_last_inserter(knot_lmdb_txn_t *txn, const knot_dname_t *new_inserter);

void journal_load_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, journal_metadata_t *md);

void journal_store_metadata(knot_lmdb_txn_t *txn, const knot_dname_t *zone, const journal_metadata_t *md);

void journal_scrape(zone_journal_t *j);
