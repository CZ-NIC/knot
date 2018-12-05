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

#include "contrib/lmdb/lmdb.h"

#include <stdbool.h>

typedef struct {
	MDB_dbi dbi;
	MDB_env *env;

	bool opened;
	int txn_flags;
} knot_lmdb_db_t;

typedef struct {
	MDB_txn *txn;
	MDB_cursor *cursor;
	MDB_val cur_key;
	MDB_val cur_val;

	bool opened;
	bool is_rw;
	int ret;
	knot_lmdb_db_t *db;
} knot_lmdb_txn_t;

typedef enum {
	KNOT_LMDB_EXACT,
	KNOT_LMDB_LEQ,
	KNOT_LMDB_GEQ,
} knot_lmdb_find_t;

typedef struct {
	MDB_val key;
	MDB_val val;
} knot_lmdb_keyval_t;


void knot_lmdb_begin(knot_lmdb_db_t *db, knot_lmdb_txn_t *txn);

void knot_lmdb_abort(knot_lmdb_txn_t *txn);

void knot_lmdb_commit(knot_lmdb_txn_t *txn);

bool knot_lmdb_find(knot_lmdb_txn_t *txn, MDB_val *what, knot_lmdb_find_t how);

bool knot_lmdb_first(knot_lmdb_txn_t *txn);

bool knot_lmdb_next(knot_lmdb_txn_t *txn);

#define knot_lmdb_foreach(txn, prefix) \
	for (bool _knot_lmdb_foreach_found = knot_lmdb_find((txn), (prefix), KNOT_LMDB_GEQ); \
	     _knot_lmdb_foreach_found && is_prefix_of((prefix), &(txn)->cur_key); \
	     _knot_lmdb_foreach_found = knot_lmdb_next((txn)))

void knot_lmdb_del_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix);

void knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val);

size_t knot_lmdb_usage(knot_lmdb_txn_t *txn);

MDB_val knot_lmdb_make_key(const char *format, ...);

bool knot_lmdb_make_key_part(void *key_data, size_t key_len, const char *format, ...);

bool knot_lmdb_unmake_key(void *key_data, size_t key_len, const char *format, ...);
