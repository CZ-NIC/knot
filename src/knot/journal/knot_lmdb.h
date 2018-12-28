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
#include <stdlib.h>

typedef struct knot_lmdb_db {
	MDB_dbi dbi;
	MDB_env *env;
	pthread_mutex_t opening_mutex;

	// those are static options. Set them before knot_lmdb_init() and set static_opts_specified to true.
	unsigned maxdbs;
	unsigned maxreaders;
	const char *dbname;
	bool static_opts_specified;

	// those are internal options. Please don't touch them directly.
	size_t mapsize;
	unsigned env_flags; // MDB_NOTLS, MDB_RDONLY, MDB_WRITEMAP, MDB_DUPSORT, MDB_NOSYNC, MDB_MAPASYNC
	char *path;
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
	KNOT_LMDB_EXACT = 3,
	KNOT_LMDB_LEQ = 1,
	KNOT_LMDB_GEQ = 2,
	KNOT_LMDB_FORCE = 4,
} knot_lmdb_find_t;

typedef struct {
	MDB_val key;
	MDB_val val;
} knot_lmdb_keyval_t;

void knot_lmdb_init(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags);

bool knot_lmdb_exists(knot_lmdb_db_t *db);

int knot_lmdb_open(knot_lmdb_db_t *db);

void knot_lmdb_close(knot_lmdb_db_t *db);

int knot_lmdb_reinit(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags);

int knot_lmdb_reconfigure(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags);

void knot_lmdb_deinit(knot_lmdb_db_t *db);

inline static bool knot_lmdb_is_open(knot_lmdb_db_t *db) { return db->env != NULL; }

void knot_lmdb_close(knot_lmdb_db_t *db);

void knot_lmdb_begin(knot_lmdb_db_t *db, knot_lmdb_txn_t *txn, bool rw);

void knot_lmdb_abort(knot_lmdb_txn_t *txn);

void knot_lmdb_commit(knot_lmdb_txn_t *txn);

bool knot_lmdb_find(knot_lmdb_txn_t *txn, MDB_val *what, knot_lmdb_find_t how);

bool knot_lmdb_first(knot_lmdb_txn_t *txn);

bool knot_lmdb_next(knot_lmdb_txn_t *txn);

bool knot_lmdb_is_prefix_of(MDB_val *prefix, MDB_val *of);

inline static bool knot_lmdb_find_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix)
{
	return knot_lmdb_find(txn, prefix, KNOT_LMDB_GEQ) &&
	       knot_lmdb_is_prefix_of(prefix, &txn->cur_key);
}

#define knot_lmdb_foreach(txn, prefix) \
	for (bool _knot_lmdb_foreach_found = knot_lmdb_find((txn), (prefix), KNOT_LMDB_GEQ); \
	     _knot_lmdb_foreach_found && knot_lmdb_is_prefix_of((prefix), &(txn)->cur_key); \
	     _knot_lmdb_foreach_found = knot_lmdb_next((txn)))

void knot_lmdb_del_cur(knot_lmdb_txn_t *txn);

void knot_lmdb_del_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix);

void knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val);

int knot_lmdb_quick_insert(knot_lmdb_db_t *db, MDB_val key, MDB_val val);

size_t knot_lmdb_usage(knot_lmdb_txn_t *txn);

MDB_val knot_lmdb_make_key(const char *format, ...);

bool knot_lmdb_make_key_part(void *key_data, size_t key_len, const char *format, ...);

bool knot_lmdb_unmake_key(void *key_data, size_t key_len, const char *format, ...);
