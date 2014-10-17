/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "libknot/dname.h"

enum {
	KNOT_NAMEDB_RDONLY = 1 << 0,
	KNOT_NAMEDB_SORTED = 1 << 1
};

typedef void knot_namedb_t;
typedef void knot_iter_t;

typedef struct knot_val {
	void *data;
	size_t len;
} knot_val_t;

typedef struct knot_txn {
	knot_namedb_t *db;
	void *txn;
} knot_txn_t;

struct namedb_api {

	const char *name;

	/* Context operations */

	int (*init)(const char *config, knot_namedb_t **db, mm_ctx_t *mm);
	void (*deinit)(knot_namedb_t *db);

	/* Transactions */

	int (*txn_begin)(knot_namedb_t *db, knot_txn_t *txn, unsigned flags);
	int (*txn_commit)(knot_txn_t *txn);
	void (*txn_abort)(knot_txn_t *txn);

	/* Data access */

	int (*count)(knot_txn_t *txn);
	int (*find)(knot_txn_t *txn, knot_val_t *key, knot_val_t *val, unsigned flags);
	int (*insert)(knot_txn_t *txn, knot_val_t *key, knot_val_t *val, unsigned flags);
	int (*del)(knot_txn_t *txn,knot_val_t *key);

	/* Iteration */

	knot_iter_t *(*iter_begin)(knot_txn_t *txn, unsigned flags);
	knot_iter_t *(*iter_next)(knot_iter_t *iter);
	int (*iter_key)(knot_iter_t *iter, knot_val_t *key);
	int (*iter_val)(knot_iter_t *iter, knot_val_t *val);
	void (*iter_finish)(knot_iter_t *iter);
};
