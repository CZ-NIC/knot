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

#include "libknot/mm_ctx.h"

enum {
	/* Database flags */

	NAMEDB_RDONLY = 1 << 0, /*!< Read only. */
	NAMEDB_SORTED = 1 << 1, /*!< Sorted output. */

	/* Operations */

	NAMEDB_NOOP   = 1 << 2, /*!< No operation. */
	NAMEDB_FIRST  = 1 << 3, /*!< First entry. */
	NAMEDB_LAST   = 1 << 4, /*!< Last entry. */
	NAMEDB_NEXT   = 1 << 5, /*!< Next entry. */
	NAMEDB_PREV   = 1 << 6, /*!< Previous entry. */
	NAMEDB_LEQ    = 1 << 7, /*!< Lesser or equal. */
	NAMEDB_GEQ    = 1 << 8  /*!< Greater or equal. */
};

typedef void namedb_t;
typedef void namedb_iter_t;

typedef struct namedb_val {
	void *data;
	size_t len;
} namedb_val_t;

typedef struct namedb_txn {
	namedb_t *db;
	void *txn;
} namedb_txn_t;

typedef struct namedb_api {
	const char *name;

	/* Context operations */

	int (*init)(namedb_t **db, knot_mm_t *mm, void *opts);
	void (*deinit)(namedb_t *db);

	/* Transactions */

	int (*txn_begin)(namedb_t *db, namedb_txn_t *txn, unsigned flags);
	int (*txn_commit)(namedb_txn_t *txn);
	void (*txn_abort)(namedb_txn_t *txn);

	/* Data access */

	int (*count)(namedb_txn_t *txn);
	int (*clear)(namedb_txn_t *txn);
	int (*find)(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags);
	int (*insert)(namedb_txn_t *txn, namedb_val_t *key, namedb_val_t *val, unsigned flags);
	int (*del)(namedb_txn_t *txn, namedb_val_t *key);

	/* Iteration */

	namedb_iter_t *(*iter_begin)(namedb_txn_t *txn, unsigned flags);
	namedb_iter_t *(*iter_seek)(namedb_iter_t *iter, namedb_val_t *key, unsigned flags);
	namedb_iter_t *(*iter_next)(namedb_iter_t *iter);
	int (*iter_key)(namedb_iter_t *iter, namedb_val_t *key);
	int (*iter_val)(namedb_iter_t *iter, namedb_val_t *val);
	void (*iter_finish)(namedb_iter_t *iter);
} namedb_api_t;
