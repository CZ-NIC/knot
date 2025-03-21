/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Structures for binary data handling.
 *
 * \addtogroup db
 * @{
 */

#pragma once

#include "libknot/mm_ctx.h"

enum {
	/* Database flags */

	KNOT_DB_RDONLY = 1 << 0, /*!< Read only. */
	KNOT_DB_SORTED = 1 << 1, /*!< Sorted output. */

	/* Operations */

	KNOT_DB_NOOP   = 1 << 2, /*!< No operation. */
	KNOT_DB_FIRST  = 1 << 3, /*!< First entry. */
	KNOT_DB_LAST   = 1 << 4, /*!< Last entry. */
	KNOT_DB_NEXT   = 1 << 5, /*!< Next entry. */
	KNOT_DB_PREV   = 1 << 6, /*!< Previous entry. */
	KNOT_DB_LEQ    = 1 << 7, /*!< Lesser or equal. */
	KNOT_DB_GEQ    = 1 << 8  /*!< Greater or equal. */
};

typedef void knot_db_t;
typedef void knot_db_iter_t;

typedef struct knot_db_val {
	void *data;
	size_t len;
} knot_db_val_t;

typedef struct knot_db_txn {
	knot_db_t *db;
	void *txn;
} knot_db_txn_t;

typedef struct knot_db_api {
	const char *name;

	/* Context operations */

	int (*init)(knot_db_t **db, knot_mm_t *mm, void *opts);
	void (*deinit)(knot_db_t *db);

	/* Transactions */

	int (*txn_begin)(knot_db_t *db, knot_db_txn_t *txn, unsigned flags);
	int (*txn_commit)(knot_db_txn_t *txn);
	void (*txn_abort)(knot_db_txn_t *txn);

	/* Data access */

	int (*count)(knot_db_txn_t *txn);
	int (*clear)(knot_db_txn_t *txn);
	int (*find)(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags);
	int (*insert)(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags);
	int (*del)(knot_db_txn_t *txn, knot_db_val_t *key);

	/* Iteration */

	knot_db_iter_t *(*iter_begin)(knot_db_txn_t *txn, unsigned flags);
	knot_db_iter_t *(*iter_seek)(knot_db_iter_t *iter, knot_db_val_t *key, unsigned flags);
	knot_db_iter_t *(*iter_next)(knot_db_iter_t *iter);
	int (*iter_key)(knot_db_iter_t *iter, knot_db_val_t *key);
	int (*iter_val)(knot_db_iter_t *iter, knot_db_val_t *val);
	void (*iter_finish)(knot_db_iter_t *iter);
} knot_db_api_t;

/*! @} */
