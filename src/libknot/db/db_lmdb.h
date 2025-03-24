/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup db
 * @{
 */

#pragma once

#include "libknot/db/db.h"

/* Defines. */
#define KNOT_DB_LMDB_MAPSIZE    (100 * 1024 * 1024)

/* LMDB specific flags. */
extern const unsigned KNOT_DB_LMDB_NOTLS;
extern const unsigned KNOT_DB_LMDB_RDONLY;
extern const unsigned KNOT_DB_LMDB_INTEGERKEY;
extern const unsigned KNOT_DB_LMDB_NOSYNC;
extern const unsigned KNOT_DB_LMDB_WRITEMAP;
extern const unsigned KNOT_DB_LMDB_MAPASYNC;
extern const unsigned KNOT_DB_LMDB_DUPSORT;

/* Native options. */
struct knot_db_lmdb_opts {
	const char *path;     /*!< Database environment path. */
	const char *dbname;   /*!< Database name (or NULL). */
	size_t mapsize;       /*!< Environment map size. */
	unsigned maxdbs;      /*!< Maximum number of databases in the env. */
	unsigned maxreaders;  /*!< Maximum number of concurrent readers */
	struct {
		unsigned env; /*!< Environment flags. */
		unsigned db;  /*!< Database flags. */
	} flags;
};

/* Default options. */
#define KNOT_DB_LMDB_OPTS_INITIALIZER { \
	NULL, NULL, \
	KNOT_DB_LMDB_MAPSIZE, \
	0, \
	126, /* = contrib/lmdb/mdb.c DEFAULT_READERS */ \
	{ 0, 0 } \
}

const knot_db_api_t *knot_db_lmdb_api(void);

/* LMDB specific operations. */
int knot_db_lmdb_del_exact(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val);
int knot_db_lmdb_txn_begin(knot_db_t *db, knot_db_txn_t *txn, knot_db_txn_t *parent,
                           unsigned flags);
int knot_db_lmdb_iter_del(knot_db_iter_t *iter);
size_t knot_db_lmdb_get_mapsize(knot_db_t *db);
size_t knot_db_lmdb_get_usage(knot_db_t *db);
const char *knot_db_lmdb_get_path(knot_db_t *db);

/*! @} */
