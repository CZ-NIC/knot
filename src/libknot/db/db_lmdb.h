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
int knot_db_lmdb_txn_begin(knot_db_t *db, knot_db_txn_t *txn, knot_db_txn_t *parent,
                           unsigned flags);
int knot_db_lmdb_iter_del(knot_db_iter_t *iter);
size_t knot_db_lmdb_get_mapsize(knot_db_t *db);
size_t knot_db_lmdb_get_usage(knot_db_t *db);
