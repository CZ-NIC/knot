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

#include "libknot/internal/namedb/namedb.h"

/* Defines. */
#define NAMEDB_LMDB_MAPSIZE    (100 * 1024 * 1024)

/* LMDB specific flags. */
extern const unsigned NAMEDB_LMDB_NOTLS;

/* Native options. */
struct namedb_lmdb_opts {
	const char *path;     /*!< Database environment path. */
	const char *dbname;   /*!< Database name (or NULL). */
	size_t mapsize;       /*!< Environment map size. */
	unsigned maxdbs;      /*!< Maximum number of databases in the env. */
	struct {
		unsigned env; /*!< Environment flags. */
		unsigned db;  /*!< Database flags. */
	} flags;
};

/* Default options. */
#define NAMEDB_LMDB_OPTS_INITIALIZER { \
	NULL, NULL, \
	NAMEDB_LMDB_MAPSIZE, \
	0, \
	{ 0, 0 } \
}

const namedb_api_t *namedb_lmdb_api(void);

/* LMDB specific operations. */
int namedb_lmdb_txn_begin(namedb_t *db, namedb_txn_t *txn, namedb_txn_t *parent,
                          unsigned flags);
int namedb_lmdb_iter_del(namedb_iter_t *iter);
