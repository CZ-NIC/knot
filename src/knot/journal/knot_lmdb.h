/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

	// those are static options. Set them after knot_lmdb_init().
	unsigned maxdbs;
	unsigned maxreaders;

	// those are internal options. Please don't touch them directly.
	size_t mapsize;
	unsigned env_flags; // MDB_NOTLS, MDB_RDONLY, MDB_WRITEMAP, MDB_DUPSORT, MDB_NOSYNC, MDB_MAPASYNC
	const char *dbname;
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
	KNOT_LMDB_EXACT = 3,   /*! \brief Search for exactly matching key. */
	KNOT_LMDB_LEQ = 1,     /*! \brief Search lexicographically lower or equal key. */
	KNOT_LMDB_GEQ = 2,     /*! \brief Search lexicographically greater or equal key. */
	KNOT_LMDB_FORCE = 4,   /*! \brief If no matching key found, consider it a transaction failure (KNOT_ENOENT). */
} knot_lmdb_find_t;

/*!
 * \brief Initialise the DB handling structure.
 *
 * \param db          DB handling structure.
 * \param path        Path to LMDB database on filesystem.
 * \param mapsize     Maximum size of the DB on FS.
 * \param env_flags   LMDB environment flags (e.g. MDB_RDONLY)
 * \param dbname      Optional: name of the sub-database.
 */
void knot_lmdb_init(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags, const char *dbname);

/*!
 * \brief Check if the databse exists on the filesystem.
 *
 * \param db   The DB in question.
 *
 * \return True if it already exists.
 */
bool knot_lmdb_exists(knot_lmdb_db_t *db);

/*!
 * \brief Open the previously initialised DB.
 *
 * \param db   The DB to be opened.
 *
 * \note If db->mapsize is zero, it will be set to twice the current size, and DB opened read-only!
 *
 * \return KNOT_E*
 */
int knot_lmdb_open(knot_lmdb_db_t *db);

/*!
 * \brief Close the database, but keep it initialised.
 *
 * \param db   The DB to be closed.
 */
void knot_lmdb_close(knot_lmdb_db_t *db);

/*!
 * \brief Re-initialise existing DB with modified parameters.
 *
 * \note If the paramateres differ and DB is open, it will be refused.
 *
 * \param db          The DB to be modified.
 * \param path        New path to the DB.
 * \param mapsize     New mapsize.
 * \param env_flags   New LMDB environment flags.
 *
 * \return KNOT_EOK on success, KNOT_EISCONN if not possible.
 */
int knot_lmdb_reinit(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags);

/*!
 * \brief Re-open opened DB with modified parameters.
 *
 * \note The DB will be first closed, re-initialised and finally opened again.
 *
 * \note There must not be any DB transaction during this process.
 *
 * \param db          The DB to be modified.
 * \param path        New path to the DB.
 * \param mapsize     New mapsize.
 * \param env_flags   New LMDB environment flags.
 *
 * \return KNOT_E*
 */
int knot_lmdb_reconfigure(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags);

/*!
 * \brief Close and de-initialise DB.
 *
 * \param db   DB to be deinitialised.
 */
void knot_lmdb_deinit(knot_lmdb_db_t *db);

/*!
 * \brief Return true if DB is open.
 */
inline static bool knot_lmdb_is_open(knot_lmdb_db_t *db) { return db->env != NULL; }

/*!
 * \brief Start a DB transaction.
 *
 * \param db    The database.
 * \param txn   Transaction handling structure to be initialised.
 * \param rw    True for read-write transaction, false for read-only.
 *
 * \note The error code will be stored in txn->ret.
 */
void knot_lmdb_begin(knot_lmdb_db_t *db, knot_lmdb_txn_t *txn, bool rw);

/*!
 * \brief Abort a transaction.
 *
 * \param txn   Transaction to be aborted.
 */
void knot_lmdb_abort(knot_lmdb_txn_t *txn);

/*!
 * \brief Commit a transaction, or abort it if id had failured.
 *
 * \param txn   Transaction to be commited.
 *
 * \note If txn->ret equals KNOT_EOK afterwards, whole DB transaction was successful.
 */
void knot_lmdb_commit(knot_lmdb_txn_t *txn);

/*!
 * \brief Find a key in database. The matched key will be in txn->cur_key and its value in txn->cur_val.
 *
 * \param txn    DB transaction.
 * \param what   Key to be searched for.
 * \param how    Method of comparing keys. See comments at knot_lmdb_find_t.
 *
 * \note It's possible to use knot_lmdb_next() subsequently to iterate over following keys.
 *
 * \return True if a key found, false if none or failure.
 */
bool knot_lmdb_find(knot_lmdb_txn_t *txn, MDB_val *what, knot_lmdb_find_t how);

/*!
 * \brief Start iteration the whole DB from lexicographically first key.
 *
 * \note The first DB record will be in txn->cur_key and txn->cur_val.
 *
 * \param txn   DB transaction.
 *
 * \return True if ok, false if no key at all or failure.
 */
bool knot_lmdb_first(knot_lmdb_txn_t *txn);

/*!
 * \brief Iterate to the lexicographically next key (sets txn->cur_key and txn->cur_val).
 *
 * \param txn   DB transaction.
 *
 * \return True if ok, false if behind the end of DB or failure.
 */
bool knot_lmdb_next(knot_lmdb_txn_t *txn);

/*!
 * \brief Check if one DB key is a prefix of another,
 *
 * \param prefix   DB key prefix.
 * \param of       Another DB key.
 *
 * \return True iff 'prefix' is a prefix of 'of'.
 */
bool knot_lmdb_is_prefix_of(MDB_val *prefix, MDB_val *of);

/*!
 * \brief Find leftmost key in DB matching given prefix.
 *
 * \param txn      DB transaction.
 * \param prefix   Prefix searched for.
 *
 * \return True if found, false if none or failure.
 */
inline static bool knot_lmdb_find_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix)
{
	return knot_lmdb_find(txn, prefix, KNOT_LMDB_GEQ) &&
	       knot_lmdb_is_prefix_of(prefix, &txn->cur_key);
}

/*!
 * \brief Execute following block of commands for every key in DB matching given prefix.
 *
 * \param txn      DB transaction.
 * \param prefix   Prefix searched for.
 */
#define knot_lmdb_foreach(txn, prefix) \
	for (bool _knot_lmdb_foreach_found = knot_lmdb_find((txn), (prefix), KNOT_LMDB_GEQ); \
	     _knot_lmdb_foreach_found && knot_lmdb_is_prefix_of((prefix), &(txn)->cur_key); \
	     _knot_lmdb_foreach_found = knot_lmdb_next((txn)))

/*!
 * \brief Delete the one DB record, that the iteration is currently pointing to.
 *
 * \note It's safe to delete during an uncomplicated iteration, e.g. knot_lmdb_foreach().
 *
 * \param txn   DB transaction.
 */
void knot_lmdb_del_cur(knot_lmdb_txn_t *txn);

/*!
 * \brief Delete all DB records matching given key prefix.
 *
 * \param txn      DB transaction.
 * \param prefix   Prefix to be deleted.
 */
void knot_lmdb_del_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix);

/*!
 * \brief Insert a new record into the DB.
 *
 * \note If a record with equal key already exists in the DB, its value will be quietly overwritten.
 *
 * \param txn   DB transaction.
 * \param key   Inserted key.
 * \param val   Inserted value.
 *
 * \return False if failure.
 */
bool knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val);

/*!
 * \brief Open a transaction, insert a record, commmit and free key's and val's mv_data.
 *
 * \param db    DB to be inserted into.
 * \param key   Inserted key.
 * \param val   Inserted val.
 *
 * \return KNOT_E*
 */
int knot_lmdb_quick_insert(knot_lmdb_db_t *db, MDB_val key, MDB_val val);

/*!
 * \brief Amount of bytes used by the DB storage.
 *
 * \note According to LMDB design, it will be a multiple of page size, which is usually 4096.
 *
 * \param txn   DB transaction.
 *
 * \return DB usage.
 */
size_t knot_lmdb_usage(knot_lmdb_txn_t *txn);

/*!
 * \brief Serialize various parameters into a DB key.
 *
 * \param format   Specifies the number and type of parameters.
 * \param ...      For each character in 'format', one or two parameters with the actual values.
 *
 * \return DB key structure. 'mv_data' needs to be freed later. 'mv_data' is NULL on failure.
 *
 * Possible format characters are:
 * - B for a byte
 * - H for uint16
 * - I for uint32
 * - L for uint64, like H and I, the serialization converts them to big endian
 * - S for zero-terminated string
 * - N for a domain name (in knot_dname_t* format)
 * - D for fixed-size data (takes two params: void* and size_t)
 */
MDB_val knot_lmdb_make_key(const char *format, ...);

/*!
 * \brief Serialize various parameters into prepared buffer.
 *
 * \param key_data   Pointer to the buffer.
 * \param key_len    Size of the buffer.
 * \param format     Specifies the number and type of parameters.
 * \param ...        For each character in 'format', one or two parameters with the actual values.
 *
 * \note See comment at knot_lmdb_make_key().
 *
 * \return True if ok and the serialization took exactly 'key_len', false on failure.
 */
bool knot_lmdb_make_key_part(void *key_data, size_t key_len, const char *format, ...);

/*!
 * \brief Deserialize various parameters from a buffer.
 *
 * \note 'format' must exactly correspond with what the data in buffer actually are.
 *
 * \param key_data   Pointer to the buffer.
 * \param key_len    Size of the buffer.
 * \param format     Specifies the number and type of parameters.
 * \param ...        For each character in 'format', pointer to where the values will be stored.
 *
 * \note For B, H, I, L; provide simply pointers to variables of correspodning type.
 * \note For S, N; provide pointer to pointer - it will be set to pointing inside the buffer, so no allocation here.
 * \note For D, provide void* and size_t, the data will be copied.
 *
 * \return True if no failure.
 */
bool knot_lmdb_unmake_key(const void *key_data, size_t key_len, const char *format, ...);

/*!
 * \brief Deserialize various parameters from txn->cur_val. Set txn->ret to KNOT_EMALF if failure.
 *
 * \param txn      DB transaction.
 * \param format   Specifies the number and type of parameters.
 * \param ...      For each character in 'format', pointer to where the values will be stored.
 *
 * \note See comment at knot_lmdb_unmake_key().
 *
 * \return True if no failure.
 */
bool knot_lmdb_unmake_curval(knot_lmdb_txn_t *txn, const char *format, ...);
