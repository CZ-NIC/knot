/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/db/db_lmdb.h"
#include "contrib/mempattern.h"

#include <lmdb.h>

/* Defines */
#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

_public_ const unsigned KNOT_DB_LMDB_NOTLS = MDB_NOTLS;
_public_ const unsigned KNOT_DB_LMDB_RDONLY = MDB_RDONLY;
_public_ const unsigned KNOT_DB_LMDB_INTEGERKEY = MDB_INTEGERKEY;
_public_ const unsigned KNOT_DB_LMDB_NOSYNC = MDB_NOSYNC;
_public_ const unsigned KNOT_DB_LMDB_WRITEMAP = MDB_WRITEMAP;
_public_ const unsigned KNOT_DB_LMDB_MAPASYNC = MDB_MAPASYNC;
_public_ const unsigned KNOT_DB_LMDB_DUPSORT = MDB_DUPSORT;

struct lmdb_env
{
	bool shared;
	MDB_dbi dbi;
	MDB_env *env;
	knot_mm_t *pool;
};

/*!
 * \brief Convert error code returned by LMDB to Knot DNS error code.
 *
 * LMDB defines own error codes but uses additional ones from libc:
 * - LMDB errors do not conflict with Knot DNS ones.
 * - Significant LMDB errors are mapped to Knot DNS ones.
 * - Standard errors are converted to negative value to match Knot DNS mapping.
 */
static int lmdb_error_to_knot(int error)
{
	if (error == MDB_SUCCESS) {
		return KNOT_EOK;
	}

	if (error == MDB_NOTFOUND) {
		return KNOT_ENOENT;
	}

	if (error == MDB_TXN_FULL) {
		return KNOT_ELIMIT;
	}

	if (error == MDB_MAP_FULL || error == ENOSPC) {
		return KNOT_ESPACE;
	}

	return -abs(error);
}

static int create_env_dir(const char *path)
{
	int r = mkdir(path, LMDB_DIR_MODE);
	if (r == -1 && errno != EEXIST) {
		return lmdb_error_to_knot(errno);
	}

	return KNOT_EOK;
}

/*! \brief Set the environment map size.
 * \note This also sets the maximum database size, see mdb_env_set_mapsize
 */
static int set_mapsize(MDB_env *env, size_t map_size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KNOT_ERROR;
	}

	/* Round to page size. */
	map_size = (map_size / page_size) * page_size;
	int ret = mdb_env_set_mapsize(env, map_size);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

/*! \brief Close the database. */
static void dbase_close(struct lmdb_env *env)
{
	mdb_dbi_close(env->env, env->dbi);
	if (!env->shared) {
		mdb_env_close(env->env);
	}
}

/*! \brief Open database environment. */
static int dbase_open_env(struct lmdb_env *env, struct knot_db_lmdb_opts *opts)
{
	MDB_env *mdb_env = NULL;
	int ret = mdb_env_create(&mdb_env);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	ret = create_env_dir(opts->path);
	if (ret != KNOT_EOK) {
		mdb_env_close(mdb_env);
		return ret;
	}

	ret = set_mapsize(mdb_env, opts->mapsize);
	if (ret != KNOT_EOK) {
		mdb_env_close(mdb_env);
		return ret;
	}

	ret = mdb_env_set_maxdbs(mdb_env, opts->maxdbs);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(mdb_env);
		return lmdb_error_to_knot(ret);
	}

	ret = mdb_env_set_maxreaders(mdb_env, opts->maxreaders);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(mdb_env);
		return lmdb_error_to_knot(ret);
	}

#ifdef __OpenBSD__
	/*
	 * Enforce that MDB_WRITEMAP is set.
	 *
	 * MDB assumes a unified buffer cache.
	 *
	 * See https://www.openldap.org/pub/hyc/mdm-paper.pdf section 3.1,
	 * references 17, 18, and 19.
	 *
	 * From Howard Chu: "This requirement can be relaxed in the
	 * current version of the library. If you create the environment
	 * with the MDB_WRITEMAP option then all reads and writes are
	 * performed using mmap, so the file buffer cache is irrelevant.
	 * Of course then you lose the protection that the read-only
	 * map offers."
	 */
	opts->flags.env |= MDB_WRITEMAP;
#endif

	ret = mdb_env_open(mdb_env, opts->path, opts->flags.env, LMDB_FILE_MODE);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(mdb_env);
		return lmdb_error_to_knot(ret);
	}

	/* Keep the environment pointer. */
	env->env = mdb_env;

	return KNOT_EOK;
}

static int dbase_open(struct lmdb_env *env, struct knot_db_lmdb_opts *opts)
{
	unsigned flags = 0;
	if (opts->flags.env & KNOT_DB_LMDB_RDONLY) {
		flags = MDB_RDONLY;
	}

	/* Open the database. */
	MDB_txn *txn = NULL;
	int ret = mdb_txn_begin(env->env, NULL, flags, &txn);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(env->env);
		return lmdb_error_to_knot(ret);
	}

	ret = mdb_dbi_open(txn, opts->dbname, opts->flags.db | MDB_CREATE, &env->dbi);
	if (ret != MDB_SUCCESS) {
		mdb_txn_abort(txn);
		mdb_env_close(env->env);
		return lmdb_error_to_knot(ret);
	}

	ret = mdb_txn_commit(txn);
	if (ret != MDB_SUCCESS) {
		mdb_env_close(env->env);
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static int init(knot_db_t **db_ptr, knot_mm_t *mm, void *arg)
{
	if (db_ptr == NULL || arg == NULL) {
		return KNOT_EINVAL;
	}

	struct lmdb_env *env = mm_alloc(mm, sizeof(struct lmdb_env));
	if (env == NULL) {
		return KNOT_ENOMEM;
	}

	memset(env, 0, sizeof(struct lmdb_env));
	env->pool = mm;

	/* Open new environment. */
	struct lmdb_env *old_env = *db_ptr;
	if (old_env == NULL) {
		int ret = dbase_open_env(env, (struct knot_db_lmdb_opts *)arg);
		if (ret != KNOT_EOK) {
			mm_free(mm, env);
			return ret;
		}
	} else {
		/* Shared environment, this instance just owns the DBI. */
		env->env = old_env->env;
		env->shared = true;
	}

	/* Open the database. */
	int ret = dbase_open(env, (struct knot_db_lmdb_opts *)arg);
	if (ret != KNOT_EOK) {
		mm_free(mm, env);
		return ret;
	}

	/* Store the new environment. */
	*db_ptr = env;

	return KNOT_EOK;
}

static void deinit(knot_db_t *db)
{
	if (db) {
		struct lmdb_env *env = db;

		dbase_close(env);
		mm_free(env->pool, env);
	}
}

_public_
int knot_db_lmdb_txn_begin(knot_db_t *db, knot_db_txn_t *txn, knot_db_txn_t *parent,
                           unsigned flags)
{
	txn->db = db;
	txn->txn = NULL;

	unsigned txn_flags = 0;
	if (flags & KNOT_DB_RDONLY) {
		txn_flags |= MDB_RDONLY;
	}

	MDB_txn *parent_txn = (parent != NULL) ? (MDB_txn *)parent->txn : NULL;

	struct lmdb_env *env = db;
	int ret = mdb_txn_begin(env->env, parent_txn, txn_flags, (MDB_txn **)&txn->txn);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static int txn_begin(knot_db_t *db, knot_db_txn_t *txn, unsigned flags)
{
	return knot_db_lmdb_txn_begin(db, txn, NULL, flags);
}

static int txn_commit(knot_db_txn_t *txn)
{
	int ret = mdb_txn_commit((MDB_txn *)txn->txn);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static void txn_abort(knot_db_txn_t *txn)
{
	mdb_txn_abort((MDB_txn *)txn->txn);
}

static int count(knot_db_txn_t *txn)
{
	struct lmdb_env *env = txn->db;

	MDB_stat stat;
	int ret = mdb_stat(txn->txn, env->dbi, &stat);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return stat.ms_entries;
}

static int clear(knot_db_txn_t *txn)
{
	struct lmdb_env *env = txn->db;

	int ret = mdb_drop(txn->txn, env->dbi, 0);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static knot_db_iter_t *iter_set(knot_db_iter_t *iter, knot_db_val_t *key, unsigned flags)
{
	MDB_cursor *cursor = iter;

	MDB_cursor_op op = MDB_SET;
	switch(flags) {
	case KNOT_DB_NOOP:  return cursor;
	case KNOT_DB_FIRST: op = MDB_FIRST; break;
	case KNOT_DB_LAST:  op = MDB_LAST;  break;
	case KNOT_DB_NEXT:  op = MDB_NEXT; break;
	case KNOT_DB_PREV:  op = MDB_PREV; break;
	case KNOT_DB_LEQ:
	case KNOT_DB_GEQ:   op = MDB_SET_RANGE; break;
	default: break;
	}

	MDB_val db_key = { 0, NULL };
	if (key) {
		db_key.mv_data = key->data;
		db_key.mv_size = key->len;
	}
	MDB_val unused_key = { 0, NULL }, unused_val = { 0, NULL };

	int ret = mdb_cursor_get(cursor, key ? &db_key : &unused_key, &unused_val, op);

	/* LEQ is not supported in LMDB, workaround using GEQ. */
	if (flags == KNOT_DB_LEQ && key) {
		/* Searched key is after the last key. */
		if (ret != MDB_SUCCESS) {
			return iter_set(iter, NULL, KNOT_DB_LAST);
		}
		/* If the searched key != matched, get previous. */
		if ((key->len != db_key.mv_size) ||
		    (memcmp(key->data, db_key.mv_data, key->len) != 0)) {
			return iter_set(iter, NULL, KNOT_DB_PREV);
		}
	}

	if (ret != MDB_SUCCESS) {
		mdb_cursor_close(cursor);
		return NULL;
	}

	return cursor;
}

static knot_db_iter_t *iter_begin(knot_db_txn_t *txn, unsigned flags)
{
	struct lmdb_env *env = txn->db;
	MDB_cursor *cursor = NULL;

	int ret = mdb_cursor_open(txn->txn, env->dbi, &cursor);
	if (ret != MDB_SUCCESS) {
		return NULL;
	}

	/* Clear sorted flag, as it's always sorted. */
	flags &= ~KNOT_DB_SORTED;

	return iter_set(cursor, NULL, (flags == 0) ? KNOT_DB_FIRST : flags);
}

static knot_db_iter_t *iter_next(knot_db_iter_t *iter)
{
	return iter_set(iter, NULL, KNOT_DB_NEXT);
}

_public_
int knot_db_lmdb_iter_del(knot_db_iter_t *iter)
{
	MDB_cursor *cursor = iter;

	int ret = mdb_cursor_del(cursor, 0);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

static int iter_key(knot_db_iter_t *iter, knot_db_val_t *key)
{
	MDB_cursor *cursor = iter;

	MDB_val mdb_key, mdb_val;
	int ret = mdb_cursor_get(cursor, &mdb_key, &mdb_val, MDB_GET_CURRENT);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	key->data = mdb_key.mv_data;
	key->len  = mdb_key.mv_size;
	return KNOT_EOK;
}

static int iter_val(knot_db_iter_t *iter, knot_db_val_t *val)
{
	MDB_cursor *cursor = iter;

	MDB_val mdb_key, mdb_val;
	int ret = mdb_cursor_get(cursor, &mdb_key, &mdb_val, MDB_GET_CURRENT);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	val->data = mdb_val.mv_data;
	val->len  = mdb_val.mv_size;
	return KNOT_EOK;
}

static void iter_finish(knot_db_iter_t *iter)
{
	if (iter == NULL) {
		return;
	}

	MDB_cursor *cursor = iter;
	mdb_cursor_close(cursor);
}

static int find(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	knot_db_iter_t *iter = iter_begin(txn, KNOT_DB_NOOP);
	if (iter == NULL) {
		return KNOT_ERROR;
	}

	int ret = KNOT_EOK;
	if (iter_set(iter, key, flags) == NULL) {
		return KNOT_ENOENT;
	} else {
		ret = iter_val(iter, val);
	}

	iter_finish(iter);
	return ret;
}

static int insert(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	struct lmdb_env *env = txn->db;

	MDB_val db_key = { key->len, key->data };
	MDB_val data = { val->len, val->data };

	/* Reserve if only size is declared. */
	unsigned mdb_flags = 0;
	if (val->len > 0 && val->data == NULL) {
		mdb_flags |= MDB_RESERVE;
	}

	int ret = mdb_put(txn->txn, env->dbi, &db_key, &data, mdb_flags);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	/* Update the result. */
	val->data = data.mv_data;
	val->len = data.mv_size;

	return KNOT_EOK;
}

static int del(knot_db_txn_t *txn, knot_db_val_t *key)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = { key->len, key->data };
	MDB_val data = { 0, NULL };

	int ret = mdb_del(txn->txn, env->dbi, &db_key, &data);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

_public_
int knot_db_lmdb_del_exact(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = { key->len, key->data };
	MDB_val data = { val->len, val->data };

	int ret = mdb_del(txn->txn, env->dbi, &db_key, &data);
	if (ret != MDB_SUCCESS) {
		return lmdb_error_to_knot(ret);
	}

	return KNOT_EOK;
}

_public_
size_t knot_db_lmdb_get_mapsize(knot_db_t *db)
{
	struct lmdb_env *env = db;
	MDB_envinfo info;
	if (mdb_env_info(env->env, &info) != MDB_SUCCESS) {
		return 0;
	}

	return info.me_mapsize;
}

// you should SUM all the usages of DBs sharing one mapsize
_public_
size_t knot_db_lmdb_get_usage(knot_db_t *db)
{
	struct lmdb_env *env = db;
	knot_db_txn_t txn;
	knot_db_lmdb_txn_begin(db, &txn, NULL, KNOT_DB_RDONLY);
	MDB_stat st;
	if (mdb_stat(txn.txn, env->dbi, &st) != MDB_SUCCESS) {
		txn_abort(&txn);
		return 0;
	}
	txn_abort(&txn);

	size_t pgs_used = st.ms_branch_pages + st.ms_leaf_pages + st.ms_overflow_pages;

	return (pgs_used * st.ms_psize);
}

_public_
const knot_db_api_t *knot_db_lmdb_api(void)
{
	static const knot_db_api_t api = {
		"lmdb",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, clear, find, insert, del,
		iter_begin, iter_set, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
