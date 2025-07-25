/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdarg.h>
#include <stdio.h> // snprintf
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "knot/journal/knot_lmdb.h"

#include "knot/conf/conf.h"
#include "contrib/files.h"
#include "contrib/time.h"
#include "contrib/wire_ctx.h"
#include "libknot/dname.h"
#include "libknot/endian.h"
#include "libknot/error.h"

#define READER_LOCK_CLEAN_MAX_FREQ 3 // minimal interval between reader-lock-table cleanups

static void err_to_knot(int *err)
{
	switch (*err) {
	case MDB_SUCCESS:
		*err = KNOT_EOK;
		break;
	case MDB_NOTFOUND:
		*err = KNOT_ENOENT;
		break;
	case MDB_TXN_FULL:
		*err = KNOT_ELIMIT;
		break;
	case MDB_MAP_FULL:
	case ENOSPC:
		*err = KNOT_ESPACE;
		break;
	default:
		*err = (*err < 0 ? *err : -*err);
	}
}

void knot_lmdb_init(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags, const char *dbname)
{
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
	env_flags |= MDB_WRITEMAP;
#endif
	db->env = NULL;
	db->path = strdup(path);
	db->mapsize = mapsize;
	db->env_flags = env_flags;
	db->dbname = dbname;
	pthread_mutex_init(&db->opening_mutex, NULL);
	db->maxdbs = 2;
	db->maxreaders = conf_lmdb_readers(conf());
	db->last_readlock_clean = 0;
}

static int lmdb_stat(const char *lmdb_path, struct stat *st)
{
	char data_mdb[strlen(lmdb_path) + 10];
	(void)snprintf(data_mdb, sizeof(data_mdb), "%s/data.mdb", lmdb_path);
	if (stat(data_mdb, st) == 0) {
		return st->st_size > 0 ? KNOT_EOK : KNOT_ENODB;
	} else if (errno == ENOENT) {
		return KNOT_ENODB;
	} else {
		return knot_map_errno();
	}
}

int knot_lmdb_exists(knot_lmdb_db_t *db)
{
	if (db->env != NULL) {
		return KNOT_EOK;
	}
	if (db->path == NULL) {
		return KNOT_ENODB;
	}
	struct stat unused;
	return lmdb_stat(db->path, &unused);
}

static int fix_mapsize(knot_lmdb_db_t *db)
{
	if (db->mapsize == 0) {
		struct stat st;
		int ret = lmdb_stat(db->path, &st);
		if (ret != KNOT_EOK) {
			return ret;
		}
		db->mapsize = st.st_size * 2; // twice the size as DB might grow while we read it
		db->env_flags |= MDB_RDONLY;
	}
	return KNOT_EOK;
}

size_t knot_lmdb_copy_size(knot_lmdb_db_t *to_copy)
{
	size_t copy_size = 1048576;
	struct stat st;
	if (lmdb_stat(to_copy->path, &st) == KNOT_EOK) {
		copy_size += st.st_size * 2;
	}
	return copy_size;
}

static int lmdb_open(knot_lmdb_db_t *db)
{
	MDB_txn *init_txn = NULL;

	if (db->env != NULL) {
		return KNOT_EOK;
	}

	if (db->path == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = fix_mapsize(db);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = make_dir(db->path, LMDB_DIR_MODE, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		return KNOT_ERROR;
	}
	size_t mapsize = (db->mapsize / page_size + 1) * page_size;

	ret = mdb_env_create(&db->env);
	if (ret != MDB_SUCCESS) {
		err_to_knot(&ret);
		return ret;
	}

	ret = mdb_env_set_mapsize(db->env, mapsize);
	if (ret == MDB_SUCCESS) {
		ret = mdb_env_set_maxdbs(db->env, db->maxdbs);
	}
	if (ret == MDB_SUCCESS) {
		ret = mdb_env_set_maxreaders(db->env, db->maxreaders);
	}
	if (ret == MDB_SUCCESS) {
		ret = mdb_env_open(db->env, db->path, db->env_flags, LMDB_FILE_MODE);
	}
	if (ret == MDB_SUCCESS) {
		unsigned init_txn_flags = (db->env_flags & MDB_RDONLY);
		ret = mdb_txn_begin(db->env, NULL, init_txn_flags, &init_txn);
		if (ret == MDB_READERS_FULL) {
			int cleared = 0;
			ret = mdb_reader_check(db->env, &cleared);
			if (ret == MDB_SUCCESS) {
				ret = mdb_txn_begin(db->env, NULL, init_txn_flags, &init_txn);
			}
		}
	}
	if (ret == MDB_SUCCESS) {
		ret = mdb_dbi_open(init_txn, db->dbname, MDB_CREATE, &db->dbi);
	}
	if (ret == MDB_SUCCESS) {
		ret = mdb_txn_commit(init_txn);
	}

	if (ret != MDB_SUCCESS) {
		if (init_txn != NULL) {
			mdb_txn_abort(init_txn);
		}
		mdb_env_close(db->env);
		db->env = NULL;
	}
	err_to_knot(&ret);
	return ret;
}

int knot_lmdb_open(knot_lmdb_db_t *db)
{
	pthread_mutex_lock(&db->opening_mutex);
	int ret = lmdb_open(db);
	pthread_mutex_unlock(&db->opening_mutex);
	return ret;
}

static void lmdb_close(knot_lmdb_db_t *db)
{
	if (db->env != NULL) {
		mdb_dbi_close(db->env, db->dbi);
		mdb_env_close(db->env);
		db->env = NULL;
	}
}

void knot_lmdb_close(knot_lmdb_db_t *db)
{
	pthread_mutex_lock(&db->opening_mutex);
	lmdb_close(db);
	pthread_mutex_unlock(&db->opening_mutex);
}

static int lmdb_reinit(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
{
#ifdef __OpenBSD__
	env_flags |= MDB_WRITEMAP;
#endif
	if (strcmp(db->path, path) == 0 && db->mapsize == mapsize && db->env_flags == env_flags) {
		return KNOT_EOK;
	}
	if (db->env != NULL) {
		return KNOT_EISCONN;
	}
	free(db->path);
	db->path = strdup(path);
	db->mapsize = mapsize;
	db->env_flags = env_flags;
	return KNOT_EOK;
}

int knot_lmdb_reinit(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
{
	pthread_mutex_lock(&db->opening_mutex);
	int ret = lmdb_reinit(db, path, mapsize, env_flags);
	pthread_mutex_unlock(&db->opening_mutex);
	return ret;
}

int knot_lmdb_reconfigure(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
{
	pthread_mutex_lock(&db->opening_mutex);
	int ret = lmdb_reinit(db, path, mapsize, env_flags);
	if (ret != KNOT_EOK) {
		lmdb_close(db);
		ret = lmdb_reinit(db, path, mapsize, env_flags);
		if (ret == KNOT_EOK) {
			ret = lmdb_open(db);
		}
	}
	pthread_mutex_unlock(&db->opening_mutex);
	return ret;
}

void knot_lmdb_deinit(knot_lmdb_db_t *db)
{
	knot_lmdb_close(db);
	pthread_mutex_destroy(&db->opening_mutex);
	free(db->path);
}

void knot_lmdb_begin(knot_lmdb_db_t *db, knot_lmdb_txn_t *txn, bool rw)
{
	uint64_t next_readlock_clean = db->last_readlock_clean + READER_LOCK_CLEAN_MAX_FREQ, now = knot_time();
	if (rw && next_readlock_clean < now) { // Cleaning up reader lock table can be done occasionally. Opening a RW txn seems a good occasion.
		int cleared = 0, _unused_ ret = mdb_reader_check(db->env, &cleared);
		db->last_readlock_clean = now;
	}

	txn->ret = mdb_txn_begin(db->env, NULL, rw ? 0 : MDB_RDONLY, &txn->txn);
	err_to_knot(&txn->ret);
	if (txn->ret == KNOT_EOK) {
		txn->opened = true;
		txn->db = db;
		txn->is_rw = rw;
	}
}

void knot_lmdb_abort(knot_lmdb_txn_t *txn)
{
	if (txn->opened) {
		if (txn->cursor != NULL) {
			mdb_cursor_close(txn->cursor);
			txn->cursor = NULL;
		}
		mdb_txn_abort(txn->txn);
		txn->opened = false;
	}
}

static bool txn_semcheck(knot_lmdb_txn_t *txn)
{
	if (!txn->opened && txn->ret == KNOT_EOK) {
		txn->ret = KNOT_ESEMCHECK;
	}
	if (txn->ret != KNOT_EOK) {
		knot_lmdb_abort(txn);
		return false;
	}
	return true;
}

void knot_lmdb_commit(knot_lmdb_txn_t *txn)
{
	if (!txn_semcheck(txn)) {
		return;
	}
	if (txn->cursor != NULL) {
		mdb_cursor_close(txn->cursor);
		txn->cursor = NULL;
	}
	txn->ret = mdb_txn_commit(txn->txn);
	err_to_knot(&txn->ret);
	txn->opened = false;
}

// save the programmer's frequent checking for ENOMEM when creating search keys
static bool txn_enomem(knot_lmdb_txn_t *txn, const MDB_val *tocheck)
{
	if (tocheck->mv_data == NULL) {
		txn->ret = KNOT_ENOMEM;
		knot_lmdb_abort(txn);
		return false;
	}
	return true;
}

static bool init_cursor(knot_lmdb_txn_t *txn)
{
	if (txn->cursor == NULL) {
		txn->ret = mdb_cursor_open(txn->txn, txn->db->dbi, &txn->cursor);
		err_to_knot(&txn->ret);
		if (txn->ret != KNOT_EOK) {
			knot_lmdb_abort(txn);
			return false;
		}
	}
	return true;
}

static bool curget(knot_lmdb_txn_t *txn, MDB_cursor_op op)
{
	txn->ret = mdb_cursor_get(txn->cursor, &txn->cur_key, &txn->cur_val, op);
	err_to_knot(&txn->ret);
	if (txn->ret == KNOT_ENOENT) {
		txn->ret = KNOT_EOK;
		return false;
	}
	return (txn->ret == KNOT_EOK);
}

static int mdb_val_clone(const MDB_val *orig, MDB_val *clone)
{
	clone->mv_data = malloc(orig->mv_size);
	if (clone->mv_data == NULL) {
		return KNOT_ENOMEM;
	}
	clone->mv_size = orig->mv_size;
	memcpy(clone->mv_data, orig->mv_data, clone->mv_size);
	return KNOT_EOK;
}

bool knot_lmdb_find(knot_lmdb_txn_t *txn, MDB_val *what, knot_lmdb_find_t how)
{
	if (!txn_semcheck(txn) || !init_cursor(txn) || !txn_enomem(txn, what)) {
		return false;
	}
	txn->cur_key.mv_size = what->mv_size;
	txn->cur_key.mv_data = what->mv_data;
	txn->cur_val.mv_size = 0;
	txn->cur_val.mv_data = NULL;
	knot_lmdb_find_t cmp = (how & 3);
	bool succ = curget(txn, cmp == KNOT_LMDB_EXACT ? MDB_SET : MDB_SET_RANGE);
	if (cmp == KNOT_LMDB_LEQ && txn->ret == KNOT_EOK) {
		// LEQ is not supported by LMDB, we use GEQ and go back
		if (succ) {
			if (txn->cur_key.mv_size != what->mv_size ||
			    memcmp(txn->cur_key.mv_data, what->mv_data, what->mv_size) != 0) {
				succ = curget(txn, MDB_PREV);
			}
		} else {
			succ = curget(txn, MDB_LAST);
		}
	}

	if ((how & KNOT_LMDB_FORCE) && !succ && txn->ret == KNOT_EOK) {
		txn->ret = KNOT_ENOENT;
	}

	return succ;
}

// this is not bulletproof thread-safe (in case of LMDB fail-teardown, but mostly OK
int knot_lmdb_find_threadsafe(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val, knot_lmdb_find_t how)
{
	assert(how == KNOT_LMDB_EXACT);
	if (key->mv_data == NULL) {
		return KNOT_ENOMEM;
	}
	if (!txn->opened) {
		return KNOT_EINVAL;
	}
	if (txn->ret != KNOT_EOK) {
		return txn->ret;
	}
	MDB_val tmp = { 0 };
	int ret = mdb_get(txn->txn, txn->db->dbi, key, &tmp);
	err_to_knot(&ret);
	if (ret == KNOT_EOK) {
		ret = mdb_val_clone(&tmp, val);
	}
	return ret;
}

bool knot_lmdb_first(knot_lmdb_txn_t *txn)
{
	return txn_semcheck(txn) && init_cursor(txn) && curget(txn, MDB_FIRST);
}

bool knot_lmdb_next(knot_lmdb_txn_t *txn)
{
	if (txn->cursor == NULL && txn->ret == KNOT_EOK) {
		txn->ret = KNOT_EINVAL;
	}
	if (!txn_semcheck(txn)) {
		return false;
	}
	return curget(txn, MDB_NEXT);
}

bool knot_lmdb_is_prefix_of(const MDB_val *prefix, const MDB_val *of)
{
	return prefix->mv_size <= of->mv_size &&
	       memcmp(prefix->mv_data, of->mv_data, prefix->mv_size) == 0;
}

bool knot_lmdb_is_prefix_of2(const MDB_val *prefix, const MDB_val *of, size_t expected_rest)
{
	return prefix->mv_size + expected_rest == of->mv_size &&
	       memcmp(prefix->mv_data, of->mv_data, prefix->mv_size) == 0;
}

void knot_lmdb_del_cur(knot_lmdb_txn_t *txn)
{
	if (txn_semcheck(txn)) {
		txn->ret = mdb_cursor_del(txn->cursor, 0);
		err_to_knot(&txn->ret);
	}
}

void knot_lmdb_del_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix)
{
	knot_lmdb_foreach(txn, prefix) {
		knot_lmdb_del_cur(txn);
	}
}

int knot_lmdb_apply_threadsafe(knot_lmdb_txn_t *txn, const MDB_val *key, bool prefix, lmdb_apply_cb cb, void *ctx)
{
	MDB_cursor *cursor;
	int ret = mdb_cursor_open(txn->txn, txn->db->dbi, &cursor);
	err_to_knot(&ret);
	if (ret != KNOT_EOK) {
		return ret;
	}

	MDB_val getkey = *key, getval = { 0 };
	ret = mdb_cursor_get(cursor, &getkey, &getval, prefix ? MDB_SET_RANGE : MDB_SET);
	err_to_knot(&ret);
	if (ret != KNOT_EOK) {
		mdb_cursor_close(cursor);
		if (prefix && ret == KNOT_ENOENT) {
			return KNOT_EOK;
		}
		return ret;
	}

	if (prefix) {
		while (knot_lmdb_is_prefix_of(key, &getkey) && ret == KNOT_EOK) {
			ret = cb(&getkey, &getval, ctx);
			if (ret == KNOT_EOK) {
				ret = mdb_cursor_get(cursor, &getkey, &getval, MDB_NEXT);
				err_to_knot(&ret);
			}
		}
		if (ret == KNOT_ENOENT) {
			ret = KNOT_EOK;
		}
	} else {
		ret = cb(&getkey, &getval, ctx);
	}
	mdb_cursor_close(cursor);
	return ret;
}

bool knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val)
{
	if (txn_semcheck(txn) && txn_enomem(txn, key)) {
		unsigned flags = (val->mv_size > 0 && val->mv_data == NULL ? MDB_RESERVE : 0);
		txn->ret = mdb_put(txn->txn, txn->db->dbi, key, val, flags);
		err_to_knot(&txn->ret);
	}
	return (txn->ret == KNOT_EOK);
}

int knot_lmdb_quick_insert(knot_lmdb_db_t *db, MDB_val key, MDB_val val)
{
	if (val.mv_data == NULL) {
		free(key.mv_data);
		return KNOT_ENOMEM;
	}
	knot_lmdb_txn_t txn = { 0 };
	knot_lmdb_begin(db, &txn, true);
	knot_lmdb_insert(&txn, &key, &val);
	free(key.mv_data);
	free(val.mv_data);
	knot_lmdb_commit(&txn);
	return txn.ret;
}

int knot_lmdb_copy_prefix(knot_lmdb_txn_t *from, knot_lmdb_txn_t *to, MDB_val *prefix)
{
	knot_lmdb_foreach(to, prefix) {
		knot_lmdb_del_cur(to);
	}
	if (to->ret != KNOT_EOK) {
		return to->ret;
	}
	knot_lmdb_foreach(from, prefix) {
		knot_lmdb_insert(to, &from->cur_key, &from->cur_val);
	}
	return from->ret == KNOT_EOK ? to->ret : from->ret;
}

int knot_lmdb_copy_prefixes(knot_lmdb_db_t *from, knot_lmdb_db_t *to,
                            MDB_val *prefixes, size_t n_prefixes)
{
	if (n_prefixes < 1) {
		return KNOT_EOK;
	}
	if (from == NULL || to == NULL || prefixes == NULL) {
		return KNOT_EINVAL;
	}
	int ret = knot_lmdb_open(from);
	if (ret == KNOT_EOK) {
		ret = knot_lmdb_open(to);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_lmdb_txn_t tr = { 0 }, tw = { 0 };
	knot_lmdb_begin(from, &tr, false);
	knot_lmdb_begin(to, &tw, true);
	for (size_t i = 0; i < n_prefixes && ret == KNOT_EOK; i++) {
		ret = knot_lmdb_copy_prefix(&tr, &tw, &prefixes[i]);
	}
	knot_lmdb_commit(&tw);
	knot_lmdb_commit(&tr);
	return ret == KNOT_EOK ? tw.ret : ret;
}

size_t knot_lmdb_usage(knot_lmdb_txn_t *txn)
{
	if (!txn_semcheck(txn)) {
		return 0;
	}
	MDB_stat st = { 0 };
	txn->ret = mdb_stat(txn->txn, txn->db->dbi, &st);
	err_to_knot(&txn->ret);

	size_t pgs_used = st.ms_branch_pages + st.ms_leaf_pages + st.ms_overflow_pages;
	return (pgs_used * st.ms_psize);
}

static bool make_key_part(void *key_data, size_t key_len, const char *format, va_list arg)
{
	wire_ctx_t wire = wire_ctx_init(key_data, key_len);
	const char *tmp_s;
	const knot_dname_t *tmp_d;
	const void *tmp_v;
	uint64_t tmp_u64;
	size_t tmp;
	int tmp_i;

	for (const char *f = format; *f != '\0'; f++) {
		switch (*f) {
		case 'B':
			wire_ctx_write_u8(&wire, va_arg(arg, int));
			break;
		case 'H':
			wire_ctx_write_u16(&wire, va_arg(arg, int));
			break;
		case 'I':
			wire_ctx_write_u32(&wire, va_arg(arg, uint32_t));
			break;
		case 'L':
			wire_ctx_write_u64(&wire, va_arg(arg, uint64_t));
			break;
		case 'S':
			tmp_s = va_arg(arg, const char *);
			wire_ctx_write(&wire, tmp_s, strlen(tmp_s) + 1);
			break;
		case 'N':
			tmp_d = va_arg(arg, const knot_dname_t *);
			wire_ctx_write(&wire, tmp_d, knot_dname_size(tmp_d));
			break;
		case 'D':
			tmp_v = va_arg(arg, const void *);
			tmp = va_arg(arg, size_t);
			wire_ctx_write(&wire, tmp_v, tmp);
			break;
		case 'T':
			tmp_i = va_arg(arg, int);
			tmp_u64 = va_arg(arg, uint64_t);
			if (tmp_u64 > 0) {
				wire_ctx_write_u8(&wire, tmp_i);
				wire_ctx_write_u64(&wire, tmp_u64);
			}
			break;
		}
	}

	return wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0;
}

MDB_val knot_lmdb_make_key(const char *format, ...)
{
	MDB_val key = { 0 };
	va_list arg;
	const char *tmp_s;
	const knot_dname_t *tmp_d;

	// first, just determine the size of the key
	va_start(arg, format);
	for (const char *f = format; *f != '\0'; f++) {
		switch (*f) {
		case 'B':
			key.mv_size += sizeof(uint8_t);
			(void)va_arg(arg, int); // uint8_t will be promoted to int
			break;
		case 'H':
			key.mv_size += sizeof(uint16_t);
			(void)va_arg(arg, int); // uint16_t will be promoted to int
			break;
		case 'I':
			key.mv_size += sizeof(uint32_t);
			(void)va_arg(arg, uint32_t);
			break;
		case 'L':
			key.mv_size += sizeof(uint64_t);
			(void)va_arg(arg, uint64_t);
			break;
		case 'S':
			tmp_s = va_arg(arg, const char *);
			key.mv_size += strlen(tmp_s) + 1;
			break;
		case 'N':
			tmp_d = va_arg(arg, const knot_dname_t *);
			key.mv_size += knot_dname_size(tmp_d);
			break;
		case 'D':
			(void)va_arg(arg, const void *);
			key.mv_size += va_arg(arg, size_t);
			break;
		case 'T':
			(void)va_arg(arg, int); // uint8_t will be promoted to int
			if (va_arg(arg, uint64_t) > 0) {
				key.mv_size += sizeof(uint8_t);
				key.mv_size += sizeof(uint64_t);
			}
			break;
		}
	}
	va_end(arg);

	// second, alloc the key and fill it
	if (key.mv_size > 0) {
		key.mv_data = malloc(key.mv_size);
	}
	if (key.mv_data == NULL) {
		return key;
	}
	va_start(arg, format);
	bool succ = make_key_part(key.mv_data, key.mv_size, format, arg);
	assert(succ);
	(void)succ;
	va_end(arg);
	return key;
}

bool knot_lmdb_make_key_part(void *key_data, size_t key_len, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	bool succ = make_key_part(key_data, key_len, format, arg);
	va_end(arg);
	return succ;
}

static bool unmake_key_part(const void *key_data, size_t key_len, const char *format, va_list arg)
{
	if (key_data == NULL) {
		return false;
	}
	wire_ctx_t wire = wire_ctx_init_const(key_data, key_len);
	for (const char *f = format; *f != '\0' && wire.error == KNOT_EOK && wire_ctx_available(&wire) > 0; f++) {
		void *tmp = va_arg(arg, void *);
		size_t tmsize;
		switch (*f) {
		case 'B':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint8_t));
			} else {
				*(uint8_t *)tmp = wire_ctx_read_u8(&wire);
			}
			break;
		case 'H':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint16_t));
			} else {
				*(uint16_t *)tmp = wire_ctx_read_u16(&wire);
			}
			break;
		case 'I':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint32_t));
			} else {
				*(uint32_t *)tmp = wire_ctx_read_u32(&wire);
			}
			break;
		case 'L':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint64_t));
			} else {
				*(uint64_t *)tmp = wire_ctx_read_u64(&wire);
			}
			break;
		case 'S':
			if (tmp != NULL) {
				*(const char **)tmp = (const char *)wire.position;
			}
			wire_ctx_skip(&wire, strlen((const char *)wire.position) + 1);
			break;
		case 'N':
			if (tmp != NULL) {
				*(const knot_dname_t **)tmp = (const knot_dname_t *)wire.position;
			}
			wire_ctx_skip(&wire, knot_dname_size((const knot_dname_t *)wire.position));
			break;
		case 'D':
			tmsize = va_arg(arg, size_t);
			if (tmp != NULL) {
				memcpy(tmp, wire.position, tmsize);
			}
			wire_ctx_skip(&wire, tmsize);
			break;
		}
	}
	return (wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);
}

bool knot_lmdb_unmake_key(const void *key_data, size_t key_len, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	bool succ = unmake_key_part(key_data, key_len, format, arg);
	va_end(arg);
	return succ;
}

bool knot_lmdb_unmake_curval(knot_lmdb_txn_t *txn, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	bool succ = unmake_key_part(txn->cur_val.mv_data, txn->cur_val.mv_size, format, arg);
	va_end(arg);
	if (!succ && txn->ret == KNOT_EOK) {
		txn->ret = KNOT_EMALF;
	}
	return succ;
}
