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

#include "knot/journal/knot_lmdb.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h> // snprintf
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "contrib/wire_ctx.h"
#include "libknot/dname.h"
#include "libknot/endian.h"
#include "libknot/error.h"

#define LMDB_DIR_MODE   0770
#define LMDB_FILE_MODE  0660

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

void knot_lmdb_init(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
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
	pthread_mutex_init(&db->opening_mutex, NULL);
	if (!db->static_opts_specified) {
		db->maxdbs = 0;
		db->maxreaders = 126/* = contrib/lmdb/mdb.c DEFAULT_READERS */;
		db->dbname = NULL;
	}
}

static bool lmdb_stat(const char *lmdb_path, struct stat *st)
{
	char data_mdb[strlen(lmdb_path) + 10];
	snprintf(data_mdb, sizeof(data_mdb), "%s/data.mdb", lmdb_path);
	return (stat(data_mdb, st) == 0 && st->st_size > 0);
}

bool knot_lmdb_exists(knot_lmdb_db_t *db)
{
	if (db->env != NULL) {
		return true;
	}
	if (db->path == NULL) {
		return false;
	}
	struct stat unused;
	return lmdb_stat(db->path, &unused);
}

static int fix_mapsize(knot_lmdb_db_t *db)
{
	if (db->mapsize == 0) {
		struct stat st;
		if (!lmdb_stat(db->path, &st)) {
			return KNOT_ENOENT;
		}
		db->mapsize = st.st_size * 2; // twice the size as DB might grow while we read it
		db->env_flags |= MDB_RDONLY;
	}
	return KNOT_EOK;
}

static int _open(knot_lmdb_db_t *db)
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

	ret = mkdir(db->path, LMDB_DIR_MODE);
	if (ret < 0 && errno != EEXIST) {
		return -errno;
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
	int ret = _open(db);
	pthread_mutex_unlock(&db->opening_mutex);
	return ret;
}

static void _close(knot_lmdb_db_t *db)
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
	_close(db);
	pthread_mutex_unlock(&db->opening_mutex);
}

static int _reinit(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
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
	int ret = _reinit(db, path, mapsize, env_flags);
	pthread_mutex_unlock(&db->opening_mutex);
	return ret;
}

int knot_lmdb_reconfigure(knot_lmdb_db_t *db, const char *path, size_t mapsize, unsigned env_flags)
{
	pthread_mutex_lock(&db->opening_mutex);
	int ret = _reinit(db, path, mapsize, env_flags);
	if (ret != KNOT_EOK) {
		_close(db);
		ret = _reinit(db, path, mapsize, env_flags);
		if (ret == KNOT_EOK) {
			ret = _open(db);
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
			txn->cursor = false;
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
		txn->cursor = false;
	}
	txn->ret = mdb_txn_commit(txn->txn);
	err_to_knot(&txn->ret);
	if (txn->ret == KNOT_EOK) {
		txn->opened = false;
	} else {
		knot_lmdb_abort(txn);
	}
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

bool knot_lmdb_find(knot_lmdb_txn_t *txn, MDB_val *what, knot_lmdb_find_t how)
{
	if (!txn_semcheck(txn) || !init_cursor(txn) || !txn_enomem(txn, what)) {
		return false;
	}
	txn->cur_key.mv_size = what->mv_size;
	txn->cur_key.mv_data = what->mv_data;
	txn->cur_val.mv_size = 0;
	txn->cur_val.mv_data = NULL;
	bool succ = curget(txn, how == KNOT_LMDB_EXACT ? MDB_SET : MDB_SET_RANGE);
	if (how == KNOT_LMDB_LEQ && txn->ret == KNOT_EOK) {
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

	return succ;
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

bool knot_lmdb_is_prefix_of(MDB_val *prefix, MDB_val *of)
{
	return prefix->mv_size <= of->mv_size &&
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

void knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val)
{
	if (txn_semcheck(txn) && txn_enomem(txn, key)) {
		unsigned flags = (val->mv_size > 0 && val->mv_data == NULL ? MDB_RESERVE : 0);
		txn->ret = mdb_put(txn->txn, txn->db->dbi, key, val, flags);
		err_to_knot(&txn->ret);
	}
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
	size_t tmp;

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
		}
	}
	va_end(arg);

	// second, alloc the key and fill it
	key.mv_data = malloc(key.mv_size);
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

bool knot_lmdb_unmake_key(void *key_data, size_t key_len, const char *format, ...)
{
	va_list arg;
	wire_ctx_t wire = wire_ctx_init(key_data, key_len);
	va_start(arg, format);
	for (const char *f = format; *f != '\0' && wire.error == KNOT_EOK && wire_ctx_available(&wire) > 0; f++) {
		void *tmp = va_arg(arg, void *);
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
			if (tmp != NULL) {
				memcpy(tmp, wire.position, va_arg(arg, size_t));
			} else {
				wire_ctx_skip(&wire, va_arg(arg, size_t));
			}
			break;
		}
	}
	va_end(arg);
	return (wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);
}
