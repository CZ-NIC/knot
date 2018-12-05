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

#include <stdarg.h>
#include <stdlib.h>

#include "contrib/wire_ctx.h"
#include "libknot/dname.h"
#include "libknot/endian.h"
#include "libknot/error.h"

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

void knot_lmdb_begin(knot_lmdb_db_t *db, knot_lmdb_txn_t *txn)
{
	unsigned flags = (db->txn_flags | (txn->is_rw ? 0 : MDB_RDONLY));
	txn->ret = mdb_txn_begin(db->env, NULL, flags, &txn->txn);
	err_to_knot(&txn->ret);
	if (txn->ret == KNOT_EOK) {
		txn->opened = true;
		txn->db = db;
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
	if (!txn_semcheck(txn) || !init_cursor(txn)) {
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

static bool is_prefix_of(MDB_val *prefix, MDB_val *of)
{
	return prefix->mv_size <= of->mv_size &&
	       memcmp(prefix->mv_data, of->mv_data, prefix->mv_size) == 0;
}


void knot_lmdb_del_prefix(knot_lmdb_txn_t *txn, MDB_val *prefix)
{
	knot_lmdb_foreach(txn, prefix) {
		txn->ret = mdb_cursor_del(txn->cursor, 0);
		err_to_knot(&txn->ret);
	}
}

void knot_lmdb_insert(knot_lmdb_txn_t *txn, MDB_val *key, MDB_val *val)
{
	if (txn_semcheck(txn)) {
		unsigned flags = (val->mv_size > 0 && val->mv_data == NULL ? MDB_RESERVE : 0);
		txn->ret = mdb_put(txn->txn, txn->db->dbi, key, val, flags);
		err_to_knot(&txn->ret);
	}
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

	for (const char *f = format; *f != '\0'; f++) {
		switch (*f) {
		case 'B':
			wire_ctx_write_u8(&wire, va_arg(arg, int));
			break;
		case 'H':
			wire_ctx_write_u16(&wire, htobe16(va_arg(arg, int)));
			break;
		case 'I':
			wire_ctx_write_u32(&wire, htobe32(va_arg(arg, uint32_t)));
			break;
		case 'L':
			wire_ctx_write_u64(&wire, htobe64(va_arg(arg, uint64_t)));
			break;
		case 'S':
			tmp_s = va_arg(arg, const char *);
			wire_ctx_write(&wire, tmp_s, strlen(tmp_s) + 1);
			break;
		case 'D':
			tmp_d = va_arg(arg, const knot_dname_t *);
			wire_ctx_write(&wire, tmp_d, knot_dname_size(tmp_d));
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
		case 'D':
			tmp_d = va_arg(arg, const knot_dname_t *);
			key.mv_size += knot_dname_size(tmp_d);
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
				*(uint16_t *)tmp = be16toh(wire_ctx_read_u16(&wire));
			}
			break;
		case 'I':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint32_t));
			} else {
				*(uint32_t *)tmp = be32toh(wire_ctx_read_u32(&wire));
			}
			break;
		case 'L':
			if (tmp == NULL) {
				wire_ctx_skip(&wire, sizeof(uint64_t));
			} else {
				*(uint64_t *)tmp = be64toh(wire_ctx_read_u64(&wire));
			}
			break;
		case 'S':
			if (tmp != NULL) {
				*(const char **)tmp = (const char *)wire.position;
			}
			wire_ctx_skip(&wire, strlen((const char *)wire.position) + 1);
			break;
		case 'D':
			if (tmp != NULL) {
				*(const knot_dname_t **)tmp = (const knot_dname_t *)wire.position;
			}
			wire_ctx_skip(&wire, knot_dname_size((const knot_dname_t *)wire.position));
			break;
		}
	}
	va_end(arg);
	return (wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);
}






