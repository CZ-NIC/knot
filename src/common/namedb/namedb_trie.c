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

#include "libknot/errcode.h"

#include "common/namedb/namedb_trie.h"
#include "common/trie/hat-trie.h"
#include "common/mempattern.h"

static int init(const char *config, knot_namedb_t **db, mm_ctx_t *mm)
{
	if (config != NULL || db == NULL) {
		return KNOT_EINVAL;
	}

	hattrie_t *trie = hattrie_create_n(TRIE_BUCKET_SIZE, mm);
	if (!trie) {
		return KNOT_ENOMEM;
	}

	*db = trie;

	return KNOT_EOK;
}

static void deinit(knot_namedb_t *db)
{
	hattrie_free((hattrie_t *)db);
}

static int txn_begin(knot_namedb_t *db, knot_txn_t *txn, unsigned flags)
{
	txn->txn = (void *)(size_t)flags;
	txn->db  = db;
	return KNOT_EOK; /* N/A */
}

static int txn_commit(knot_txn_t *txn)
{
	/* Rebuild order index only for WR transactions. */
	if ((size_t)txn->txn & KNOT_NAMEDB_RDONLY) {
		return KNOT_EOK;
	}

	hattrie_build_index((hattrie_t *)txn->db);
	return KNOT_EOK;
}

static void txn_abort(knot_txn_t *txn)
{
}

static int count(knot_txn_t *txn)
{
	return hattrie_weight((hattrie_t *)txn->db);
}

static int find(knot_txn_t *txn, knot_val_t *key, knot_val_t *val, unsigned flags)
{
	value_t *ret = hattrie_tryget((hattrie_t *)txn->db, key->data, key->len);
	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t); /* Trie doesn't support storing length. */
	return KNOT_EOK;
}

static int insert(knot_txn_t *txn, knot_val_t *key, knot_val_t *val, unsigned flags)
{
	value_t *ret = hattrie_get((hattrie_t *)txn->db, key->data, key->len);
	if (ret == NULL) {
		return KNOT_ENOMEM;
	}

	*ret = val->data;
	return KNOT_EOK;
}

static int del(knot_txn_t *txn, knot_val_t *key)
{
	return hattrie_del((hattrie_t *)txn->db, key->data, key->len);
}

static knot_iter_t *iter_begin(knot_txn_t *txn, unsigned flags)
{
	return hattrie_iter_begin((hattrie_t *)txn->db, (flags & KNOT_NAMEDB_SORTED));
}

static knot_iter_t *iter_next(knot_iter_t *iter)
{
	hattrie_iter_next((hattrie_iter_t *)iter);
	if (hattrie_iter_finished((hattrie_iter_t *)iter)) {
		hattrie_iter_free((hattrie_iter_t *)iter);
		return NULL;
	}

	return iter;
}

static int iter_key(knot_iter_t *iter, knot_val_t *val)
{
	val->data = (void *)hattrie_iter_key((hattrie_iter_t *)iter, &val->len);
	if (val->data == NULL) {
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

static int iter_val(knot_iter_t *iter, knot_val_t *val)
{
	value_t *ret = hattrie_iter_val((hattrie_iter_t *)iter);
	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t);
	return KNOT_EOK;
}

static void iter_finish(knot_iter_t *iter)
{
	hattrie_iter_free((hattrie_iter_t *)iter);
}

const struct namedb_api *namedb_trie_api(void)
{
	static const struct namedb_api api = {
		"hattrie",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, find, insert, del,
		iter_begin, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
