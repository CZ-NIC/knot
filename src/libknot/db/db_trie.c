/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/db/db_trie.h"
#include "contrib/hat-trie/hat-trie.h"
#include "contrib/mempattern.h"

static int init(knot_db_t **db, knot_mm_t *mm, void *arg)
{
	if (db == NULL || arg == NULL) {
		return KNOT_EINVAL;
	}

	struct knot_db_trie_opts *opts = arg;
	UNUSED(opts);
	hattrie_t *trie = hattrie_create(mm);
	if (!trie) {
		return KNOT_ENOMEM;
	}

	*db = trie;

	return KNOT_EOK;
}

static void deinit(knot_db_t *db)
{
	hattrie_free((hattrie_t *)db);
}

static int txn_begin(knot_db_t *db, knot_db_txn_t *txn, unsigned flags)
{
	txn->txn = (void *)(size_t)flags;
	txn->db  = db;
	return KNOT_EOK; /* N/A */
}

static int txn_commit(knot_db_txn_t *txn)
{
	return KNOT_EOK;
}

static void txn_abort(knot_db_txn_t *txn)
{
}

static int count(knot_db_txn_t *txn)
{
	return hattrie_weight((hattrie_t *)txn->db);
}

static int clear(knot_db_txn_t *txn)
{
	hattrie_clear((hattrie_t *)txn->db);

	return KNOT_EOK;
}

static int find(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	value_t *ret = hattrie_tryget((hattrie_t *)txn->db, key->data, key->len);
	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t); /* Trie doesn't support storing length. */
	return KNOT_EOK;
}

static int insert(knot_db_txn_t *txn, knot_db_val_t *key, knot_db_val_t *val, unsigned flags)
{
	/* No flags supported. */
	if (flags != 0) {
		return KNOT_ENOTSUP;
	}

	value_t *ret = hattrie_get((hattrie_t *)txn->db, key->data, key->len);
	if (ret == NULL) {
		return KNOT_ENOMEM;
	}

	*ret = val->data;
	return KNOT_EOK;
}

static int del(knot_db_txn_t *txn, knot_db_val_t *key)
{
	return hattrie_del((hattrie_t *)txn->db, key->data, key->len);
}

static knot_db_iter_t *iter_begin(knot_db_txn_t *txn, unsigned flags)
{
	flags &= ~KNOT_DB_SORTED;

	/* No operations other than begin are supported right now. */
	if (flags != 0) {
		return NULL;
	}

	return hattrie_iter_begin((hattrie_t *)txn->db);
}

static knot_db_iter_t *iter_seek(knot_db_iter_t *iter, knot_db_val_t *key, unsigned flags)
{
	assert(0);
	return NULL; /* ENOTSUP */
}

static knot_db_iter_t *iter_next(knot_db_iter_t *iter)
{
	hattrie_iter_next((hattrie_iter_t *)iter);
	if (hattrie_iter_finished((hattrie_iter_t *)iter)) {
		hattrie_iter_free((hattrie_iter_t *)iter);
		return NULL;
	}

	return iter;
}

static int iter_key(knot_db_iter_t *iter, knot_db_val_t *val)
{
	val->data = (void *)hattrie_iter_key((hattrie_iter_t *)iter, &val->len);
	if (val->data == NULL) {
		return KNOT_ENOENT;
	}

	return KNOT_EOK;
}

static int iter_val(knot_db_iter_t *iter, knot_db_val_t *val)
{
	value_t *ret = hattrie_iter_val((hattrie_iter_t *)iter);
	if (ret == NULL) {
		return KNOT_ENOENT;
	}

	val->data = *ret;
	val->len  = sizeof(value_t);
	return KNOT_EOK;
}

static void iter_finish(knot_db_iter_t *iter)
{
	hattrie_iter_free((hattrie_iter_t *)iter);
}

_public_
const knot_db_api_t *knot_db_trie_api(void)
{
	static const knot_db_api_t api = {
		"hattrie",
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, clear, find, insert, del,
		iter_begin, iter_seek, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
