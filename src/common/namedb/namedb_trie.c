#include "common/namedb/namedb_trie.h"
#include "common-knot/hattrie/hat-trie.h"
#include "libknot/errcode.h"

knot_namedb_t* init(const char *handle, mm_ctx_t *mm)
{
	return NULL; /* NOTIMPL */
}

void deinit(knot_namedb_t *db)
{
}

int txn_begin(knot_namedb_t *db, knot_txn_t *txn, unsigned flags)
{
	return KNOT_ENOTSUP;
}

int txn_commit(knot_txn_t *txn)
{
	return KNOT_ENOTSUP;
}

void txn_abort(knot_txn_t *txn)
{
}

int count(knot_txn_t *txn)
{
	return KNOT_ENOTSUP;
}

int find(knot_txn_t *txn, const knot_dname_t *key, knot_val_t *val, unsigned op)
{
	return KNOT_ENOTSUP;
}

int insert(knot_txn_t *txn, const knot_dname_t *key, knot_val_t *val)
{
	return KNOT_ENOTSUP;
}

int del(knot_txn_t *txn, const knot_dname_t *key)
{
	return KNOT_ENOTSUP;
}

knot_iter_t *iter_begin(knot_txn_t *txn, unsigned flags)
{
	return NULL; /* NOTIMPL */
}

int iter_next(knot_iter_t *iter)
{
	return KNOT_ENOTSUP;
}

const knot_dname_t *iter_key(knot_iter_t *iter)
{
	return NULL; /* NOTIMPL */
}

int iter_val(knot_iter_t *iter, knot_val_t *val)
{
	return KNOT_ENOTSUP;
}

int iter_finish(knot_iter_t *iter)
{
	return KNOT_ENOTSUP;
}

struct namedb_api *namedb_trie_api(void)
{
	static struct namedb_api api = {
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, find, insert, del,
		iter_begin, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}
