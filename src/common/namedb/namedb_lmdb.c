#include <lmdb.h>

#include "common/namedb/namedb_lmdb.h"
#include "libknot/errcode.h"

#define NAME_TO_KEY(key) { knot_dname_size(key), (void *)(key)  }

struct lmdb_env
{
	MDB_dbi dbi;
	MDB_env *env;
	mm_ctx_t *pool;
};

static int dbase_open(struct lmdb_env *env, const char *handle)
{
	int ret = mdb_env_create(&env->env);
	if (ret != 0) {
		return ret;
	}

	ret = mdb_env_open(env->env, handle, 0, 0644);
	if (ret != 0) {
		mdb_env_close(env->env);
		return ret;
	}

	MDB_txn *txn = NULL;
	ret = mdb_txn_begin(env->env, NULL, 0, &txn);
	if (ret != 0) {
		mdb_env_close(env->env);
		return ret;
	}

	ret = mdb_open(txn, NULL, MDB_DUPSORT, &env->dbi);
	if (ret != 0) {
		mdb_txn_abort(txn);
		mdb_env_close(env->env);
		return ret;
	}

	ret = mdb_txn_commit(txn);
	if (ret != 0) {
		mdb_env_close(env->env);
		return ret;
	}

	return 0;
}

static void dbase_close(struct lmdb_env *env)
{
	mdb_close(env->env, env->dbi);
	mdb_env_close(env->env);
}

knot_namedb_t* init(const char *handle, mm_ctx_t *mm)
{
	struct lmdb_env *env = mm_alloc(mm, sizeof(struct lmdb_env));
	if (env == NULL) {
		return NULL;
	}
	memset(env, 0, sizeof(struct lmdb_env));

	int ret = dbase_open(env, handle);
	if (ret != 0) {
		mm_free(mm, env);
		return NULL;
	}

	env->pool = mm;
	return env;
}

void deinit(knot_namedb_t *db)
{
	struct lmdb_env *env = db;

	dbase_close(env);
	mm_free(env->pool, env);
}

int txn_begin(knot_namedb_t *db, knot_txn_t *txn, unsigned flags)
{
	txn->db = db;
	txn->txn = NULL;

	unsigned txn_flags = 0;
	if (flags & NAMEDB_RDONLY) {
		txn_flags |= MDB_RDONLY;
	}

	struct lmdb_env *env = db;
	int ret = mdb_txn_begin(env->env, NULL, txn_flags, (MDB_txn **)&txn->txn);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int txn_commit(knot_txn_t *txn)
{
	int ret = mdb_txn_commit((MDB_txn *)txn->txn);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

void txn_abort(knot_txn_t *txn)
{
	mdb_txn_abort((MDB_txn *)txn->txn);
}

int count(knot_txn_t *txn)
{
	struct lmdb_env *env = txn->db;

	MDB_stat stat;
	int ret = mdb_stat(txn->txn, env->dbi, &stat);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return stat.ms_entries;
}

int find(knot_txn_t *txn, const knot_dname_t *key, knot_val_t *val, unsigned op)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = NAME_TO_KEY(key);
	MDB_val data = { 0, NULL };


	int ret = mdb_get(txn->txn, env->dbi, &db_key, &data);
	if (ret != 0) {
		if (ret == MDB_NOTFOUND) {
			return KNOT_ENOENT;
		} else {
			return KNOT_ERROR;
		}
	}

	val->data = data.mv_data;
	val->len  = data.mv_size;
	return KNOT_EOK;
}

int insert(knot_txn_t *txn, const knot_dname_t *key, knot_val_t *val)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = NAME_TO_KEY(key);
	MDB_val data = { val->len, val->data };

	int ret = mdb_put(txn->txn, env->dbi, &db_key, &data, 0);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int del(knot_txn_t *txn, const knot_dname_t *key)
{
	struct lmdb_env *env = txn->db;
	MDB_val db_key = NAME_TO_KEY(key);
	MDB_val data = { 0, NULL };

	int ret = mdb_del(txn->txn, env->dbi, &db_key, &data);
	if (ret != 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
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

struct namedb_api *namedb_lmdb_api(void)
{
	static struct namedb_api api = {
		init, deinit,
		txn_begin, txn_commit, txn_abort,
		count, find, insert, del,
		iter_begin, iter_next, iter_key, iter_val, iter_finish
	};

	return &api;
}

