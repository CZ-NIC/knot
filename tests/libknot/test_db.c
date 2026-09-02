/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <tap/basic.h>
#include <tap/files.h>

#include "knot/conf/migration.h"
#include "libknot/libknot.h"
#include "contrib/files.h"
#include "contrib/mempattern.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/string.h"
#include "contrib/ucw/mempool.h"

/* UCW array sorting defines. */
#define ASORT_PREFIX(X) str_key_##X
#define ASORT_KEY_TYPE char*
#define ASORT_LT(x, y) (strcmp((x), (y)) < 0)
#include "contrib/ucw/array-sort.h"

/* Constants. */
#define KEY_MAXLEN 64
#define KEY_SET(key, str) key.data = (str); key.len = strlen(str) + 1

/*! \brief Generate random key. */
static const char *alphabet = "abcdefghijklmn0123456789";
static char *str_key_rand(size_t len, knot_mm_t *pool)
{
	char *s = mm_calloc(pool, len, sizeof(char));
	for (unsigned i = 0; i < len - 1; ++i) {
		s[i] = alphabet[rand() % strlen(alphabet)];
	}
	return s;
}

static void knot_db_test_set(unsigned nkeys, char **keys, void *opts,
                            const knot_db_api_t *api, knot_mm_t *pool)
{
	if (api == NULL) {
		skip("API not compiled in");
		return;
	}

	/* Create database */
	knot_db_t *db = NULL;
	int ret = api->init(&db, pool, opts);
	ok(ret == KNOT_EOK && db != NULL, "%s: create", api->name);

	/* Start WR transaction. */
	knot_db_txn_t txn;
	ret = api->txn_begin(db, &txn, 0);
	is_int(KNOT_EOK, ret, "%s: txn_begin(WR)", api->name);

	/* Insert keys */
	knot_db_val_t key, val;
	bool passed = true;
	for (unsigned i = 0; i < nkeys; ++i) {
		KEY_SET(key, keys[i]);
		val.len = sizeof(void*);
		val.data = &key.data;

		ret = api->insert(&txn, &key, &val, 0);
		if (ret != KNOT_EOK && ret != KNOT_EEXIST) {
			passed = false;
			break;
		}
	}
	ok(passed, "%s: insert", api->name);

	/* Commit WR transaction. */
	ret = api->txn_commit(&txn);
	is_int(KNOT_EOK, ret, "%s: txn_commit(WR)", api->name);

	/* Start RD transaction. */
	ret = api->txn_begin(db, &txn, KNOT_DB_RDONLY);
	is_int(KNOT_EOK, ret, "%s: txn_begin(RD)", api->name);

	/* Lookup all keys */
	passed = true;
	for (unsigned i = 0; i < nkeys; ++i) {
		KEY_SET(key, keys[i]);

		ret = api->find(&txn, &key, &val, 0);
		if (ret != KNOT_EOK) {
			passed = false;
			break;
		}

		const char **stored_key = val.data;
		if (strcmp(*stored_key, keys[i]) != 0) {
			diag("%s: mismatch on element '%u'", api->name, i);
			passed = false;
			break;
		}
	}
	ok(passed, "%s: lookup all keys", api->name);

	/* Fetch dataset size. */
	int db_size = api->count(&txn);
	ok(db_size > 0 && db_size <= nkeys, "%s: count %d", api->name, db_size);

	/* Unsorted iteration */
	int iterated = 0;
	knot_db_iter_t *it = api->iter_begin(&txn, 0);
	while (it != NULL) {
		++iterated;
		it = api->iter_next(it);
	}
	api->iter_finish(it);
	is_int(db_size, iterated, "%s: unsorted iteration", api->name);

	/* Sorted iteration. */
	char first_key[KEY_MAXLEN] = { '\0' };
	char second_key[KEY_MAXLEN] = { '\0' };
	char last_key[KEY_MAXLEN] = { '\0' };
	char key_buf[KEY_MAXLEN] = {'\0'};
	iterated = 0;
	memset(&key, 0, sizeof(key));
	it = api->iter_begin(&txn, KNOT_DB_SORTED);
	while (it != NULL) {
		api->iter_key(it, &key);
		if (iterated > 0) { /* Only if previous exists. */
			if (strcmp(key_buf, key.data) > 0) {
				diag("%s: iter_sort '%s' <= '%s' FAIL\n",
				     api->name, key_buf, (const char *)key.data);
				break;
			}
			if (iterated == 1) {
				memcpy(second_key, key.data, key.len);
			}
		} else {
			memcpy(first_key, key.data, key.len);
		}
		++iterated;
		memcpy(key_buf, key.data, key.len);
		it = api->iter_next(it);
	}
	strlcpy(last_key, key_buf, sizeof(last_key));
	is_int(db_size, iterated, "%s: sorted iteration", api->name);
	api->iter_finish(it);

	/* Interactive iteration. */
	it = api->iter_begin(&txn, KNOT_DB_NOOP);
	if (it != NULL) { /* If supported. */
		ret = 0;
		/* Check if first and last keys are reachable */
		it = api->iter_seek(it, NULL, KNOT_DB_FIRST);
		ret += api->iter_key(it, &key);
		is_string(first_key, key.data, "%s: iter_set(FIRST)", api->name);
		/* Check left/right iteration. */
		it = api->iter_seek(it, &key, KNOT_DB_NEXT);
		ret += api->iter_key(it, &key);
		is_string(second_key, key.data, "%s: iter_set(NEXT)", api->name);
		it = api->iter_seek(it, &key, KNOT_DB_PREV);
		ret += api->iter_key(it, &key);
		is_string(first_key, key.data, "%s: iter_set(PREV)", api->name);
		it = api->iter_seek(it, &key, KNOT_DB_LAST);
		ret += api->iter_key(it, &key);
		is_string(last_key, key.data, "%s: iter_set(LAST)", api->name);
		/* Check if prev(last_key + 1) is the last_key */
		strlcpy(key_buf, last_key, sizeof(key_buf));
		key_buf[0] += 1;
		KEY_SET(key, key_buf);
		it = api->iter_seek(it, &key, KNOT_DB_LEQ);
		ret += api->iter_key(it, &key);
		is_string(last_key, key.data, "%s: iter_set(LEQ)", api->name);
		/* Check if next(first_key - 1) is the first_key */
		strlcpy(key_buf, first_key, sizeof(key_buf));
		key_buf[0] -= 1;
		KEY_SET(key, key_buf);
		it = api->iter_seek(it, &key, KNOT_DB_GEQ);
		ret += api->iter_key(it, &key);
		is_string(first_key, key.data, "%s: iter_set(GEQ)", api->name);
		api->iter_finish(it);
		is_int(ret, 0, "%s: iter_* error codes", api->name);
	}
	api->txn_abort(&txn);

	/* Deleting during iteration. */
	const uint8_t DEL_MAX_CNT = 3;
	api->txn_begin(db, &txn, 0);
	api->clear(&txn);
	for (uint8_t i = 0; i < DEL_MAX_CNT; ++i) {
		key.data = &i;
		key.len = sizeof(i);
		val.data = NULL;
		val.len = 0;

		ret = api->insert(&txn, &key, &val, 0);
		is_int(KNOT_EOK, ret, "%s: add key '%u'", api->name, i);
	}
	it = api->iter_begin(&txn, KNOT_DB_NOOP);
	if (it != NULL) { /* If supported. */
		is_int(DEL_MAX_CNT, api->count(&txn), "%s: key count before", api->name);
		it = api->iter_seek(it, NULL, KNOT_DB_FIRST);
		uint8_t pos = 0;
		while (it != NULL) {
			ret = api->iter_key(it, &key);
			is_int(KNOT_EOK, ret, "%s: iter key before del", api->name);
			is_int(pos, ((uint8_t *)(key.data))[0], "%s: iter compare key '%u'",
			       api->name, pos);

			ret = knot_db_lmdb_iter_del(it);
			is_int(KNOT_EOK, ret, "%s: iter del", api->name);

			it = api->iter_next(it);

			ret = api->iter_key(it, &key);
			if (++pos < DEL_MAX_CNT) {
				is_int(KNOT_EOK, ret, "%s: iter key after del", api->name);
				is_int(pos, ((uint8_t *)key.data)[0], "%s: iter compare key '%u",
				       api->name, pos);
			} else {
				is_int(KNOT_EINVAL, ret, "%s: iter key after del", api->name);
			}
		}
		api->iter_finish(it);
		is_int(0, api->count(&txn), "%s: key count after", api->name);
	}
	api->txn_abort(&txn);

	/* Clear database and recheck. */
	ret =  api->txn_begin(db, &txn, 0);
	ret += api->clear(&txn);
	ret += api->txn_commit(&txn);
	is_int(0, ret, "%s: clear()", api->name);

	/* Check if the database is empty. */
	api->txn_begin(db, &txn, KNOT_DB_RDONLY);
	db_size = api->count(&txn);
	is_int(0, db_size, "%s: count after clear = %d", api->name, db_size);
	api->txn_abort(&txn);

	api->deinit(db);
}

#if !EMBEDDED_LMDB
#include "contrib/lmdb/emb_prefix.h" // Renames included mdb_* symbols to emb_mdb_* ones.
#endif
#include "contrib/lmdb/lmdb.h"

static void knot_db_lmdb_migration(const char *test_dir)
{
	char *db_dir = sprintf_alloc("%s/db_old", test_dir);
	int ret = make_dir(db_dir, LMDB_DIR_MODE, true);
	ok(ret == KNOT_EOK, "make database directory");

	int lmdb_major, lmdb_minor, lmdb_patch;
	(void)mdb_version(&lmdb_major, &lmdb_minor, &lmdb_patch);
	ok(lmdb_major == 0 && lmdb_minor == 9 && lmdb_patch == 35, "embedded LMDB version");

	// Always uses embedded LMDB, either via emb_mdb_* or via mdb_* if embedded enabled globally.
	MDB_env *env;
	MDB_txn *txn;
	MDB_dbi dbi;
	int rc = mdb_env_create(&env);
	if (rc == MDB_SUCCESS) {
		rc = mdb_env_open(env, db_dir, 0, LMDB_FILE_MODE);
		if (rc == MDB_SUCCESS) {
			rc = mdb_txn_begin(env, NULL, 0, &txn);
			if (rc == MDB_SUCCESS) {
				rc = mdb_open(txn, NULL, 0, &dbi);
				mdb_close(env, dbi);
			}
			mdb_txn_abort(txn);
		}
		mdb_env_close(env);
	}
	ok(rc == MDB_SUCCESS, "create old LMDB database");

	struct knot_db_lmdb_opts lmdb_opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.path = db_dir;
	const knot_db_api_t *api = knot_db_lmdb_api();

	// Indirectly used mdb_* functions, either external or embedded if enabled globally.
	knot_db_t *db = NULL;
	ret = api->init(&db, NULL, &lmdb_opts);
	if (ret == KNOT_EMALF) {
		ret = migrate_lmdb(db_dir, false);
		ok(ret == KNOT_EOK, "migration success");
		if (ret == KNOT_EOK) {
			ret = api->init(&db, NULL, &lmdb_opts);
		}
	}
	ok(ret == KNOT_EOK, "open database success");
	api->deinit(db);

	free(db_dir);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	knot_mm_t pool;
	mm_ctx_mempool(&pool, MM_DEFAULT_BLKSIZE);

	char *dbid = test_mkdtemp();
	ok(dbid != NULL, "make temporary directory");

	/* Random keys. */
	unsigned nkeys = 10000;
	char **keys = mm_alloc(&pool, sizeof(char*) * nkeys);
	for (unsigned i = 0; i < nkeys; ++i) {
		keys[i] = str_key_rand(KEY_MAXLEN, &pool);
	}

	/* Sort random keys. */
	str_key_sort(keys, nkeys);

	/* Execute test set for all backends. */
	struct knot_db_lmdb_opts lmdb_opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.path = dbid;
	struct knot_db_trie_opts trie_opts = KNOT_DB_TRIE_OPTS_INITIALIZER;
	knot_db_test_set(nkeys, keys, &lmdb_opts, knot_db_lmdb_api(), &pool);
	knot_db_test_set(nkeys, keys, &trie_opts, knot_db_trie_api(), &pool);

	/* Test LMDB migration. */
	knot_db_lmdb_migration(dbid);

	/* Cleanup. */
	mp_delete(pool.ctx);
	test_rm_rf(dbid);
	free(dbid);

	return 0;
}
