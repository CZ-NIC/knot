/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <tap/basic.h>

#include "libknot/common.h"
#include "common/mempool.h"
#include "common/mem.h"
#include "common/namedb/namedb_lmdb.h"
#include "common/namedb/namedb_trie.h"

/* Constants. */
#define KEY_MAXLEN 64
#define KEY_SET(key, str) key.data = (str); key.len = strlen(str) + 1

/*! \brief Generate random key. */
static const char *alphabet = "abcdefghijklmn0123456789";
static char *str_key_rand(size_t len, mm_ctx_t *pool)
{
	char *s = mm_alloc(pool, len);
	memset(s, 0, len);
	for (unsigned i = 0; i < len - 1; ++i) {
		s[i] = alphabet[rand() % strlen(alphabet)];
	}
	return s;
}

/* UCW array sorting defines. */
#define ASORT_PREFIX(X) str_key_##X
#define ASORT_KEY_TYPE char*
#define ASORT_LT(x, y) (strcmp((x), (y)) < 0)
#include "common-knot/array-sort.h"

static void namedb_test_set(unsigned nkeys, char **keys, char *dbid,
                            const struct namedb_api *api, mm_ctx_t *pool)
{
	if (api == NULL) {
		skip("API not compiled in");
		return;
	}

	/* Create database */
	knot_namedb_t *db = NULL;
	int ret = api->init(dbid, &db, pool);
	ok(ret == KNOT_EOK && db != NULL, "%s: create", api->name);

	/* Start WR transaction. */
	knot_txn_t txn;
	ret = api->txn_begin(db, &txn, 0);
	ok(ret == KNOT_EOK, "%s: txn_begin(WR)", api->name);

	/* Insert keys */
	knot_val_t key, val;
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
	ok(ret == KNOT_EOK, "%s: txn_commit(WR)", api->name);

	/* Start RD transaction. */
	ret = api->txn_begin(db, &txn, KNOT_NAMEDB_RDONLY);
	ok(ret == KNOT_EOK, "%s: txn_begin(RD)", api->name);

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
	knot_iter_t *it = api->iter_begin(&txn, 0);
	while (it != NULL) {
		++iterated;
		it = api->iter_next(it);
	}
	api->iter_finish(it);
	is_int(db_size, iterated, "%s: unsorted iteration", api->name);

	/* Sorted iteration. */
	char key_buf[KEY_MAXLEN] = {'\0'};
	iterated = 0;
	it = api->iter_begin(&txn, KNOT_NAMEDB_SORTED);
	while (it != NULL) {
		ret = api->iter_key(it, &key);
		if (iterated > 0) { /* Only if previous exists. */
			if (strcmp(key_buf, key.data) > 0) {
				diag("%s: iter_sort '%s' <= '%s' FAIL\n",
				     api->name, key_buf, (const char *)key.data);
				break;
			}
		}
		++iterated;
		memcpy(key_buf, key.data, key.len);
		it = api->iter_next(it);
	}
	is_int(db_size, iterated, "hattrie: sorted iteration");
	api->iter_finish(it);

	api->txn_abort(&txn);
	api->deinit(db);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	mm_ctx_t pool;
	mm_ctx_mempool(&pool, 4096);

	/* Temporary DB identifier. */
	char dbid_buf[] = "/tmp/namedb.XXXXXX";
	char *dbid = mkdtemp(dbid_buf);

	/* Random keys. */
	unsigned nkeys = 10000;
	char **keys = mm_alloc(&pool, sizeof(char*) * nkeys);
	for (unsigned i = 0; i < nkeys; ++i) {
		keys[i] = str_key_rand(KEY_MAXLEN, &pool);
	}

	/* Sort random keys. */
	str_key_sort(keys, nkeys);

	/* Execute test set for all backends. */
	namedb_test_set(nkeys, keys, dbid, namedb_lmdb_api(), &pool);
	namedb_test_set(nkeys, keys, NULL, namedb_trie_api(), &pool);

	/* Cleanup */
	mp_delete(pool.ctx);
	return 0;
}
