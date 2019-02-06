/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
    Copyright (C) 2018 Tony Finch <dot@dotat.at>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <err.h>
#include <unistd.h>

#include "contrib/qp-trie/trie.h"
#include "contrib/macros.h"
#include "contrib/string.h"
#include "libknot/errcode.h"
#include "tap/basic.h"

/* Constants. */
#define MAX_KEYLEN 64
#define MAX_LEAVES 12345
#define MAX_MUTATIONS 123
#define MAX_TRANSACTIONS 1234

enum cowstate {
	cow_absent, // not in trie
	cow_unmarked,
	cow_shared,
	cow_old, // deleted from new trie
	cow_new, // added to new trie
	deadbeef,
};

struct cowleaf {
	char *key;
	size_t len;
	int cowstate;
};

static inline size_t
prng(size_t max) {
	/* good enough these days */
	return (size_t)rand() % max;
}

static struct cowleaf *
grow_leaves(size_t maxlen, size_t leaves)
{
	struct cowleaf *leaf = bcalloc(leaves, sizeof(*leaf));

	trie_t *trie = trie_create(NULL);
	if (!trie) sysbail("trie_create");

	for (size_t i = 0; i < leaves; i++) {
		trie_val_t *valp;
		char *str = NULL;
		size_t len = 0;
		do {
			free(str);
			len = prng(maxlen);
			str = bmalloc(len + 1);
			for (size_t j = 0; j < len; j++)
				str[j] = "0123456789"
					"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz"
					[prng(62)];
			str[len] = '\0';
			valp = trie_get_ins(trie, (uint8_t *)str, (uint32_t)len);
			if (!valp) bail("trie_get_ins");
		} while (*valp != NULL);
		*valp = &leaf[i];
		leaf[i].key = str;
		leaf[i].len = len;
		leaf[i].cowstate = cow_absent;
	}
	trie_free(trie);

	return (leaf);
}

static void
dead_leaves(struct cowleaf *leaf, size_t leaves)
{
	for (size_t i = 0; i < leaves; i++)
		free(leaf[i].key);
	free(leaf);
}

static void
mark_cb(trie_val_t val, const uint8_t *key, size_t len, void *d)
{
	struct cowleaf *leaf = val;
	assert(leaf->cowstate == cow_unmarked &&
	       "leaf should go from unmarked to shared exactly once");
	leaf->cowstate = cow_shared;
	(void)key;
	(void)len;
	(void)d;
}

static void
commit_rollback(trie_val_t val, const uint8_t *key, size_t len, void *d)
{
	struct cowleaf *leaf = val;
	int *commit = d;
	if (*commit)
		assert((leaf->cowstate == cow_shared ||
			leaf->cowstate == cow_old) &&
		       "committing deletes from old trie");
	else
		assert((leaf->cowstate == cow_shared ||
			leaf->cowstate == cow_new) &&
		       "roll back deletes from new trie");
	if (leaf->cowstate != cow_shared)
		leaf->cowstate = deadbeef;
	(void)key;
	(void)len;
}

static void
del_cow(trie_cow_t *x, struct cowleaf *leaf)
{
	trie_val_t val;
	assert(KNOT_EOK == trie_del_cow(x,
					(uint8_t *)leaf->key,
					(uint32_t)leaf->len,
					&val));
	assert(val == leaf);
}

static void
usage(void) {
	fprintf(stderr,
		"usage: test_qp-cow [-k N] [-l N] [-t N]\n"
		"	-k N	maximum key length (default %d)\n"
		"	-l N	number of leaves (default %d)\n"
		"	-m N	mutations per transaction (default %d)\n"
		"	-t N	number of transactions (default %d)\n",
		MAX_KEYLEN,
		MAX_LEAVES,
		MAX_MUTATIONS,
		MAX_TRANSACTIONS);
	exit(1);
}

int
main(int argc, char *argv[])
{
	size_t keylen = MAX_KEYLEN;
	size_t leaves = MAX_LEAVES;
	int mutations = MAX_MUTATIONS;
	int transactions = MAX_TRANSACTIONS;

	int opt;
	while ((opt = getopt(argc, argv, "k:l:m:t:h")) != -1)
		switch (opt) {
		case('k'):
			keylen = (unsigned)atoi(optarg);
			continue;
		case('l'):
			leaves = (unsigned)atoi(optarg);
			continue;
		case('m'):
			mutations = atoi(optarg);
			continue;
		case('t'):
			transactions = atoi(optarg);
			continue;
		default:
			usage();
		}

	if (argc != optind)
		usage();

	plan(transactions);

	struct cowleaf *leaf = grow_leaves(keylen, leaves);
	trie_t *t = trie_create(NULL);

	for (int round = 0; round < transactions; round++) {
		trie_cow_t *x = trie_cow(t, mark_cb, NULL);
		if (!x) sysbail("trie_cow");

		int hits = prng(mutations);
		for (int hit = 0; hit < hits; hit++) {
			size_t i = prng(leaves);
			switch (leaf[i].cowstate) {
			case(cow_absent): {
				trie_val_t *val =
					trie_get_cow(x,
					             (uint8_t *)leaf[i].key,
					             (uint32_t)leaf[i].len);
				if (!val) sysbail("trie_get_cow");
				assert(*val == NULL && "new leaf");
				*val = &leaf[i];
				leaf[i].cowstate = cow_new;
			} break;
			case(cow_unmarked): {
				del_cow(x, &leaf[i]);
				assert(leaf[i].cowstate == cow_shared &&
				       "state changed unmarked -> shared");
				leaf[i].cowstate = cow_old;
			} break;
			case(cow_shared): {
				del_cow(x, &leaf[i]);
				assert(leaf[i].cowstate == cow_shared &&
				       "state remained shared");
				leaf[i].cowstate = cow_old;
			} break;
			case(cow_new): {
				del_cow(x, &leaf[i]);
				assert(leaf[i].cowstate == cow_new &&
				       "state remained new");
				leaf[i].cowstate = cow_absent;
			} break;
			case(cow_old): {
				// don't want to mess with old tree
			} break;
			case(deadbeef): {
				assert(!"deadbeef should not be possible");
			} break;
			default:
				assert(!"bug - unhandled state");
			}
		}

		int commit = !prng(2);
		if (commit)
			t = trie_cow_commit(x, commit_rollback, &commit);
		else
			t = trie_cow_rollback(x, commit_rollback, &commit);

		trie_it_t *it = trie_it_begin(t);
		while (!trie_it_finished(it)) {
			trie_val_t *val = trie_it_val(it);
			assert(val != NULL);
			struct cowleaf *l = *val;
			if (commit)
				assert((l->cowstate == cow_unmarked ||
					l->cowstate == cow_shared ||
					l->cowstate == cow_new) &&
				       "committing expected state");
			else
				assert((l->cowstate == cow_unmarked ||
					l->cowstate == cow_shared ||
					l->cowstate == cow_old) &&
				       "roll back expected state");
			l->cowstate = cow_unmarked;
			trie_it_next(it);
		}
		trie_it_free(it);

		for (size_t i = 0; i < leaves; i++) {
			assert((leaf[i].cowstate == cow_unmarked ||
				leaf[i].cowstate == cow_absent ||
				leaf[i].cowstate == deadbeef) &&
			       "cleanup leaves either unmarked or dead");
			if (leaf[i].cowstate == deadbeef)
				leaf[i].cowstate = cow_absent;
		}
		ok(1, "transaction done");
	}

	trie_free(t);
	dead_leaves(leaf, leaves);

	return 0;
}
