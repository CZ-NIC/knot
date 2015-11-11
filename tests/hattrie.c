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
#include <tap/basic.h>

#include "libknot/internal/trie/hat-trie.h"
#include "libknot/internal/mem.h"

/* Constants. */
#define KEY_MAXLEN 64

/*! \brief Generate random key. */
static const char *alphabet = "abcdefghijklmn0123456789";
static char *str_key_rand(size_t len)
{
	char *s = malloc(len);
	memset(s, 0, len);
	for (unsigned i = 0; i < len - 1; ++i) {
		s[i] = alphabet[rand() % strlen(alphabet)];
	}
	return s;
}

/* \brief Check lesser or equal result. */
static bool str_key_find_leq(hattrie_t *trie, char **keys, size_t i, size_t size)
{
	static char key_buf[KEY_MAXLEN];

	int ret = 0;
	value_t *val = NULL;
	const char *key = keys[i];
	size_t key_len = strlen(key) + 1;
	memcpy(key_buf, key, key_len);

	/* Count equal first keys. */
	size_t first_key_count = 1;
	for (size_t k = 1; k < size; ++k) {
		if (strcmp(keys[0], keys[k]) == 0) {
			first_key_count += 1;
		} else {
			break;
		}
	}

	/* Before current key. */
	key_buf[key_len - 2] -= 1;
	if (i < first_key_count) {
		ret = hattrie_find_leq(trie, key_buf, key_len, &val);
		if (ret != 1) {
			diag("%s: leq for key BEFORE %zu/'%s' ret = %d", __func__, i, keys[i], ret);
			return false; /* No key before first. */
		}
	} else {
		ret = hattrie_find_leq(trie, key_buf, key_len, &val);
		if (ret > 0 || strcmp(*val, key_buf) > 0) {
			diag("%s: '%s' is not before the key %zu/'%s'", __func__, (char*)*val, i, keys[i]);
			return false; /* Found key must be LEQ than searched. */
		}
	}

	/* Current key. */
	key_buf[key_len - 2] += 1;
	ret = hattrie_find_leq(trie, key_buf, key_len, &val);
	if (! (ret == 0 && val && strcmp(*val, key_buf) == 0)) {
		diag("%s: leq for key %zu/'%s' ret = %d", __func__, i, keys[i], ret);
		return false; /* Must find equal match. */
	}

	/* After the current key. */
	key_buf[key_len - 2] += 1;
	ret = hattrie_find_leq(trie, key_buf, key_len, &val);
	if (! (ret <= 0 && strcmp(*val, key_buf) <= 0)) {
		diag("%s: leq for key AFTER %zu/'%s' ret = %d %s", __func__, i, keys[i], ret, (char*)*val);
		return false; /* Every key must have its LEQ match. */
	}

	return true;

}

/* UCW array sorting defines. */
#define ASORT_PREFIX(X) str_key_##X
#define ASORT_KEY_TYPE char*
#define ASORT_LT(x, y) (strcmp((x), (y)) < 0)
#include "libknot/internal/array-sort.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	/* Random keys. */
	srand(time(NULL));
	unsigned key_count = 100000;
	char **keys = malloc(sizeof(char*) * key_count);
	for (unsigned i = 0; i < key_count; ++i) {
		keys[i] = str_key_rand(KEY_MAXLEN);
	}

	/* Sort random keys. */
	str_key_sort(keys, key_count);

	/* Create trie */
	value_t *val = NULL;
	hattrie_t *trie = hattrie_create();
	ok(trie != NULL, "hattrie: create");

	/* Insert keys */
	bool passed = true;
	size_t inserted = 0;
	for (unsigned i = 0; i < key_count; ++i) {
		val = hattrie_get(trie, keys[i], strlen(keys[i]) + 1);
		if (!val) {
			passed = false;
			break;
		}
		if (*val == NULL) {
			*val = keys[i];
			++inserted;
		}
	}
	ok(passed, "hattrie: insert");

	/* Check total insertions against trie weight. */
	is_int(hattrie_weight(trie), inserted, "hattrie: trie weight matches insertions");

	/* Build order-index. */
	hattrie_build_index(trie);

	/* Lookup all keys */
	passed = true;
	for (unsigned i = 0; i < key_count; ++i) {
		val = hattrie_tryget(trie, keys[i], strlen(keys[i]) + 1);
		if (val && (*val == keys[i] || strcmp(*val, keys[i]) == 0)) {
			continue;
		} else {
			diag("hattrie: mismatch on element '%u'", i);
			passed = false;
			break;
		}
	}
	ok(passed, "hattrie: lookup all keys");

	/* Lesser or equal lookup. */
	passed = true;
	for (unsigned i = 0; i < key_count; ++i) {
		if (!str_key_find_leq(trie, keys, i, key_count)) {
			passed = false;
			for (int off = -10; off < 10; ++off) {
				int k = (int)i + off;
				if (k < 0 || k >= key_count) {
					continue;
				}
				diag("[%u/%d]: %s%s", i, off, off == 0?">":"",keys[k]);
			}
			break;
		}
	}
	ok(passed, "hattrie: find lesser or equal for all keys");

	/* Next lookup. */
	passed = true;
	for (unsigned i = 0; i < key_count - 1 && passed; ++i) {
		value_t *val;
		hattrie_find_next(trie, keys[i], strlen(keys[i]), &val);
		passed = val && *val == (void *)keys[(i + 1)];
	}
	ok(passed, "hattrie: find next for all keys");

	/* Unsorted iteration */
	size_t iterated = 0;
	hattrie_iter_t *it = hattrie_iter_begin(trie, false);
	while (!hattrie_iter_finished(it)) {
		++iterated;
		hattrie_iter_next(it);
	}
	is_int(inserted, iterated, "hattrie: unsorted iteration");
	hattrie_iter_free(it);

	/* Sorted iteration. */
	char key_buf[KEY_MAXLEN] = {'\0'};
	iterated = 0;
	it = hattrie_iter_begin(trie, true);
	while (!hattrie_iter_finished(it)) {
		size_t cur_key_len = 0;
		const char *cur_key = hattrie_iter_key(it, &cur_key_len);
		if (iterated > 0) { /* Only if previous exists. */
			if (strcmp(key_buf, cur_key) > 0) {
				diag("'%s' <= '%s' FAIL\n", key_buf, cur_key);
				break;
			}
		}
		++iterated;
		memcpy(key_buf, cur_key, cur_key_len);
		hattrie_iter_next(it);
	}
	is_int(inserted, iterated, "hattrie: sorted iteration");
	hattrie_iter_free(it);

	/* Cleanup */
	for (unsigned i = 0; i < key_count; ++i) {
		free(keys[i]);
	}
	free(keys);
	hattrie_free(trie);
	return 0;
}
