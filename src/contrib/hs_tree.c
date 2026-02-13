/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hs_tree.h"

#include "contrib/mempattern.h" // NOTE this include is optional

#ifndef MM_DEFAULT_BLKSIZE
#define mm_alloc(mm, size) malloc(size)
#define mm_free(mm, ptr)   free(ptr)
#endif

static bool leaf_parent(hs_node_t *n, unsigned depth, hs_tree_t *t)
{
	(void)n;
	return depth == t->depth;
}

static size_t node_alloc_size(const hs_node_t *n, hs_tree_t *t) {
	return sizeof(*n) + (n->capacity * sizeof(n->leaf_childs[0])) + t->hash_len;
}

static void node_free(hs_node_t *n, hs_tree_t *t) {
	mm_free(t->mm, n);
}

static bool node_geq(hs_node_t *n, unsigned depth, hs_tree_t *t, unsigned idx, const uint8_t *hash)
{
	if (leaf_parent(n, depth, t)) {
		return memcmp(n->leaf_childs[idx], hash, t->hash_len) <= 0;
	} else {
		return node_geq(n->branch_childs[idx], depth + 1, t, 0, hash);
	}
}

static unsigned node_bsearch(hs_node_t *n, unsigned depth, hs_tree_t *t, const uint8_t *hash)
{
	unsigned rangebeg = 0, rangelen = n->size;
	while (rangelen > 1) {
		unsigned middle = rangebeg + rangelen / 2;
		if (node_geq(n, depth, t, middle, hash)) {
			rangelen -= (middle - rangebeg);
			rangebeg = middle;
		} else {
			rangelen = middle - rangebeg;
		}
	}
	return rangebeg;
}

static int node_rem_idx(hs_node_t **npp, unsigned depth, hs_tree_t *t, unsigned idx)
{
	hs_node_t *n = *npp;

	assert(idx < n->size);
	assert(n->size <= n->capacity);

	if (leaf_parent(n, depth, t)) {
		t->alloc_size -= t->hash_len;
		mm_free(t->mm, n->leaf_childs[idx]);
	} else {
		t->alloc_size -= node_alloc_size(n->branch_childs[idx], t);
		node_free(n->branch_childs[idx], t);
	}

	n->size--;
	if (n->size > idx) {
		// regardless if leaf_parent or above, the pointers work the same way
                memmove(n->leaf_childs + idx, n->leaf_childs + idx + 1, sizeof(n->leaf_childs[0]) * (n->size - idx));
	}

	if (n->size < n->capacity / 2 && n->size > 0) {
		size_t before = node_alloc_size(n, t);
		n->capacity /= 2;
		size_t after = node_alloc_size(n, t);

		n = mm_realloc(t->mm, n, after, before);
		if (n == NULL) {
			return -ENOMEM;
		}
		*npp = n;
		t->alloc_size -= (before - after);
	}

	return 0;
}

const static hs_node_t node_new_tpl = { .size = 0, .capacity = 2 };

static hs_node_t *node_new(hs_tree_t *t)
{
	hs_node_t *n = mm_alloc(t->mm, node_alloc_size(&node_new_tpl, t));
	if (n != NULL) {
		n->capacity = 2;
		n->own_hash = (void *)n + node_alloc_size(n, t) - t->hash_len;
	}
	return n;
}

static int node_rem(hs_node_t **npp, unsigned depth, hs_tree_t *t, const uint8_t *hash)
{
	hs_node_t *n = *npp;
	unsigned idx = node_bsearch(n, depth, t, hash);

	if (leaf_parent(n, depth, t)) {
		if (memcmp(n->leaf_childs[idx], hash, t->hash_len) != 0) {
			return -ENOENT;
		}
		return node_rem_idx(npp, depth, t, idx);
	} else {
		int ret = node_rem(&n->branch_childs[idx], depth + 1, t, hash);
		if (ret == 0 && n->branch_childs[idx]->size == 0) {
			ret = node_rem_idx(npp, depth, t, idx);
		}
		return ret;
	}
}

int hs_tree_rem(hs_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}

	if (t->root == NULL) {
		return -ENOENT;
	}

	return node_rem(&t->root, 0, t, hash);

	// FIXME rehash
}

static int node_add_idx(hs_node_t **npp, unsigned depth, hs_tree_t *t, unsigned idx, const uint8_t *hash)
{
	hs_node_t *n = *npp;
	if (n->capacity == n->size) {
                size_t before = node_alloc_size(n, t);
		n->capacity *= 2;
                size_t after = node_alloc_size(n, t);
		n = mm_realloc(t->mm, n, after, before);
		if (n == NULL) {
			return -ENOMEM;
		}
		*npp = n;
		t->alloc_size += (after - before);
	}

	if (n->size > idx) {
		memmove(n->leaf_childs + idx + 1, n->leaf_childs + idx, sizeof(n->leaf_childs[0]) * (n->size - idx));
	}
	n->size++;

        // generate one-item branch nodes down to leaf to fulfill the depth
	while (!leaf_parent(n, depth, t)) {
		n->branch_childs[idx] = node_new(t);
		if (n->branch_childs[idx] == NULL) {
			return -ENOMEM;
		}

		npp = &n->branch_childs[idx];
		n = *npp;
		idx = 0;
		n->size = 1;
	}

	n->leaf_childs[idx] = mm_alloc(t->mm, t->hash_len);
	if (n->leaf_childs[idx] == NULL) {
		return -ENOMEM;
        }
	memcpy(n->leaf_childs[idx], hash, t->hash_len);

	return 0;
}

static int node_add(hs_node_t **npp, unsigned depth, hs_tree_t *t, const uint8_t *hash)
{
	hs_node_t *n = *npp;
	unsigned idx = node_bsearch(n, depth, t, hash);

	if (leaf_parent(n, depth, t)) {
		int cmp = memcmp(n->leaf_childs[idx], hash, t->hash_len);
		if (cmp == 0) {
			return -EEXIST;
		}
		if (cmp > 0) {
			assert(idx == 0);
		} else {
			idx++;
		}
		return node_add_idx(npp, depth, t, idx, hash);
	} else {
		int cmp = memcmp(TODO, hash, t->hash_len);
		if (cmp == 0) {
			return node_add(&n->branch_childs[idx], depth + 1, t, hash);
		} else {
			if (cmp > 0) {
				assert(idx == 0);
			} else {
				idx++;
			}
			return node_add_idx(npp, depth, t, idx, hash);
		}
	}
}

int hs_tree_add(hs_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}

	if (t->root == NULL) {
		// TODO
	}

	return node_add(&t->root, 0, t, hash);

	// FIXME rehash
}

