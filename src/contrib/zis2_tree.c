/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "zis2_tree.h"

#include "contrib/mempattern.h" // NOTE this include is optional

#ifndef MM_DEFAULT_BLKSIZE
#define mm_alloc(mm, size) malloc(size)
#define mm_free(mm, ptr)   free(ptr)
#endif

#define INITIAL_CAPACITY 8
#define BITMAP_SIZE 32

// TODO maybe put an extra field into zis2_node in order to optimize this? There is a placeholder there anyway
static bool isbranch(const zis2_tree_t *t, const zis2_node_t *n)
{
	return n->depth < t->depth - 1;
}

static size_t node_alloc_size(const zis2_tree_t *t, const zis2_size_t capacity, zis2_size_t depth)
{
	return sizeof(zis2_node_t) + (t->has_bitmap ? BITMAP_SIZE : 0) + (capacity * t->hash_len) + (isbranch(t, n) ? (capacity * sizeof(zis2_node_t *)) : 0);
}

static zis2_char_t *node_hashable_start(const zis2_node_t *n)
{
	return (zis2_char_t *)(&n->depth);
}

static size_t node_hashable_length(const zis2_tree_t *t, const zis2_node_t *n)
{
	return sizeof(n->depth) + (t->has_bitmap ? BITMAP_SIZE : 0) + (n->capacity * t->hash_len);
}

static zis2_char_t *node_bitmap(const zis2_tree_t *t, const zis2_node_t *n)
{
	assert(isbranch(t, n));
	assert(t->has_bitmap);
	return (zis2_char_t *)n + sizeof(*n);
}

static size_t node_bitmap_size(const zis2_tree_t *t, const zis2_node_t *n)
{
	return (t->has_bitmap && isbranch(t, n)) ? BITMAP_SIZE : 0;
}

static void node_bitmap_set(const zis2_tree_t *t, zis2_node_t *n, zis2_size_t idx, bool set)
{
	zis2_char_t *byte = node_bitmap(t, n) + (idx >> 3);
	zis2_char_t mask = 1 << (idx & 7);
	if (set) {
		*byte |= mask;
	} else {
		*byte &= ~mask;
	}
}

static zis2_char_t *node_hash_at(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	assert(idx < n->size || idx == n->capacity /* just for the shortcut in node_pchild */);
	return (zis2_char_t *)(n + 1) + node_bitmap_size(t, n) + (idx * t->hash_len);
}

static zis2_node_t **node_pchild(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	assert(idx < n->size);
	assert(isbranch(t, n));
	return (zis2_node_t **)node_hash_at(t, n, n->capacity) + idx;
}

static zis2_node_t *node_child(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	return *node_pchild(t, n, idx);
}

#define node_foreach(t, n, iter_name) \
	for (zis2_node_t *__node_foreach_start = node_child((t), (n), 0), *iter_name = __node_foreach_start; \
	     iter_name != __node_foreach_start + (n)->size; \
	     iter_name++)

static zis2_char_t *node_leaf_at(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	return isbranch(t, n) ? node_child(t, n, idx)->any_leaf : node_hash_at(t, n, idx);
}

static void node_leaf_fix(const zis2_tree_t *t, zis2_node_t *n)
{
	n->any_leaf = node_leaf_at(t, n, 0);
}

static int node_cmp(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx, const zis2_char_t *hash)
{
	if (isbranch(t, n)) {
		return memcmp(node_leaf_at(t, n, idx), hash, n->depth + 1);
	} else {
		return memcmp(node_hash_at(t, n, idx), hash, t->hash_len); // in fact, leading n->depth bytes could be skipped from comparing
	}
}

// TODO: try to optimize by splitting to isbranch versus !isbranch cases?
static zis2_size_t node_bsearch(const zis2_tree_t *t, const zis2_node_t *n, const zis2_char_t *hash, bool *hit)
{
	zis2_size_t beg = 0, end = n->size;
	while (beg < end) {
		long mid = (beg + end) / 2;
		int cmp = node_cmp(t, n, mid, hash);
		if (cmp == 0) {
			*hit = true;
			return mid;
		} else if (cmp > 0) {
			end = mid;
		} else {
			beg = mid + 1;
		}
	}
	return beg;
}

static void node_grow(const zis2_tree_t *t, zis2_node_t *n, zis2_size_t at)
{
	assert(n->size < n->capacity);
	assert(at <= n->size);
	zis2_size_t nmove = n->size - at;
	if (nmove > 0) {
		memmove(node_hash_at(t, n, at + 1), node_hash_at(t, n, at), nmove * t->hash_len);
		memset(node_hash_at(t, n, at), 0, t->hash_len);
		if (isbranch(t, n)) {
			memmove(node_pchild(t, n, at + 1), node_pchild(t, n, at), nmove * sizeof(zis2_node_t *));
			memset(node_pchild(t, n, at), 0, sizeof(zis2_node_t *));
		}
	}
	n->size++;
}

static void node_shrink(const zis2_tree_t *t, zis2_node_t *n, zis2_size_t at)
{
	assert(n->size > 0);
	zis2_size_t nmove = n->size - at - 1;
	if (nmove > 0) {
		memmove(node_hash_at(t, n, at), node_hash_at(t, n, at + 1), nmove * t->hash_len);
		if (isbranch(t, n)) {
			memmove(node_pchild(t, n, at), node_pchild(t, n, at + 1), nmove * sizeof(zis2_node_t *));
		}
	}
	n->size--;
}

static int node_realloc(zis2_tree_t *t, zis2_node_t **pn, zis2_size_t new_capacity)
{
	zis2_node_t *n = *pn;
	size_t prev_size = node_alloc_size(t, n->capacity, n->depth);
	size_t asize = node_alloc_size(t, new_capacity, n->depth);
	zis2_node_t *nnew = mm_realloc(t->mm, n, asize, prev_size);
	if (nnew == NULL) {
		return -ENOMEM;
	}
	*pn = nnew;
	if (isbranch(t, nnew)) {
		zis2_node_t *node0before = node_child(t, nnew, 0);
		nnew->capacity = new_capacity;
		zis2_node_t *node0after = node_child(t, nnew, 0);
		memmove(node0after, node0before, nnew->size * sizeof(*node0before));
	} else {
		nnew->capacity = new_capacity;
	}
	t->alloc_size += (asize - prev_size);
	return 0;
}

static zis2_node_t *node_new(zis2_tree_t *t, zis2_size_t depth)
{
	size_t asize = node_alloc_size(t, INITIAL_CAPACITY, depth);
	zis2_node_t *n = mm_calloc(t->mm, 1, asize);
	if (n != NULL) {
		n->capacity = INITIAL_CAPACITY;
		n->depth = depth;
		t->alloc_size += asize;
	}
	return n;
}

static void node_free(zis2_tree_t *t, zis2_node_t *n)
{
	if (n == NULL) {
		return;
	}
	size_t prev_size = node_alloc_size(t, n->capacity, n->depth);
	if (isbranch(t, n)) {
		node_foreach(t, n, child) {
			node_free(t, child);
		}
	}
	mm_free(t->mm, n);
	t->alloc_size -= prev_size;
}

static int node_add(zis2_tree_t *t, zis2_node_t **pn, const zis2_char_t *hash)
{
	zis2_node_t *n = *pn, *add = NULL;
	bool hit = false;
	int ret = 0;
	zis2_size_t at = node_bsearch(t, n, hash, &hit);
	if (isbranch(t, n) && hit) {
		return node_add(t, node_pchild(t, n, at), hash);
	}
	if (!isbranch(t, n) && hit && t->no_same_leaf) {
		return -EEXIST;
	}
	if (isbranch(t, n) && !hit) {
		add = node_new(t, n->depth + 1);
		if (add == NULL) {
			return -ENOMEM;
		}
	}
	if (n->size == n->capacity) {
		ret = node_realloc(t, pn, n->capacity * 2);
		if (ret != 0) {
			node_free(t, add);
			return ret;
		}
		n = *pn;
	}
	node_grow(t, n, at);
	if (isbranch(t, n)) {
		zis2_node_t **addto = node_pchild(t, n, at);
		*addto = add;
		ret = node_add(t, addto, hash);
		if (ret == 0 && t->has_bitmap) {
			node_bitmap_set(t, n, at, true);
		}
	} else {
		memcpy(node_hash_at(t, n, at), hash, t->hash_len);
	}
	if (ret == 0) {
		node_leaf_fix(t, n);
	}
	return ret;
}

static int node_rem(zis2_tree_t *t, zis2_node_t **pn, const zis2_char_t *hash)
{
	zis2_node_t *n = *pn;
	bool hit = false;
	int ret = 0;
	zis2_size_t at = node_bsearch(t, n, hash, &hit);
	if (!hit) {
		return -ENOENT;
	}
	if (isbranch(t, n)) {
		ret = node_rem(t, node_pchild(t, n, at), hash);
		if (ret != 0) {
			return ret;
		}
	}
	if (!isbranch(t, n) || node_child(t, n, at)->size == 0) {
		if (isbranch(t, n)) {
			node_free(t, node_child(t, n, at));
		}
		node_shrink(t, n, at);
	}

	if (n->size > 0) {
		node_leaf_fix(t, n);
	}
	if (isbranch(t, n) && t->has_bitmap) {
		node_bitmap_set(t, n, at, false);
	}
	if (n->capacity >= n->size * 2 + 2 && n->capacity >= 2 * INITIAL_CAPACITY) {
		ret = node_realloc(t, pn, n->capacity / 2);
	}
	return ret;
}

zis2_tree_t *zis2_tree_new(zis2_size_t depth, zis2_size_t hash_len, bool has_bitmap, struct knot_mm *mm)
{
	size_t asize = sizeof(zis2_tree_t) + hash_len;
	zis2_tree_t *t = mm_alloc(mm, asize);
	if (t != NULL) {
		t->depth = depth;
		t->hash_len = hash_len;
		t->has_bitmap = has_bitmap;
		t->alloc_size = asize;
		t->mm = mm;
		t->root = node_new(t, 0);
		if (t->root == NULL) {
			free(t);
			return NULL;
		}
	}
	return t;
}

void zis2_tree_free(zis2_tree_t *tree)
{
	if (tree != NULL) {
		node_free(tree, tree->root);
		assert(tree->alloc_size == sizeof(zis2_tree_t) + tree->hash_len);
		mm_free(tree->mm, tree);
	}
}

int zis2_tree_add(zis2_tree_t *tree, const zis2_char_t *hash)
{
	if (tree == NULL || hash == NULL) {
		return -EINVAL;
	}
	return node_add(tree, &tree->root, hash);
}

int zis2_tree_rem(zis2_tree_t *tree, const zis2_char_t *hash)
{
	if (tree == NULL || hash == NULL) {
		return -EINVAL;
	}
	return node_rem(tree, &tree->root, hash);
}

