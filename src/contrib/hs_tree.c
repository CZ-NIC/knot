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
#define mm_alloc(mm, size)              malloc(size)
#define mm_free(mm, ptr)                free(ptr)
#define mm_realloc(mm, ptr, size, old)  realloc(ptr, size)
#endif

#define INIT_CAPACITY 6

static bool leaf_parent(hs_tree_t *t, unsigned depth)
{
	return depth == t->depth;
}

static hs_node_t *child2node(uint8_t *childp, hs_tree_t *t)
{
	return (hs_node_t *)(childp + t->hash_len);
}

static uint8_t *node2child(hs_node_t *n, hs_tree_t *t)
{
	return (uint8_t *)n - t->hash_len;
}

static hs_node_t *go_branch(hs_tree_t *t, const hs_node_t *branch_parent, unsigned idx)
{
	return child2node(branch_parent->childs[idx], t);
}

static void fix_any_leaf(hs_tree_t *t, hs_node_t *n, unsigned depth)
{
	if (leaf_parent(t, depth)) {
		n->any_leaf = n->childs[0];
	} else {
		n->any_leaf = go_branch(t, n, 0)->any_leaf;
	}
}

static unsigned invalid_hash_len(hs_tree_t *t)
{
	return t->hash_len >= 4 ? 4 : t->hash_len;
}

static void invalidate_own_hash(hs_tree_t *t, hs_node_t *n)
{
	memset(node2child(n, t), 0, invalid_hash_len(t));
}

static const uint32_t zeroes4 = 0;
static bool invalid_hash(hs_tree_t *t, hs_node_t *n)
{
	return memcmp(node2child(n, t), &zeroes4, invalid_hash_len(t)) == 0;
}

static size_t alloc_size(hs_tree_t *t, unsigned capacity)
{
	return t->hash_len + sizeof(hs_node_t) + capacity * sizeof(uint8_t *);
}

static void node_init(hs_tree_t *t, hs_node_t *n)
{
	invalidate_own_hash(t, n);
	n->size = 0;
	n->capacity = INIT_CAPACITY;
	n->any_leaf = NULL;
}

static int nibble_memcmp(const uint8_t *a, const uint8_t *b, unsigned nibbles)
{
	int res = memcmp(a, b, nibbles >> 1);
	if ((nibbles & 1) && res == 0) {
		uint8_t ea = a[nibbles >> 1] & 0xf0, eb = b[nibbles >> 1] & 0xf0;
		res = memcmp(&ea, &eb, sizeof(ea));
	}
	return res;
}

static int child_cmp(hs_tree_t *t, const hs_node_t *n, unsigned depth, unsigned idx, const uint8_t *hash)
{
	if (leaf_parent(t, depth)) {
		return memcmp(n->childs[idx], hash, t->hash_len);
	} else {
		return nibble_memcmp(go_branch(t, n, idx)->any_leaf, hash, (depth + 1) * t->width_4bits);
	}
}

static unsigned child_bsearch(hs_tree_t *t, const hs_node_t *n, unsigned depth, const uint8_t *hash, bool *hit)
{
	long beg = 0, end = n->size;
	while (beg < end) {
		long mid = (beg + end) / 2;
		int cmp = child_cmp(t, n, depth, mid, hash);
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

static int ptr_add(hs_tree_t *t, hs_node_t *n, uint8_t **npp, unsigned depth, unsigned idx)
{
	assert(n->capacity >= n->size);
	if (n->capacity == n->size) {
		size_t before = alloc_size(t, n->capacity), after = alloc_size(t, n->capacity * 2);
		uint8_t *nnew = mm_realloc(t->mm, *npp, after, before);
		if (nnew == NULL) {
			return -ENOMEM;
		}
		t->alloc_size += after - before;
		*npp = nnew;
		n = child2node(nnew, t);
		n->capacity *= 2;
	}

	if (idx < n->size) {
		memmove(n->childs + idx + 1, n->childs + idx, (n->size - idx) * sizeof(n->childs[0]));
	}
	n->size++;
	n->childs[idx] = NULL;
	return 0;
}

static int ptr_rem(hs_tree_t *t, hs_node_t *n, uint8_t **npp, unsigned depth, unsigned idx)
{
	n->childs[idx] = NULL;
	n->size--;
	if (idx < n->size) {
		memmove(n->childs + idx, n->childs + idx + 1, (n->size - idx) * sizeof(n->childs[0]));
	}

	if (n->capacity > n->size * 2) {
		size_t before = alloc_size(t, n->capacity), after = alloc_size(t, n->capacity / 2);
		uint8_t *nnew = mm_realloc(t->mm, *npp, after, before);
		if (nnew == NULL) {
			return -ENOMEM;
		}
		t->alloc_size -= (before - after);
		*npp = nnew;
		n = child2node(nnew, t);
		n->capacity /= 2;
	}
	return 0;
}

static int node_rem(hs_tree_t *t, hs_node_t *n, uint8_t **npp, unsigned depth, const uint8_t *hash)
{
	bool hit = false;
	unsigned idx = child_bsearch(t, n, depth, hash, &hit);
	if (!hit) {
		return -ENOENT;
	}
	int ret = 0;
	if (!leaf_parent(t, depth)) {
		ret = node_rem(t, go_branch(t, n, idx), &n->childs[idx], depth + 1, hash);
	}

	hs_node_t *childn = leaf_parent(t, depth) ? NULL : go_branch(t, n, idx);
	if (ret != 0 || (childn != NULL && childn->size > 0)) {
		fix_any_leaf(t, n, depth);
		invalidate_own_hash(t, n);
		return ret;
	}

	t->alloc_size -= leaf_parent(t, depth) ? t->hash_len : alloc_size(t, childn->capacity);
	mm_free(t->mm, n->childs[idx]);

	ret = ptr_rem(t, n, npp, depth, idx);
	if (ret == 0) {
		n = child2node(*npp, t);
		if (n->size > 0) {
                        fix_any_leaf(t, n, depth);
		}
		invalidate_own_hash(t, n);
	}
	return ret;
}

static int node_add(hs_tree_t *t, hs_node_t *n, uint8_t **npp, unsigned depth, const uint8_t *hash)
{
	bool hit = false;
	unsigned idx = child_bsearch(t, n, depth, hash, &hit);

	if (!hit) {
		int ret = ptr_add(t, n, npp, depth, idx);
		if (ret != 0) {
			return ret;
		}
		n = child2node(*npp, t);

		size_t asize = leaf_parent(t, depth) ? t->hash_len : alloc_size(t, INIT_CAPACITY);
		n->childs[idx] = mm_alloc(t->mm, asize);
		if (n->childs[idx] == NULL) {
			return -ENOMEM;
		}
		t->alloc_size += asize;

		if (leaf_parent(t, depth)) {
			memcpy(n->childs[idx], hash, t->hash_len);
			fix_any_leaf(t, n, depth);
			invalidate_own_hash(t, n);
			return 0;
		}

		node_init(t, go_branch(t, n, idx));
	}

	int ret = leaf_parent(t, depth) ? -EEXIST : node_add(t, go_branch(t, n, idx), &n->childs[idx], depth + 1, hash);
	if (ret == 0) {
		fix_any_leaf(t, n, depth);
		invalidate_own_hash(t, n);
	}
	return ret;
}

int hs_tree_rem(hs_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}

	if (t->rootp == NULL) {
		return -ENOENT;
	}

	int ret = node_rem(t, child2node(t->rootp, t), &t->rootp, 0, hash);

	if (ret == 0 && child2node(t->rootp, t)->size == 0) {
		t->alloc_size -= alloc_size(t, child2node(t->rootp, t)->capacity);
		mm_free(t->mm, t->rootp);
		assert(t->alloc_size == 0);
	}

	return ret;
}

int hs_tree_add(hs_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}

	if (t->rootp == NULL) {
		assert(t->alloc_size == 0);
		size_t asize = alloc_size(t, INIT_CAPACITY);
		t->rootp = mm_alloc(t->mm, asize);
		if (t->rootp == NULL) {
			return -ENOMEM;
		}
		t->alloc_size += asize;
		node_init(t, child2node(t->rootp, t));
	}

	return node_add(t, child2node(t->rootp, t), &t->rootp, 0, hash);
}

static int rehash(hs_tree_t *t, hs_node_t *n, unsigned depth, hs_rehash_t cb, void *ctx)
{
	if (!invalid_hash(t, n)) {
		return 0;
	}

	int ret = 0;
	for (unsigned i = 0; ret == 0 && i < n->size && !leaf_parent(t, depth); i++) {
		ret = rehash(t, go_branch(t, n, i), depth + 1, cb, ctx);
	}

	return ret ? ret : cb(node2child(n, t), n->childs, n->size, t->hash_len, ctx, t->algorithm);
}

int hs_tree_hash(hs_tree_t *t, hs_rehash_t cb, void *ctx, uint8_t **out_hash)
{
	if (t == NULL || t->rootp == NULL || cb == NULL || out_hash == NULL) {
		return -EINVAL;
	}

	int ret = rehash(t, child2node(t->rootp, t), 0, cb, ctx);
	if (ret == 0) {
		*out_hash = t->rootp;
	}
	return ret;
}

bool hs_tree_empty(hs_tree_t *t)
{
	if (t != NULL && t->rootp != NULL) {
		assert(child2node(t->rootp, t)->size > 0);
		return false;
	}
	return true;
}

static void clear_node(hs_tree_t *t, hs_node_t *n, unsigned depth)
{
	if (leaf_parent(t, depth)) {
		for (unsigned i = 0; i < n->size; i++) {
			mm_free(t->mm, n->childs[i]);
		}
		t->alloc_size -= n->size * t->hash_len;
	} else {
		for (unsigned i = 0; i < n->size; i++) {
			hs_node_t *child = go_branch(t, n, i);
			clear_node(t, child, depth + 1);
			t->alloc_size -= alloc_size(t, child->capacity);
			mm_free(t->mm, n->childs[i]);
		}
	}
	n->size = 0;
}

void hs_tree_clear(hs_tree_t *t)
{
	if (!hs_tree_empty(t)) {
		clear_node(t, child2node(t->rootp, t), 0);
		t->alloc_size -= alloc_size(t, child2node(t->rootp, t)->capacity);
		assert(t->alloc_size == 0);
		mm_free(t->mm, t->rootp);
		t->rootp = NULL;
	}
}

#include <stdio.h>

static void print_hash(uint8_t *hash, unsigned len)
{
	const static char hex[] = "0123456789abcdef";
	for (unsigned i = 0; i < len; i++) {
		putchar(hex[ hash[i] >> 4 ]);
		putchar(hex[ hash[i] & 15 ]);
	}
	putchar('\n');
}

static void recur_print(hs_tree_t *t, uint8_t *np, unsigned depth, bool last_child)
{
	static const char pipes[] = "||||||||||||||||||||||||||||||||";
	if (depth > 0) {
		printf("%.*s%c%c%c", depth - 1, pipes, 0xe2, 0x94, last_child ? 0x94 : 0x9c);
	}

	hs_node_t *n = (depth <= t->depth ? child2node(np, t) : NULL);
	if (n != NULL) {
		printf("* ");
	}

	print_hash(np, t->hash_len);

	for (unsigned i = 0; n != NULL && i < n->size; i++) {
		recur_print(t, n->childs[i], depth + 1, i == n->size - 1);
	}
}

void hs_tree_print(hs_tree_t *t)
{
	if (hs_tree_empty(t)) {
		printf("(empty)\n");
	} else {
		recur_print(t, t->rootp, 0, true);
	}
}
