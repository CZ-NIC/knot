/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hr256tree.h"

#include "contrib/mempattern.h" // NOTE this include is optional

#ifndef MM_DEFAULT_BLKSIZE
#define mm_alloc(mm, size) malloc(size)
#define mm_free(mm, ptr)   free(ptr)
#endif

#define INIT_CAPACITY 6

inline static hr256node_t *hash2node(const hr256tree_t *t, uint8_t *h)
{
	return (hr256node_t *)(h + t->hash_len);
}

inline static uint8_t *node2hash(const hr256tree_t *t, hr256node_t *n)
{
	return (uint8_t *)n - t->hash_len;
}

inline static size_t branch_size(const hr256tree_t *t, uint16_t capacity)
{
	return t->hash_len + sizeof(hr256node_t) + capacity * sizeof(uint8_t *);
}

inline static size_t leaf_size(const hr256tree_t *t)
{
	return t->hash_len + sizeof(unsigned);
}

inline static bool isbranch(const hr256tree_t *t, const hr256node_t *node)
{
	return node->branch_byte != t->hash_len;
}

inline static int memcmp_range(const uint8_t *hash1, const uint8_t *hash2, unsigned from, unsigned to)
{
	return memcmp(hash1 + from, hash2 + from, to - from);
}

inline static unsigned memcmp_diff(const uint8_t *hash1, const uint8_t *hash2,
                                   unsigned start_idx, unsigned end_idx)
{
	for (const uint8_t *a = hash1 + start_idx, *b = hash2 + start_idx;
	     a != hash1 + end_idx; a++, b++) {
		if (*a != *b) {
			return (a - hash1);
		}
	}
	return end_idx;
}

static unsigned invalid_hash_len(const hr256tree_t *t)
{
	return t->hash_len >= 4 ? 4 : t->hash_len;
}

static void invalidate_own_hash(const hr256tree_t *t, hr256node_t *n)
{
	assert(isbranch(t, n));
	memset(node2hash(t, n), 0, invalid_hash_len(t));
}

static const uint32_t zeroes4 = 0;
static bool invalid_hash(const hr256tree_t *t, hr256node_t *n)
{
	assert(isbranch(t, n));
	return memcmp(node2hash(t, n), &zeroes4, invalid_hash_len(t)) == 0;
}

inline static hr256node_t *go_child(const hr256tree_t *t, const hr256node_t *n, unsigned idx)
{
	return hash2node(t, n->childs_h[idx]);
}

inline static uint8_t **go_child_pp(hr256node_t *n, unsigned idx)
{
	return &n->childs_h[idx];
}

inline static uint8_t *any_leaf_hash(const hr256tree_t *t, hr256node_t *n)
{
	return isbranch(t, n) ? n->any_leaf : node2hash(t, n);
}

static uint8_t *new_branch(hr256tree_t *t, unsigned branch_byte, uint16_t capacity)
{
	uint8_t *res = mm_alloc(t->mm, branch_size(t, capacity));
	if (res != NULL) {
		hr256node_t *n = hash2node(t, res);

		n->branch_byte = branch_byte;
		n->size = 0;
		n->capacity = capacity;
		invalidate_own_hash(t, n);

		t->alloc_size += branch_size(t, capacity);
	}
	return res;
}

static uint8_t *new_leaf(hr256tree_t *t, const uint8_t *hash)
{
	uint8_t *res = mm_alloc(t->mm, leaf_size(t));
	if (res != NULL) {
		memcpy(res, hash, t->hash_len);
		hash2node(t, res)->branch_byte = t->hash_len;

		t->alloc_size += leaf_size(t);
	}
	return res;
}

static void node_free(hr256tree_t *t, uint8_t **npp)
{
	hr256node_t *n = hash2node(t, *npp);
	t->alloc_size -= isbranch(t, n) ? branch_size(t, n->capacity) : leaf_size(t);
	mm_free(t->mm, *npp);
	*npp = NULL;
}

int rem_child(hr256tree_t *t, hr256node_t *n, uint8_t **npp, unsigned idx)
{
	assert(idx < n->size);
	if (idx < --n->size) {
		memmove(n->childs_h + idx, n->childs_h + idx + 1,
		        (n->size - idx) * sizeof(*n->childs_h));
	}

	if (n->capacity > n->size * 2) {
		size_t before = branch_size(t, n->capacity), after = branch_size(t, n->capacity / 2);
		uint8_t *newh = mm_realloc(t->mm, *npp, after, before);
		if (newh == NULL) {
			return -ENOMEM;
		}
		t->alloc_size -= (before - after);
		*npp = newh;
		n = hash2node(t, newh);
		n->capacity /= 2;
	}

	if (idx == 0 && n->size > 0) {
		n->any_leaf = any_leaf_hash(t, go_child(t, n, 0));
	}

	return 0;
}

int add_child(hr256tree_t *t, hr256node_t *n, uint8_t **npp, hr256node_t *child, unsigned idx)
{
	assert(n->capacity >= n->size);
	if (n->capacity == n->size) {
		size_t before = branch_size(t, n->capacity), after = branch_size(t, n->capacity * 2);
		uint8_t *newh = mm_realloc(t->mm, *npp, after, before);
		if (newh == NULL) {
			return -ENOMEM;
		}
		t->alloc_size += after - before;
		*npp = newh;
		n = hash2node(t, newh);
		n->capacity *= 2;
	}

	if (idx < n->size) {
		memmove(n->childs_h + idx + 1, n->childs_h + idx,
		        (n->size - idx) * sizeof(*n->childs_h));
	}

	n->size++;
	n->childs_h[idx] = node2hash(t, child);

	if (idx == 0) {
		n->any_leaf = any_leaf_hash(t, go_child(t, n, 0));
	}

	return 0;
}

static int child_cmp(const hr256tree_t *t, const hr256node_t *n, unsigned idx, const uint8_t *hash)
{
	hr256node_t *child = go_child(t, n, idx);
	assert(child->branch_byte > n->branch_byte);
	return memcmp_range(any_leaf_hash(t, child), hash, n->branch_byte, child->branch_byte);
}

static unsigned child_bsearch(hr256tree_t *t, const hr256node_t *n, const uint8_t *hash, bool *hit)
{
	long beg = 0, end = n->size;
	*hit = false;
	while (beg < end) {
		long mid = (beg + end) / 2;
		int cmp = child_cmp(t, n, mid, hash);
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

static int node_rem(hr256tree_t *t, hr256node_t *n, uint8_t **npp, const uint8_t *hash, bool *got_empty)
{
	assert(n == hash2node(t, *npp));
	if (!isbranch(t, n)) {
		*got_empty = true;
		return 0;
	}

	bool hit = false, child_empty = false;
	unsigned idx = child_bsearch(t, n, hash, &hit);
	if (!hit) {
		return -ENOENT;
	}

	uint8_t **childpp = go_child_pp(n, idx);
	int ret = node_rem(t, go_child(t, n, idx), childpp, hash, &child_empty);
	if (child_empty && ret == 0) {
		node_free(t, childpp);
		ret = rem_child(t, n, npp, idx);
	}
	n = hash2node(t, *npp);

	*got_empty = (n->size == 0);

	if (n->size == 1 && ret == 0) {
		uint8_t *child_h = n->childs_h[0];
		node_free(t, npp);
		*npp = child_h;
	} else if (n->size > 1 && ret == 0) {
		invalidate_own_hash(t, n);
	}

	return ret;
}

int hr256tree_rem(hr256tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}
	if (t->root_h == NULL) {
		return -ENOENT;
	}

	bool empty = false;
	int ret = node_rem(t, hash2node(t, t->root_h), &t->root_h, hash, &empty);
	if (empty && ret == 0) {
		node_free(t, &t->root_h);
		assert(t->alloc_size == 0);
	}
	return ret;
}

static int add_branch(hr256tree_t *t, hr256node_t *left, hr256node_t *right, uint8_t **where)
{
	unsigned new_byte = memcmp_diff(any_leaf_hash(t, left), any_leaf_hash(t, right), 0, t->hash_len);

	uint8_t *branch_p = new_branch(t, new_byte, INIT_CAPACITY);
	if (branch_p == NULL) {
		return -ENOMEM;
	}
	hr256node_t *branch = hash2node(t, branch_p);
	branch->size = 2;
	*go_child_pp(branch, 0) = node2hash(t, left);
	*go_child_pp(branch, 1) = node2hash(t, right);
	branch->any_leaf = any_leaf_hash(t, left);

	*where = branch_p;
	return 0;
}

static int node_add(hr256tree_t *t, hr256node_t *n, uint8_t **npp, hr256node_t *new_leaf)
{
	const uint8_t *hash = node2hash(t, new_leaf);

	if (!isbranch(t, n)) {
		int cmp = memcmp(node2hash(t, n), hash, t->hash_len);
		if (cmp == 0) {
			return -EEXIST;
		} else if (cmp < 0) {
			return add_branch(t, n, new_leaf, npp);
		} else {
			return add_branch(t, new_leaf, n, npp);
		}
	}

	invalidate_own_hash(t, n);

	int cmp = memcmp(hash, any_leaf_hash(t, n), n->branch_byte);
	if (cmp != 0) {
		assert(*npp == t->root_h);
		if (cmp < 0) {
			return add_branch(t, new_leaf, n, npp);
		} else {
			return add_branch(t, n, new_leaf, npp);
		}
	}

	bool hit = false;
	unsigned idx = child_bsearch(t, n, hash, &hit);
	if (hit) {
		return node_add(t, go_child(t, n, idx), go_child_pp(n, idx), new_leaf);
	}

	unsigned i = n->branch_byte;
	bool same_left = (idx > 0 && hash[i] == any_leaf_hash(t, go_child(t, n, idx - 1))[i]);
	bool same_right = (idx < n->size && hash[i] == any_leaf_hash(t, go_child(t, n, idx))[i]);
	assert(!same_left || !same_right);

	if (same_left) {
		return add_branch(t, go_child(t, n, idx - 1), new_leaf, go_child_pp(n, idx - 1));
	} else if (same_right) {
		return add_branch(t, new_leaf, go_child(t, n, idx), go_child_pp(n, idx));
	} else {
		return add_child(t, n, npp, new_leaf, idx);
	}
}

int hr256tree_add(hr256tree_t *t, const uint8_t *hash)
{
	uint8_t *leaf_p = new_leaf(t, hash);
	if (leaf_p == NULL) {
		return -ENOMEM;
	}
	if (t->root_h == NULL) {
		t->root_h = leaf_p;
		return 0;
	}
	int ret = node_add(t, hash2node(t, t->root_h), &t->root_h, hash2node(t, leaf_p));
	if (ret != 0) {
		node_free(t, &leaf_p);
	}
	return ret;
}

static int nrehash(hr256tree_t *t, hr256node_t *n, hr256rehash_t cb, void *ctx)
{
	if (!isbranch(t, n) || !invalid_hash(t, n)) {
		return 0;
	}

	int ret = 0;
	for (unsigned i = 0; ret == 0 && i < n->size; i++) {
		ret = nrehash(t, go_child(t, n, i), cb, ctx);
	}

	return ret ? ret : cb(node2hash(t, n), n->childs_h, n->size, t->hash_len, ctx, t->algorithm);
}

int hr256tree_hash(hr256tree_t *t, hr256rehash_t cb, void *ctx, uint8_t **out_hash)
{
	if (t == NULL || t->root_h == NULL || cb == NULL || out_hash == NULL) {
		return -EINVAL;
	}

	int ret = nrehash(t, hash2node(t, t->root_h), cb, ctx);
	if (ret == 0) {
		*out_hash = t->root_h;
	}
	return ret;
}

bool hr256tree_empty(const hr256tree_t *t)
{
	return (t == NULL || t->root_h == NULL);
}

static void clear_node(hr256tree_t *t, hr256node_t *n, uint8_t **npp)
{
	if (isbranch(t, n)) {
		for (unsigned i = 0; i < n->size; i++) {
			clear_node(t, go_child(t, n, i), go_child_pp(n, i));
		}
	}
	node_free(t, npp);
}

void hr256tree_clear(hr256tree_t *t)
{
	if (!hr256tree_empty(t)) {
		clear_node(t, hash2node(t, t->root_h), &t->root_h);
		assert(t->root_h == NULL);
		assert(t->alloc_size == 0);
	}
}

#include <stdio.h>

static void print_hash(uint8_t *hash, unsigned len)
{
	const static char hex[] = "0123456789ABCDEF";
	for (unsigned i = 0; i < len; i++) {
		putchar(hex[ hash[i] >> 4 ]);
		putchar(hex[ hash[i] & 15 ]);
	}
	putchar('\n');
}

static void recur_print(const hr256tree_t *t, hr256node_t *n, unsigned depth, bool last_child)
{
	static const char pipes[] = "||||||||||||||||||||||||||||||||";
	if (depth > 0) {
		printf("%.*s%c%c%c", depth - 1, pipes, 0xe2, 0x94, last_child ? 0x94 : 0x9c);
	}

	if (!isbranch(t, n)) {
		print_hash(node2hash(t, n), t->hash_len);
		return;
	}

	printf("* %u ", n->branch_byte);
	print_hash(node2hash(t, n), t->hash_len);

	for (unsigned i = 0; n != NULL && i < n->size; i++) {
		recur_print(t, go_child(t, n, i), depth + 1, i == n->size - 1);
	}
}

void hr256tree_print(const hr256tree_t *t)
{
	if (hr256tree_empty(t)) {
		printf("(empty)\n");
	} else {
		recur_print(t, hash2node(t, t->root_h), 0, false);
	}
}
