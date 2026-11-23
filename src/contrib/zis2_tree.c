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

/*
 * Tree structure:
 * - root
 * - one or more levels of intermediate (Level-1) branch nodes, isbranch(n) == true
 * - one level of final (Level-2) branch nodes, isbranch == false !!
 * - one level of leaves, which are actually not nodes in the tree, but only hashes stored at Level-2 nodes
 */

static bool isbranch_depth(const zis2_tree_t *t, zis2_size_t depth)
{
	assert(depth < t->depth);
	return depth != t->depth - 1;
}

static bool isbranch(const zis2_tree_t *t, const zis2_node_t *n)
{
	assert(isbranch_depth(t, n->depth) == (bool)n->isbranch);
	return (bool)n->isbranch;
}

static size_t node_alloc_size(const zis2_tree_t *t, zis2_size_t capacity, zis2_size_t depth)
{
	return sizeof(zis2_node_t) + (t->has_bitmap ? BITMAP_SIZE : 0) + (capacity * t->hash_len) + (isbranch_depth(t, depth) ? (capacity * sizeof(zis2_node_t *)) : 0);
}

static size_t node_bitmap_size(const zis2_tree_t *t, const zis2_node_t *n)
{
	return (t->has_bitmap && isbranch(t, n)) ? BITMAP_SIZE : 0;
}

static zis2_char_t *node_bitmap(const zis2_tree_t *t, const zis2_node_t *n)
{
	assert(node_bitmap_size(t, n) > 0);
	return (zis2_char_t *)n + sizeof(*n);
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

static void invalidate_hash_at(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	*(zis2_size_t *)node_hash_at(t, n, idx) = 0;
}

static bool hash_invalid(const zis2_char_t *hash) {
	return *(zis2_size_t *)hash == 0;
	// if by chance a legitimate hash starts with four zero bytes, than it's just performance penalty
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

static zis2_char_t *node_hashable_start(const zis2_tree_t *t, const zis2_node_t *n)
{
	//return (zis2_char_t *)(&n->depth);
	return (zis2_char_t *)(n + 1);
}

static size_t node_hashable_length(const zis2_tree_t *t, const zis2_node_t *n)
{
	return (t->has_bitmap ? BITMAP_SIZE : 0) + (n->capacity * t->hash_len);
}

#define node_foreach(t, n, iter_name) \
	for (zis2_node_t **__node_foreach_start = node_pchild((t), (n), 0), \
	                 **__node_foreach_end   = __node_foreach_start + (n)->size, \
	                 **__node_foreach_cur   = __node_foreach_start, \
	                 *iter_name             = *__node_foreach_cur; \
	     __node_foreach_cur != __node_foreach_end; \
	     iter_name = *++__node_foreach_cur)

static zis2_char_t *node_leaf_at(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx)
{
	while (isbranch(t, n)) {
		n = node_child(t, n, idx);
		idx = 0;
	}
	return node_hash_at(t, n, idx);
	//return isbranch(t, n) ? node_child(t, n, idx)->any_leaf : node_hash_at(t, n, idx);
}


/*static int node_cmp(const zis2_tree_t *t, const zis2_node_t *n, zis2_size_t idx, const zis2_char_t *hash)
{
	if (isbranch(t, n)) {
		return memcmp(node_leaf_at(t, n, idx), hash, n->depth + 1);
	} else {
		return memcmp(node_hash_at(t, n, idx), hash, t->hash_len); // in fact, leading n->depth bytes could be skipped from comparing
	}
}*/

static zis2_size_t node_bsearch(const zis2_tree_t *t, const zis2_node_t *n, const zis2_char_t *hash, bool *hit)
{
	zis2_size_t beg = 0, end = n->size;

	if (end == 0) {
		return 0;
	}

	if (isbranch(t, n)) {
		zis2_node_t **pchilds = node_pchild(t, n, 0);
		zis2_char_t ref = hash[n->depth];
		while (beg < end) {
			zis2_size_t mid = (beg + end) / 2;
			zis2_char_t found = (pchilds[mid])->order;
			if (found == ref) {
				*hit = true;
				return mid;
			} else if (found > ref) {
				end = mid;
			} else {
				beg = mid + 1;
			}
		}
	} else {
		zis2_char_t *hashes = node_hash_at(t, n, 0);
		while (beg < end) {
			zis2_size_t mid = (beg + end) / 2;
			zis2_char_t *found = hashes + mid * t->hash_len;
			int cmp = memcmp(found, hash, t->hash_len); // in fact, leading n->depth bytes could be skipped from comparing, but this is better aligned
			if (cmp == 0) {
				*hit = true;
				return mid;
			} else if (cmp > 0) {
				end = mid;
			} else {
				beg = mid + 1;
			}
		}
	}

	return beg;
}

static void node_grow(const zis2_tree_t *t, zis2_node_t *n, zis2_size_t at)
{
	assert(n->size < n->capacity);
	assert(at <= n->size);
	zis2_size_t nmove = n->size - at;
	n->size++;
	if (nmove > 0) {
		memmove(node_hash_at(t, n, at + 1), node_hash_at(t, n, at), nmove * t->hash_len);
		if (isbranch(t, n)) {
			memmove(node_pchild(t, n, at + 1), node_pchild(t, n, at), nmove * sizeof(zis2_node_t *));
		}
	}
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

static zis2_node_t *node_new(zis2_tree_t *t, zis2_size_t depth, zis2_char_t order)
{
	size_t asize = node_alloc_size(t, INITIAL_CAPACITY, depth);
	zis2_node_t *n = mm_calloc(t->mm, 1, asize);
	if (n != NULL) {
		n->order = order;
		assert(depth < t->depth);
		n->isbranch = (bool)(depth != t->depth - 1);
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
		invalidate_hash_at(t, n, at);
		return node_add(t, node_pchild(t, n, at), hash);
	}
	if (!isbranch(t, n) && hit && t->no_same_leaf) {
		return -EEXIST;
	}
	if (isbranch(t, n) && !hit) {
		add = node_new(t, n->depth + 1, hash[n->depth]);
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
	invalidate_hash_at(t, n, at);
	if (isbranch(t, n)) {
		zis2_node_t **addto = node_pchild(t, n, at);
		*addto = add;
		ret = node_add(t, addto, hash);
		if (ret == 0 && t->has_bitmap) {
			node_bitmap_set(t, n, hash[n->depth], true);
		}
	} else {
		memcpy(node_hash_at(t, n, at), hash, t->hash_len);
	}
	if (ret == 0) {
		//node_leaf_fix(t, n);
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
		invalidate_hash_at(t, n, at);
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
		//node_leaf_fix(t, n);
	}
	if (isbranch(t, n) && t->has_bitmap) {
		node_bitmap_set(t, n, at, false);
	}
	if (n->capacity >= n->size * 2 + 2 && n->capacity >= 2 * INITIAL_CAPACITY) {
		ret = node_realloc(t, pn, n->capacity / 2);
	}
	return ret;
}

static int node_rehash(zis2_tree_t *t, zis2_node_t *n, zis2_char_t *n_hash, zis2_hash_cb hash_fun, void *hf_ctx)
{
	if (!hash_invalid(n_hash)) {
		return 0;
	}

	if (isbranch(t, n)) {
		uint8_t *child_hash = node_hash_at(t, n, 0);
		node_foreach(t, n, child) {
			int ret = node_rehash(t, child, child_hash, hash_fun, hf_ctx);
			if (ret != 0) {
				return ret;
			}
			child_hash += t->hash_len;
		}
	}

	return hash_fun(n_hash, node_hashable_start(t, n), node_hashable_length(t, n), hf_ctx, t->algorithm);
}

static int node_check(zis2_tree_t *t, zis2_node_t *n)
{
	const zis2_char_t *prev = node_leaf_at(t, n, 0);
	if (n->depth > 0 && prev[n->depth - 1] != n->order) {
		return -ESPIPE;
	}
	for (zis2_size_t i = 1; i < n->size; i++) {
		const zis2_char_t *cur = node_leaf_at(t, n, i);
		if (n->depth > 0 && cur[n->depth - 1] != n->order) {
			return -ESPIPE;
		}
		int cmp = memcmp(cur, prev, t->hash_len);
		if (cmp < 0) {
			return -EILSEQ;
		} else if (cmp == 0 && isbranch(t, n)) {
			return -EEXIST;
		}
		prev = cur;
	}

	zis2_size_t bits = 0;
	const zis2_char_t *cur = node_leaf_at(t, n, 0);
	for (zis2_size_t i = 0; i < node_bitmap_size(t, n); i++) {
		zis2_char_t byte = node_bitmap(t, n)[i];
		for (int j = 0; j < 8 && byte != 0; j++) {
			if (byte & 1) {
				if (cur[n->depth] != i * 8 + j) {
					return -EADV;
				}
				bits++;
				if (bits < n->size) {
					cur = node_leaf_at(t, n, bits);
				}
			}
			byte >>= 1;
		}
	}
	if (node_bitmap_size(t, n) > 0 && bits != n->size) {
		return -ELNRNG;
	}

	if (n->size > n->capacity || (n->size == 0 && n != t->root) ||
	    n->capacity < INITIAL_CAPACITY ||
	    (n->size * 2 + 2 < n->capacity && n->capacity > INITIAL_CAPACITY)) {
		return -EXFULL;
	}
	if (isbranch(t, n)){
		if (n->capacity > 256) {
			return -EDQUOT;
		}

		node_foreach(t, n, child) {
			int ret = node_check(t, child);
			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

zis2_tree_t *zis2_tree_new(zis2_size_t depth, zis2_size_t hash_len, bool has_bitmap, struct knot_mm *mm)
{
	size_t asize = sizeof(zis2_tree_t) + hash_len;
	zis2_tree_t *t = mm_calloc(mm, 1, asize);
	if (t != NULL) {
		t->depth = depth;
		t->hash_len = hash_len;
		t->has_bitmap = has_bitmap;
		t->alloc_size = asize;
		t->mm = mm;
		t->root = node_new(t, 0, 0);
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

int zis2_tree_hash(zis2_tree_t *tree, zis2_hash_cb hash_fun, void *hf_ctx, zis2_char_t *out)
{
	if (tree == NULL || hash_fun == NULL || out == NULL) {
		return -EINVAL;
	}

	memset(out, 0, tree->hash_len);
	return node_rehash(tree, tree->root, out, hash_fun, hf_ctx);
}

int zis2_tree_check(zis2_tree_t *tree)
{
	if (tree == NULL || tree->root == NULL) {
		return -EINVAL;
	}
	return node_check(tree, tree->root);
}

#include <stdio.h>

static void print_hash(zis2_char_t *hash, zis2_size_t len)
{
	const static char hex[] = "0123456789abcdef";
	for (zis2_size_t i = 0; i < len; i++) {
		putchar(hex[ hash[i] >> 4 ]);
		putchar(hex[ hash[i] & 15 ]);
	}
}

static void print_depth(zis2_size_t depth, bool last_child)
{
	static const char pipes[] = "||||||||||||||||||||||||||||||||";
	if (depth > 0) {
		printf("%.*s%c%c%c", depth - 1, pipes, 0xe2, 0x94, last_child ? 0x94 : 0x9c);
	}
}

static void node_print(zis2_tree_t *t, zis2_node_t *n, zis2_char_t *n_hash, bool last_child)
{
	print_depth(n->depth, last_child);

	printf("* [%02x] ", n->order);

	if (isbranch(t, n)) {
		if (t->has_bitmap) {
			printf("b:");
			print_hash(node_bitmap(t, n), node_bitmap_size(t, n));
			printf(" ");
		}
	}

	if (n_hash != NULL) {
		print_hash(n_hash, t->hash_len);
		printf("\n");
	} else {
		printf("(root)\n");
	}

	if (isbranch(t, n)) {
		uint8_t *child_hash = node_hash_at(t, n, 0);
		zis2_node_t *last = node_child(t, n, n->size - 1);
		node_foreach(t, n, child) {
			node_print(t, child, child_hash, child == last);
			child_hash += t->hash_len;
		}
	} else {
		for (zis2_size_t i = 0; i < n->size; i++) {
			print_depth(n->depth + 1, i == n->size - 1);
			print_hash(node_hash_at(t, n, i), t->hash_len);
			printf("\n");
		}
	}
}

void zis2_tree_print(zis2_tree_t *tree)
{
	if (tree == NULL) {
		printf("(NULL)\n");
	} else {
		node_print(tree, tree->root, NULL, false);
	}
}

