/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "hr_tree.h"

#include "contrib/mempattern.h" // NOTE this include is optional

#ifndef MM_DEFAULT_BLKSIZE
#define mm_alloc(mm, size) malloc(size)
#define mm_free(mm, ptr)   free(ptr)
#endif

unsigned bitarray_bit(const uint8_t *bitarray, unsigned bit_idx)
{
	return (bitarray[bit_idx >> 3] >> (7 - (bit_idx & 0x7))) & 1; // more readable: (bitarray[bit_idx / 8] >> (7 - bit_idx % 8)) & 1
}

static const uint8_t bitarray_ffs[256] = {
	7, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0 // 127 zeroes follow
};

unsigned bitarray_diff_idx(const uint8_t *a, const uint8_t *b, unsigned len)
{
	for (unsigned i = 0; i < len; i++) {
		if (a[i] != b[i]) {
			return i * 8 + bitarray_ffs[a[i] ^ b[i]];
		}
	}

	return len * 8;
}

static unsigned leaf_size(hr_tree_t *t)
{
	return 8 + t->hash_len;
}

static unsigned branch_size(hr_tree_t *t)
{
	return 8 + 2 * 8 + t->hash_len;
}

static bool isbranch(hr_tree_t *t, hr_node_t *n)
{
	assert(n->branch_bit <= t->hash_len * 8);
	return n->branch_bit < t->hash_len * 8;
}

static uint8_t *node_hash(hr_tree_t *t, hr_node_t *n)
{
	return isbranch(t, n) ? n->branch_hash : n->leaf_hash;
}

static unsigned invalid_hash_len(hr_tree_t *t)
{
	return t->hash_len >= 4 ? 4 : t->hash_len;
}

static void invalidate_own_hash(hr_tree_t *t, hr_node_t *n)
{
	assert(isbranch(t, n));
	memset(n->branch_hash, 0, invalid_hash_len(t));
}

static const uint32_t zeroes4 = 0;
static bool invalid_hash(hr_tree_t *t, hr_node_t *n)
{
	assert(isbranch(t, n));
	return memcmp(n->branch_hash, &zeroes4, invalid_hash_len(t)) == 0;
}

static int nrehash(hr_tree_t *t, hr_node_t *n, hr_rehash_t cb, void *ctx)
{
	if (!isbranch(t, n) || !invalid_hash(t, n)) {
		return 0;
	}

	int ret = nrehash(t, n->childs[0], cb, ctx);
	if (ret == 0) {
		ret = nrehash(t, n->childs[1], cb, ctx);
	}
	if (ret == 0) {
                ret = cb(n->branch_hash, node_hash(t, n->childs[0]), node_hash(t, n->childs[1]), ctx, t->algorithm);
	}
	return ret;
}

int hr_tree_hash(hr_tree_t *t, hr_rehash_t cb, void *ctx, uint8_t **out_hash)
{
	if (t == NULL || t->root == NULL || cb == NULL || out_hash == NULL) {
		return -EINVAL;
	}

	int ret = nrehash(t, t->root, cb, ctx);
	if (ret == 0) {
		*out_hash = node_hash(t, t->root);
	}
	return ret;
}

static hr_node_t **next_pp(hr_tree_t *t, hr_node_t *n, const uint8_t *hash)
{
	assert(isbranch(t, n));
	return &n->childs[bitarray_bit(hash, n->branch_bit)];
}

static hr_node_t *next_other(hr_tree_t *t, hr_node_t *n, const uint8_t *hash)
{
	assert(isbranch(t, n));
	return n->childs[bitarray_bit(hash, n->branch_bit) ^ 1];
}

int hr_tree_rem(hr_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}
	if (t->root == NULL) {
		return -ENOENT;
	}
	if (!isbranch(t, t->root)) {
		if (memcmp(t->root->leaf_hash, hash, t->hash_len) != 0) {
			return -ENOENT;
		}
		mm_free(t->mm, t->root);
		t->root = NULL;

		assert(t->alloc_size == leaf_size(t));
		t->alloc_size = 0;
		return 0;
	}
	invalidate_own_hash(t, t->root);

	hr_node_t **prev_pp = &t->root, **cur_pp = next_pp(t, *prev_pp, hash);
	while (isbranch(t, *cur_pp)) {
		invalidate_own_hash(t, *cur_pp);
		prev_pp = cur_pp;
		cur_pp = next_pp(t, *prev_pp, hash);
	}

	hr_node_t *leaf = *cur_pp, *branch = *prev_pp;
	if (memcmp(leaf->leaf_hash, hash, t->hash_len) != 0) {
		return -ENOENT;
	}
	*prev_pp = next_other(t, branch, hash);
	mm_free(t->mm, branch);
	mm_free(t->mm, leaf);

	size_t freed = branch_size(t) + leaf_size(t);
	assert(freed < t->alloc_size);
	t->alloc_size -= freed;

	return 0;
}

int hr_tree_add(hr_tree_t *t, const uint8_t *hash)
{
	if (t == NULL || hash == NULL) {
		return -EINVAL;
	}

	hr_node_t *new_leaf = mm_alloc(t->mm, leaf_size(t));
	if (new_leaf == NULL) {
		return -ENOMEM;
	}
	new_leaf->branch_bit = t->hash_len * 8;
	memcpy(new_leaf->leaf_hash, hash, t->hash_len);

	if (t->root == NULL) {
		t->root = new_leaf;

		assert(t->alloc_size == 0);
		t->alloc_size = leaf_size(t);
		return 0;
	}

	hr_node_t *cur = t->root;
	while (isbranch(t, cur)) {
		cur = *next_pp(t, cur, hash);
	}
	unsigned diff_bit = bitarray_diff_idx(cur->leaf_hash, hash, t->hash_len);
	assert(diff_bit <= t->hash_len * 8);
	if (diff_bit == t->hash_len * 8) {
		mm_free(t->mm, new_leaf);
		return -EEXIST;
	}

	hr_node_t **cur_pp = &t->root;
	while ((*cur_pp)->branch_bit <= diff_bit) {
		assert((*cur_pp)->branch_bit < diff_bit);
		invalidate_own_hash(t, *cur_pp);
		cur_pp = next_pp(t, *cur_pp, hash);
	}

	hr_node_t *new_branch = mm_alloc(t->mm, branch_size(t));
	if (new_branch == NULL) {
		mm_free(t->mm, new_leaf);
		return -ENOMEM;
	}
	new_branch->branch_bit = diff_bit;
	invalidate_own_hash(t, new_branch);
	if (bitarray_bit(hash, diff_bit) == 0) {
		new_branch->childs[0] = new_leaf;
		new_branch->childs[1] = *cur_pp;
	} else {
		new_branch->childs[0] = *cur_pp;
		new_branch->childs[1] = new_leaf;
	}
	*cur_pp = new_branch;

	t->alloc_size += branch_size(t) + leaf_size(t);

	return 0;
}

static void clear_node(hr_tree_t *t, hr_node_t *n)
{
	if (isbranch(t, n)) {
		clear_node(t, n->childs[0]);
		clear_node(t, n->childs[1]);
		t->alloc_size -= branch_size(t);
	} else {
		t->alloc_size -= leaf_size(t);
	}
	mm_free(t->mm, n);
}

bool hr_tree_empty(hr_tree_t *t)
{
	return (t == NULL || t->root == NULL);
}

void hr_tree_clear(hr_tree_t *t)
{
	if (!hr_tree_empty(t)) {
		clear_node(t, t->root);
		t->root = NULL;
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

static void recur_print(hr_tree_t *t, hr_node_t *n, unsigned depth, bool first_child)
{
	static const char pipes[] = "||||||||||||||||||||||||||||||||";
	if (depth > 0) {
                printf("%.*s%c%c%c", depth - 1, pipes, 0xe2, 0x94, first_child ? 0x9c : 0x94);
	}

	if (!isbranch(t, n)) {
		print_hash(n->leaf_hash, t->hash_len);
		return;
	}

	printf("* %u ", n->branch_bit);
	print_hash(n->branch_hash, t->hash_len);

	recur_print(t, n->childs[0], depth + 1, true);
	recur_print(t, n->childs[1], depth + 1, false);
}

void hr_tree_print(hr_tree_t *t)
{
	if (hr_tree_empty(t)) {
		printf("(empty)\n");
	} else {
                recur_print(t, t->root, 0, false);
	}
}
