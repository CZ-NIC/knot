/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*hs_rehash_t)(uint8_t *, uint8_t *[], unsigned, unsigned, void *, int);

typedef struct hs_node {
	unsigned capacity;
	unsigned size;
	uint8_t *any_leaf;

	// depth is not stored in hs_node_t, rather maintained while walking the tree

	uint8_t *childs[];
} hs_node_t;

typedef struct {
	unsigned hash_len;
	unsigned algorithm;
	unsigned depth; // 0 actually means 1: root and all hashes below it
	unsigned width_4bits; // 1..4, width from { 16, 256, 4096, 65536 }
	uint8_t *rootp;
	size_t alloc_size;
	struct knot_mm *mm;
} hs_tree_t;

int hs_tree_rem(hs_tree_t *t, const uint8_t *hash);

int hs_tree_add(hs_tree_t *t, const uint8_t *hash);

int hs_tree_hash(hs_tree_t *t, hs_rehash_t cb, void *ctx, uint8_t **out_hash);

bool hs_tree_empty(hs_tree_t *t);

void hs_tree_clear(hs_tree_t *t);

void hs_tree_print(hs_tree_t *t);
