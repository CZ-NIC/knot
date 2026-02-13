/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*hs_rehash_t)(uint8_t *, const uint8_t *[], unsigned, unsigned, void *);

typedef struct hs_node {
	unsigned capacity;
	unsigned size;
	// depth is not stored in hs_node_t, rather maintained while walking the tree
	union {
		struct {
			uint8_t *own_hash;
			struct hs_node *branch_childs[];
		};
		struct {
			uint8_t *_placeholder_own_hash;
			uint8_t *leaf_childs[];
		};
	};
} hs_node_t;

typedef struct {
	unsigned hash_len;
	unsigned depth; // 0 actually means 1: root and all hashes below it
	unsigned width_4bits; // 1..4, width from { 16, 256, 4096, 65536 }
	hs_rehash_t rehash_cb;
	void *cb_ctx;
	hs_node_t *root;
	size_t alloc_size;
	struct knot_mm *mm;
} hs_tree_t;


inline static unsigned hs_tree_width(const hs_tree_t *t)
{
	return 1 << (t->width_4bits * 4);
}
