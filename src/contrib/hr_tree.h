/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*hr_rehash_t)(uint8_t *, const uint8_t *, const uint8_t *, void *, int);

#pragma pack(push, 8)

typedef union hr_node {
	struct {
		unsigned branch_bit;
		uint8_t leaf_hash[];
	};
	struct {
		unsigned _branch_bit_placeholder;
		union hr_node *childs[2];
		uint8_t branch_hash[];
	};
} hr_node_t; // NOTE don't forget to updated leaf_size() and branch_size() any time this typedef is modified!

#pragma pack(pop)

typedef struct {
	unsigned hash_len;
	int algorithm;
	hr_node_t *root;
	size_t alloc_size;
	struct knot_mm *mm;
} hr_tree_t;

/*!
 * \brief Return N-th bit of array of bytes.
 *
 * \warning Doesn't check for array bounds.
 */
unsigned bitarray_bit(const uint8_t *bitarray, unsigned bit_idx);

/*!
 * \brief Return index of first bit where the given byte arrays differ.
 *
 * \retval (len * 8)   If the arrays are equal.
 */
unsigned bitarray_diff_idx(const uint8_t *a, const uint8_t *b, unsigned len);

/*!
 * \brief Recalculate hashes in the tree and return the resulting hash of the whole tree.
 *
 * \param t          Tree.
 * \param cb         Hashing callback.
 * \param ctx        Arbitraty context for the callback.
 * \param out_hash   Out: pointer at resulting hash.
 *
 * \return Error from hash callback.
 */
int hr_tree_hash(hr_tree_t *t, hr_rehash_t cb, void *ctx, uint8_t **out_hash);

/*!
 * \brief Remove given hash from the tree.
 *
 * \retval 0        All OK.
 * \retval -ENOENT  Hash was not present, no changes made.
 * \retval -EINVAL  Called with NULL parameter.
 * \retval (Any non-zero error from rehash_cb(): the tree is broken and SHOULD be cleared.)
 */
int hr_tree_rem(hr_tree_t *t, const uint8_t *hash);

/*!
 * \brief Add given hash to the tree.
 *
 * \retval 0        All OK.
 * \retval -EEXIST  Hash was already present, no changes made.
 * \retval -EINVAL  Called with NULL parameter.
 * \retval (Any non-zero error from rehash_cb(): the tree is broken and SHOULD be cleared.)
 */
int hr_tree_add(hr_tree_t *t, const uint8_t *hash);

/*!
 * \brief Check if tree is empty.
 */
bool hr_tree_empty(hr_tree_t *t);

/*!
 * \brief Free all nodes and empty the tree.
 */
void hr_tree_clear(hr_tree_t *t);

/*!
 * \brief Print the tree human-readably to stdout.
 */
void hr_tree_print(hr_tree_t *t);
