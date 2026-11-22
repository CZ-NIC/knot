/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*zis2_hash_cb)(uint8_t *, const uint8_t *, size_t, void *, int);

typedef uint32_t zis2_size_t;
typedef uint8_t zis2_char_t;

typedef struct zis2_node {
	zis2_char_t *any_leaf;
	zis2_size_t capacity;
	zis2_size_t size;
	zis2_size_t __alignment_placeholder;
	zis2_size_t depth; // this MUST be the last
	// Follows:
	// bitmap 32B (only if tree->has_bitmap and not leaf parent)
	// child hashes (capacity * tree->hash_len)
	// child pointers (capacity * sizeof(zis2_node *) )
} zis2_node_t;

typedef struct zis2_tree {
	zis2_size_t depth;
	zis2_size_t hash_len;
	size_t alloc_size;
	int algorithm;
	bool has_bitmap;
	bool no_same_leaf;
	zis2_node_t *root;
	struct knot_mm *mm;
	zis2_char_t hash[];
} zis2_tree_t;

/*!
 * \brief Construct new empty tree.
 *
 * \param depth          Desired tree depth.
 * \param hash_len       Length of inserted hashes.
 * \param has_bitmap     Should the branch nodes contain a bitmap?
 * \param mm             Optional: memory allocation pool.
 *
 * \return New tree or NULL if error.
 */
zis2_tree_t *zis2_tree_new(zis2_size_t depth, zis2_size_t hash_len, bool has_bitmap, struct knot_mm *mm);

/*!
 * \brief Free the tree including all its contents.
 */
void zis2_tree_free(zis2_tree_t *tree);

/*!
 * \brief Add a new hash to the tree.
 *
 * \param tree      Tree to add to.
 * \param hash      Hash to add with the length equal to tree->hash_len.
 *
 * \return 0 if OK; -ENOMEM, -EINVAL, if tree->no_same_leaf also -EEXIST
 */
int zis2_tree_add(zis2_tree_t *tree, const zis2_char_t *hash);

/*!
 * \brief Remove a hash from the tree.
 *
 * \param tree      Tree to remove from.
 * \param hash      Hash to be removed, length equals tree->hash_len.
 *
 * \return 0 if OK; -ENOMEM, -EINVAL, -ENOENT
 */
int zis2_tree_rem(zis2_tree_t *tree, const zis2_char_t *hash);
