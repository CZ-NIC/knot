/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*hr256rehash_t)(uint8_t *, uint8_t *[], unsigned, unsigned, void *, int);

#pragma pack(push)

typedef struct hr256node {
	unsigned branch_byte;
	uint16_t capacity;
	uint16_t size;
	uint8_t *any_leaf;
	uint8_t *childs_h[];
} hr256node_t;

#pragma pack(pop)

typedef struct {
	unsigned hash_len;
	unsigned algorithm;
	uint8_t *root_h;
	size_t alloc_size;
	struct knot_mm *mm;
} hr256tree_t;

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
int hr256tree_hash(hr256tree_t *t, hr256rehash_t cb, void *ctx, uint8_t **out_hash);

/*!
 * \brief Remove given hash from the tree.
 *
 * \retval 0        All OK.
 * \retval -ENOENT  Hash was not present, no changes made.
 * \retval -EINVAL  Called with NULL parameter.
 * \retval (Any non-zero error from rehash_cb(): the tree is broken and SHOULD be cleared.)
 */
int hr256tree_rem(hr256tree_t *t, const uint8_t *hash);

/*!
 * \brief Add given hash to the tree.
 *
 * \retval 0        All OK.
 * \retval -EEXIST  Hash was already present, no changes made.
 * \retval -EINVAL  Called with NULL parameter.
 * \retval (Any non-zero error from rehash_cb(): the tree is broken and SHOULD be cleared.)
 */
int hr256tree_add(hr256tree_t *t, const uint8_t *hash);

/*!
 * \brief Check if tree is empty.
 */
bool hr256tree_empty(const hr256tree_t *t);

/*!
 * \brief Free all nodes and empty the tree.
 */
void hr256tree_clear(hr256tree_t *t);

/*!
 * \brief Print the tree human-readably to stdout.
 */
void hr256tree_print(const hr256tree_t *t);

