/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Microsoft Toeplitz-based hash implementation
 */

#pragma once

#include <assert.h>
#include <stdint.h>

#include "libknot/endian.h"

/*!
 * \brief Computes a Toeplitz hash value for given key and data.
 *
 * \param key       Key vector
 * \param key_len   Length of the key vector in bytes.
 * \param data      Input data to compute hash from.
 * \param data_len  Lenght of the input data in bytes.
 *
 * \return A Toeplitz hash value.
 */
inline static uint32_t toeplitz_hash(const uint8_t *key, const size_t key_len,
                                     const uint8_t *data, const size_t data_len)
{
	assert(key_len >= 4 + 2 * (16 + 2));

	uint32_t key32 = be32toh(*(const uint32_t *)key);
	key += sizeof(uint32_t);

	int ret = 0;

	for (int i = 0; i < data_len; i++) {
		for (int bit = 7; bit >= 0; bit--) {
			if (data[i] & (1 << bit)) {
				ret ^= key32;
			}

			key32 <<= 1;
			key32 |= !!(key[0] & (1 << bit));
		}
		key++;
	}

	return ret;
}

/*!
 * \brief Toeplitz hash context for divided processing.
 */
typedef struct {
	const uint8_t *data;
	const uint8_t *data_end;
	const uint8_t *key;
	uint32_t hash;
	uint32_t key32;
} toeplitz_ctx_t;

inline static void toeplitz_init(toeplitz_ctx_t *ctx, uint8_t count,
                                 const uint8_t *key, const uint8_t key_len,
                                 const uint8_t *data, const uint8_t data_len)
{
	assert(key_len >= 40);

	ctx->data = data;
	ctx->data_end = data + data_len;
	ctx->key = key + sizeof(uint32_t);
	ctx->hash = 0;
	ctx->key32 = be32toh(*(const uint32_t *)key);

	const uint8_t *stop = ctx->data + count;
	assert(stop <= ctx->data_end);

	while (ctx->data < stop) {
		for (int bit = 7; bit >= 0; bit--) {
			if (*ctx->data & (1 << bit)) {
				ctx->hash ^= ctx->key32;
			}

			ctx->key32 <<= 1;
			ctx->key32 |= !!(*ctx->key & (1 << bit));
		}
		ctx->data++;
		ctx->key++;
	}
}

inline static uint32_t toeplitz_finish(toeplitz_ctx_t *ctx)
{
	uint32_t hash = ctx->hash;
	uint32_t key32 = ctx->key32;
	const uint8_t *key = ctx->key;

	for (const uint8_t *in = ctx->data; in < ctx->data_end; in++) {
		for (int bit = 7; bit >= 0; bit--) {
			if (*in & (1 << bit)) {
				hash ^= key32;
			}

			key32 <<= 1;
			key32 |= !!(*key & (1 << bit));
		}
		key++;
	}

	return hash;
}
