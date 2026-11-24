/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup digest
 *
 * \brief Data hashing operations.
 *
 * @{
 */

#pragma once

#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"

typedef enum {
	DNSSEC_DIGEST_INVALID = 0,
	DNSSEC_DIGEST_SHA384  = 1,
	DNSSEC_DIGEST_SHA512  = 2,
} dnssec_digest_t;

struct dnssec_digest_ctx;
typedef struct dnssec_digest_ctx dnssec_digest_ctx_t;

/*!
 * \brief Length of hash output for given algorithm.
 */
size_t dnssec_digest_length(dnssec_digest_t algorithm);

/*!
 * \brief Initialize digest context.
 *
 * \param algorithm   Hasing algorithm to be used.
 * \param out_ctx     Output: context structure to be initialized.
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_init(dnssec_digest_t algorithm, dnssec_digest_ctx_t **out_ctx);

/*!
 * \brief Free digest context without finishing computation.
 *
 * \param ctx    Digest context to be aborted.
 */
void dnssec_digest_clear(dnssec_digest_ctx_t *ctx);

/*!
 * \brief Digest data.
 *
 * \param ctx    Digest context.
 * \param data   Data to be hashed.
 *
 * \note This function may be invoked repeatedly for single digest context,
 *       hashing all data as concatenated.
 *
 * \return DNSSEC_E*
 *
 * \note If error is returned, the digest context is automatically disposed.
 */
int dnssec_digest(dnssec_digest_ctx_t *ctx, dnssec_binary_t *data);

/*!
 * \brief Finalize digest, dispose digest context and return the hash.
 *
 * \param ctx   Digest context.
 * \param out   Output: computed hash.
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_finish(dnssec_digest_ctx_t *ctx, dnssec_binary_t *out);

/*!
 * \brief Finalize and dispose context, put the hash into pre-allocated buffer.
 *
 * \param ctx   Digest context.
 * \param out   Output: computed hash. Must be pre-allocated to dnssec_digest_length(algorithm).
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_finish2(dnssec_digest_ctx_t *ctx, uint8_t *out);

/*!
 * \brief Hash a single chunk of data in one go.
 *
 * \param algorithm   Hasing algorithm to be used.
 * \param data        Data to be hashed.
 * \param out         Output: computed hash. Must be pre-allocated to dnssec_digest_length(algorithm).
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_fast(dnssec_digest_t algorithm, dnssec_binary_t *data, uint8_t *out);

/*! @} */
