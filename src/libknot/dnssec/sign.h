/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \addtogroup sign
 *
 * \brief DNSSEC signing API
 *
 * The module provides the low level DNSSEC signing and verification.
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/key.h"

struct dnssec_sign_ctx;

typedef enum {
	DNSSEC_SIGN_NORMAL       = 0,
	DNSSEC_SIGN_REPRODUCIBLE = (1 << 0),
} dnssec_sign_flags_t;

/*!
 * DNSSEC signing context.
 */
typedef struct dnssec_sign_ctx dnssec_sign_ctx_t;

/*!
 * Create new DNSSEC signing context.
 *
 * \note \ref dnssec_sign_init is called as a part of this function.
 *
 * \param ctx_ptr  Pointer to context to be allocated.
 * \param key      DNSSEC key to be used.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_sign_new(dnssec_sign_ctx_t **ctx_ptr, const dnssec_key_t *key);

/*!
 * Free DNSSEC signing context.
 *
 * \param ctx  Signing context to be freed.
 */
void dnssec_sign_free(dnssec_sign_ctx_t *ctx);

/*!
 * Reinitialize DNSSEC signing context to start a new operation.
 *
 * \param ctx  Signing context.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_sign_init(dnssec_sign_ctx_t *ctx);

/*!
 * Add data to be covered by DNSSEC signature.
 *
 * \param ctx   Signing context.
 * \param data  Data to be signed.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *data);

/*!
 * Write down the DNSSEC signature.
 *
 * \param ctx        Signing context.
 * \param flags      Additional flags to be used for signing.
 * \param signature  Signature to be allocated and written.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, dnssec_sign_flags_t flags,
                      dnssec_binary_t *signature);

/*!
 * Verify DNSSEC signature.
 *
 * \param ctx        Signing context.
 * \param sign_cmp   Verify by signing and comparing signatures.
 *                   Not possible for non-deterministic algorithms!
 * \param signature  Signature to be verified.
 *
 * \return Error code.
 * \retval DNSSEC_EOK                Validation successful, valid signature.
 * \retval DNSSEC_INVALID_SIGNATURE  Validation successful, invalid signature.
 */
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, bool sign_cmp,
                       const dnssec_binary_t *signature);

/*! @} */
