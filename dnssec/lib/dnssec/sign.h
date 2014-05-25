/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*!
 * \file
 *
 * DNSSEC signing API.
 *
 * \defgroup sign Sign
 *
 * DNSSEC signing API.
 *
 * The module provides the low level DNSSEC signing and verification.
 *
 * Example of signature validation:
 *
 * ~~~~~ {.c}
 *
 * dnssec_key_t *dnskey = // ... ;
 * dnssec_binary_t *rrsig_header = // ... ;
 * dnssec_binary_t *covered_rdata = // ... ;
 * dnssec_binary_t *signature = // ... ;
 *
 * int result;
 * dnssec_sign_ctx_t *ctx = NULL;
 *
 * result = dnssec_sign_new(&ctx, dnskey);
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * dnssec_sign_add(ctx, rrsig_header);
 * dnssec_sign_add(ctx, covered_rdata);
 *
 * result = dnssec_sign_verify(ctx, signature);
 * if (result == DNSSEC_EOK) {
 *     // valid signature
 * } else if (result == DNSSEC_INVALID_SIGNATURE) {
 *     // invalid signature
 * } else {
 *     // error
 * }
 *
 * dnssec_sign_free(ctx);
 *
 * ~~~~~
 *
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <dnssec/binary.h>
#include <dnssec/key.h>

struct dnssec_sign_ctx;

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
 * \param signature  Signature to be allocated and written.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, dnssec_binary_t *signature);

/*!
 * Verify DNSSEC signature.
 *
 * \param ctx        Signing context.
 * \param signature  Signature to be verified.
 *
 * \return Error code.
 * \retval DNSSEC_EOK                Validation successful, valid signature.
 * \retval DNSSEC_INVALID_SIGNATURE  Validation successful, invalid signature.
 */
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature);

/** @} */
