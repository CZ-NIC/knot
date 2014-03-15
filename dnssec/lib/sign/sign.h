#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "key.h"
#include "binary.h"

/*!
 * DNSSEC signing context.
 */
struct dnssec_sign_ctx;
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
 * \return Error code, DNSSEC_EOK if successful.
 * TODO: add retval for failed verification.
 */
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature);
