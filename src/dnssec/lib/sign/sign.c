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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "bignum.h"
#include "error.h"
#include "key.h"
#include "key/internal.h"
#include "shared.h"
#include "sign.h"
#include "sign/der.h"
#include "wire.h"

/*!
 * Signature format conversion callback.
 *
 * \param ctx   DNSSEC signing context.
 * \param from  Data in source format.
 * \param to    Allocated data in target format.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
typedef int (*signature_convert_cb)(dnssec_sign_ctx_t *ctx,
				    const dnssec_binary_t *from,
				    dnssec_binary_t *to);

/*!
 * Algorithm specific callbacks.
 */
typedef struct algorithm_functions {
	//! Convert X.509 signature to DNSSEC format.
	signature_convert_cb x509_to_dnssec;
	//! Convert DNSSEC signature to X.509 format.
	signature_convert_cb dnssec_to_x509;
} algorithm_functions_t;

/*!
 * DNSSEC signgin context.
 */
struct dnssec_sign_ctx {
	const dnssec_key_t *key;		  //!< Signing key.
	const algorithm_functions_t *functions;	  //!< Implementation specific.

	gnutls_digest_algorithm_t hash_algorithm; //!< Used algorithm.
	gnutls_hash_hd_t hash;			  //!< Hash computation context.
};

/* -- signature format conversions ----------------------------------------- */

/*!
 * Conversion of RSA signature between X.509 and DNSSEC format is a NOOP.
 *
 * \note Described in RFC 3110.
 */
static int rsa_copy_signature(dnssec_sign_ctx_t *ctx,
			      const dnssec_binary_t *from,
			      dnssec_binary_t *to)
{
	assert(ctx);
	assert(from);
	assert(to);

	return dnssec_binary_dup(from, to);
}

static const algorithm_functions_t rsa_functions = {
	.x509_to_dnssec = rsa_copy_signature,
	.dnssec_to_x509 = rsa_copy_signature,
};

/*!
 * Get T value from DSA key public key.
 */
static uint8_t dsa_dnskey_get_t_value(const dnssec_key_t *key)
{
	assert(key);

	if (key->rdata.size <= 4) {
		return 0;
	}

	wire_ctx_t wire = wire_init_binary(&key->rdata);
	wire_seek(&wire, 4);

	return wire_read_u8(&wire);
}

/*!
 * Convert DSA signature to DNSSEC format.
 *
 * \note Described in RFC 2536.
 */
static int dsa_x509_to_dnssec(dnssec_sign_ctx_t *ctx,
			      const dnssec_binary_t *x509,
			      dnssec_binary_t *dnssec)
{
	assert(ctx);
	assert(x509);
	assert(dnssec);

	dnssec_binary_t value_r = { 0 };
	dnssec_binary_t value_s = { 0 };

	int result = dss_sig_value_decode(x509, &value_r, &value_s);
	if (result != DNSSEC_EOK) {
		return result;
	}

	size_t r_size = bignum_size_u(&value_r);
	size_t s_size = bignum_size_u(&value_s);

	if (r_size > 20 || s_size > 20) {
		return DNSSEC_MALFORMED_DATA;
	}

	uint8_t value_t = dsa_dnskey_get_t_value(ctx->key);

	result = dnssec_binary_alloc(dnssec, 41);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(dnssec);
	wire_write_u8(&wire, value_t);
	wire_write_bignum(&wire, 20, &value_r);
	wire_write_bignum(&wire, 20, &value_s);
	assert(wire_tell(&wire) == dnssec->size);

	return DNSSEC_EOK;
}

static int dsa_dnssec_to_x509(dnssec_sign_ctx_t *ctx,
			      const dnssec_binary_t *dnssec,
			      dnssec_binary_t *x509)
{
	assert(ctx);
	assert(dnssec);
	assert(x509);

	if (dnssec->size != 41) {
		return DNSSEC_INVALID_SIGNATURE;
	}

	const dnssec_binary_t value_r = { .size = 20, .data = dnssec->data + 1 };
	const dnssec_binary_t value_s = { .size = 20, .data = dnssec->data + 21 };

	return dss_sig_value_encode(&value_r, &value_s, x509);
}

static const algorithm_functions_t dsa_functions = {
	.x509_to_dnssec = dsa_x509_to_dnssec,
	.dnssec_to_x509 = dsa_dnssec_to_x509,
};

static size_t ecdsa_sign_integer_size(dnssec_sign_ctx_t *ctx)
{
	assert(ctx);

	switch (ctx->hash_algorithm) {
	case GNUTLS_DIG_SHA256: return 32;
	case GNUTLS_DIG_SHA384: return 48;
	default: return 0;
	};
}

/*!
 * Convert ECDSA signature to DNSSEC format.
 *
 * \note Described in RFC 6605.
 */
static int ecdsa_x509_to_dnssec(dnssec_sign_ctx_t *ctx,
				const dnssec_binary_t *x509,
				dnssec_binary_t *dnssec)
{
	assert(ctx);
	assert(x509);
	assert(dnssec);

	dnssec_binary_t value_r = { 0 };
	dnssec_binary_t value_s = { 0 };

	int result = dss_sig_value_decode(x509, &value_r, &value_s);
	if (result != DNSSEC_EOK) {
		return result;
	}

	size_t int_size = ecdsa_sign_integer_size(ctx);
	size_t r_size = bignum_size_u(&value_r);
	size_t s_size = bignum_size_u(&value_s);

	if (r_size > int_size || s_size > int_size) {
		return DNSSEC_MALFORMED_DATA;
	}

	result = dnssec_binary_alloc(dnssec, 2 * int_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = wire_init_binary(dnssec);
	wire_write_bignum(&wire, int_size, &value_r);
	wire_write_bignum(&wire, int_size, &value_s);
	assert(wire_tell(&wire) == dnssec->size);

	return DNSSEC_EOK;
}

static int ecdsa_dnssec_to_x509(dnssec_sign_ctx_t *ctx,
				const dnssec_binary_t *dnssec,
				dnssec_binary_t *x509)
{
	assert(ctx);
	assert(x509);
	assert(dnssec);

	size_t int_size = ecdsa_sign_integer_size(ctx);

	if (dnssec->size != 2 * int_size) {
		return DNSSEC_INVALID_SIGNATURE;
	}

	const dnssec_binary_t value_r = { .size = int_size, .data = dnssec->data };
	const dnssec_binary_t value_s = { .size = int_size, .data = dnssec->data + int_size };

	return dss_sig_value_encode(&value_r, &value_s, x509);
}

static const algorithm_functions_t ecdsa_functions = {
	.x509_to_dnssec = ecdsa_x509_to_dnssec,
	.dnssec_to_x509 = ecdsa_dnssec_to_x509,
};

/* -- crypto helper functions --------------------------------------------- */

static const algorithm_functions_t *get_functions(const dnssec_key_t *key)
{
	uint8_t algorithm = dnssec_key_get_algorithm(key);

	switch ((dnssec_key_algorithm_t)algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return &rsa_functions;
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
		return &dsa_functions;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return &ecdsa_functions;
	case DNSSEC_KEY_ALGORITHM_ED25519:
	case DNSSEC_KEY_ALGORITHM_ED448:
	default:
		return NULL;
	}
}

/**
 * Get digest algorithm used with a given key.
 */
static gnutls_digest_algorithm_t get_digest_algorithm(const dnssec_key_t *key)
{
	uint8_t algorithm = dnssec_key_get_algorithm(key);

	switch ((dnssec_key_algorithm_t)algorithm) {
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
		return GNUTLS_DIG_SHA1;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
		return GNUTLS_DIG_SHA256;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return GNUTLS_DIG_SHA512;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return GNUTLS_DIG_SHA384;
	case DNSSEC_KEY_ALGORITHM_ED25519:
	case DNSSEC_KEY_ALGORITHM_ED448:
	default:
		return GNUTLS_DIG_UNKNOWN;
	}
}

static gnutls_sign_algorithm_t get_sign_algorithm(const dnssec_sign_ctx_t *ctx)
{
	assert(ctx);
	assert(ctx->key && ctx->key->public_key);

	gnutls_pk_algorithm_t pubkey_algorithm =
		gnutls_pubkey_get_pk_algorithm(ctx->key->public_key, NULL);

	return gnutls_pk_to_sign(pubkey_algorithm, ctx->hash_algorithm);
}

/* -- public API ---------------------------------------------------------- */

_public_
int dnssec_sign_new(dnssec_sign_ctx_t **ctx_ptr, const dnssec_key_t *key)
{
	if (!ctx_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_sign_ctx_t *ctx = calloc(1, sizeof(*ctx));

	ctx->key = key;

	ctx->functions = get_functions(key);
	if (ctx->functions == NULL) {
		free(ctx);
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	ctx->hash_algorithm = get_digest_algorithm(key);
	int result = dnssec_sign_init(ctx);
	if (result != DNSSEC_EOK) {
		free(ctx);
		return result;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

_public_
void dnssec_sign_free(dnssec_sign_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->hash) {
		gnutls_hash_deinit(ctx->hash, NULL);
	}

	free(ctx);
}

_public_
int dnssec_sign_init(dnssec_sign_ctx_t *ctx)
{
	if (!ctx) {
		return DNSSEC_EINVAL;
	}

	if (ctx->hash) {
		gnutls_hash_deinit(ctx->hash, NULL);
		ctx->hash = NULL;
	}

	int result = gnutls_hash_init(&ctx->hash, ctx->hash_algorithm);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_SIGN_INIT_ERROR;
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *data)
{
	if (!ctx || !data || !data->data) {
		return DNSSEC_EINVAL;
	}

	int result = gnutls_hash(ctx->hash, data->data, data->size);
	if (result != 0) {
		return DNSSEC_SIGN_ERROR;
	}

	return DNSSEC_EOK;
}

static int finish_hash(dnssec_sign_ctx_t *ctx, gnutls_datum_t *hash)
{
	assert(ctx);
	assert(hash);

	hash->size = gnutls_hash_get_len(ctx->hash_algorithm);
	if (hash->size == 0) {
		return DNSSEC_SIGN_ERROR;
	}

	hash->data = gnutls_malloc(hash->size);
	if (hash->data == NULL) {
		return DNSSEC_ENOMEM;
	}

	gnutls_hash_output(ctx->hash, hash->data);

	return DNSSEC_EOK;
}

_public_
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, dnssec_binary_t *signature)
{
	if (!ctx || !signature) {
		return DNSSEC_EINVAL;
	}

	if (!dnssec_key_can_sign(ctx->key)) {
		return DNSSEC_NO_PRIVATE_KEY;
	}

	_cleanup_datum_ gnutls_datum_t hash = { 0 };
	int result = finish_hash(ctx, &hash);
	if (result != DNSSEC_EOK) {
		return result;
	}

	assert(ctx->key->private_key);
	_cleanup_datum_ gnutls_datum_t raw = { 0 };
	result = gnutls_privkey_sign_hash(ctx->key->private_key,
					  ctx->hash_algorithm,
					  0, &hash, &raw);
	if (result < 0) {
		return DNSSEC_SIGN_ERROR;
	}

	dnssec_binary_t bin_raw = binary_from_datum(&raw);

	return ctx->functions->x509_to_dnssec(ctx, &bin_raw, signature);
}

_public_
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature)
{
	if (!ctx || !signature) {
		return DNSSEC_EINVAL;
	}

	if (!dnssec_key_can_verify(ctx->key)) {
		return DNSSEC_NO_PUBLIC_KEY;
	}

	_cleanup_datum_ gnutls_datum_t hash = { 0 };
	int result = finish_hash(ctx, &hash);
	if (result != DNSSEC_EOK) {
		return result;
	}

	_cleanup_binary_ dnssec_binary_t bin_raw = { 0 };
	result = ctx->functions->dnssec_to_x509(ctx, signature, &bin_raw);
	if (result != DNSSEC_EOK) {
		return result;
	}

	gnutls_datum_t raw = binary_to_datum(&bin_raw);
	gnutls_sign_algorithm_t algorithm = get_sign_algorithm(ctx);

	assert(ctx->key->public_key);
	result = gnutls_pubkey_verify_hash2(ctx->key->public_key, algorithm,
					    0, &hash, &raw);
	if (result == GNUTLS_E_PK_SIG_VERIFY_FAILED) {
		return DNSSEC_INVALID_SIGNATURE;
	} else if (result < 0) {
		return DNSSEC_ERROR;
	}

	return DNSSEC_EOK;
}
