/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "libdnssec/shared/bignum.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/key/internal.h"
#include "libdnssec/shared/shared.h"
#include "libdnssec/sign.h"
#include "libdnssec/sign/der.h"
#include "libdnssec/shared/binary_wire.h"
#include "libdnssec/contrib/vpool.h"

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

typedef struct dnssec_buffer {
	uint8_t *allocd;	//!< Pointer to allocated data.
	uint8_t *data;		//!< API: pointer to data to copy from.
	size_t max_length;
	size_t length;		//!< API: current length.
} dnssec_buffer_t;

/*!
 * DNSSEC signing context.
 */
struct dnssec_sign_ctx {
	const dnssec_key_t *key;		  //!< Signing key.
	const algorithm_functions_t *functions;	  //!< Implementation specific.

	gnutls_sign_algorithm_t sign_algorithm;   //!< Used algorithm for signing.
	struct vpool buffer;                      //!< Buffer for the data to be signed.
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

static size_t ecdsa_sign_integer_size(dnssec_sign_ctx_t *ctx)
{
	assert(ctx);

	switch (ctx->sign_algorithm) {
	case GNUTLS_SIGN_ECDSA_SHA256: return 32;
	case GNUTLS_SIGN_ECDSA_SHA384: return 48;
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

	wire_ctx_t wire = binary_init(dnssec);
	bignum_write(&wire, int_size, &value_r);
	bignum_write(&wire, int_size, &value_s);
	assert(wire_ctx_offset(&wire) == dnssec->size);

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

#define eddsa_copy_signature rsa_copy_signature
static const algorithm_functions_t eddsa_functions = {
	.x509_to_dnssec = eddsa_copy_signature,
	.dnssec_to_x509 = eddsa_copy_signature,
};

#define gost_copy_signature rsa_copy_signature
static const algorithm_functions_t gost_functions = {
	.x509_to_dnssec = gost_copy_signature,
	.dnssec_to_x509 = gost_copy_signature,
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
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return &ecdsa_functions;
	case DNSSEC_KEY_ALGORITHM_ED25519:
	case DNSSEC_KEY_ALGORITHM_ED448:
		return &eddsa_functions;
	case DNSSEC_KEY_ALGORITHM_ECC_GOST:
		return &gost_functions;
	default:
		return NULL;
	}
}

#ifndef HAVE_SIGN_DATA2
/**
 * Get digest algorithm used with a given key.
 */
static gnutls_digest_algorithm_t get_digest_algorithm(const dnssec_key_t *key)
{
	uint8_t algorithm = dnssec_key_get_algorithm(key);

	switch ((dnssec_key_algorithm_t)algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
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
		return GNUTLS_DIG_SHA512;
#ifdef HAVE_GOST
	case DNSSEC_KEY_ALGORITHM_ECC_GOST:
		return GNUTLS_DIG_GOSTR_94;
#endif
	case DNSSEC_KEY_ALGORITHM_ED448:
	default:
		return GNUTLS_DIG_UNKNOWN;
	}
}
#endif

static gnutls_sign_algorithm_t get_sign_algorithm(const dnssec_key_t *key)
{
	uint8_t algorithm = dnssec_key_get_algorithm(key);

	switch ((dnssec_key_algorithm_t)algorithm) {
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1:
	case DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3:
		return GNUTLS_SIGN_RSA_SHA1;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA256:
		return GNUTLS_SIGN_RSA_SHA256;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256:
		return GNUTLS_SIGN_ECDSA_SHA256;
	case DNSSEC_KEY_ALGORITHM_RSA_SHA512:
		return GNUTLS_SIGN_RSA_SHA512;
	case DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384:
		return GNUTLS_SIGN_ECDSA_SHA384;
#ifdef HAVE_ED25519
	case DNSSEC_KEY_ALGORITHM_ED25519:
		return GNUTLS_SIGN_EDDSA_ED25519;
#endif
#ifdef HAVE_ED448
	case DNSSEC_KEY_ALGORITHM_ED448:
		return GNUTLS_SIGN_EDDSA_ED448;
#endif
#ifdef HAVE_GOST
	case DNSSEC_KEY_ALGORITHM_ECC_GOST:
		return GNUTLS_SIGN_GOST_94;
#endif
	default:
		return GNUTLS_SIGN_UNKNOWN;
	}
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

	ctx->sign_algorithm = get_sign_algorithm(key);
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

	vpool_reset(&ctx->buffer);

	free(ctx);
}

_public_
int dnssec_sign_init(dnssec_sign_ctx_t *ctx)
{
	if (!ctx) {
		return DNSSEC_EINVAL;
	}

	if (vpool_get_buf(&ctx->buffer) != NULL) {
		vpool_wipe(&ctx->buffer);
	} else {
		vpool_init(&ctx->buffer, 1024, 0);
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *data)
{
	if (!ctx || !data || !data->data) {
		return DNSSEC_EINVAL;
	}

	void *result = vpool_insert(&ctx->buffer, vpool_get_length(&ctx->buffer), data->data, data->size);
	if (result == NULL) {
		return DNSSEC_SIGN_ERROR;
	}

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

	gnutls_datum_t data = {
		.data = vpool_get_buf(&ctx->buffer),
		.size = vpool_get_length(&ctx->buffer)
	};

	assert(ctx->key->private_key);
	_cleanup_datum_ gnutls_datum_t raw = { 0 };
#ifdef HAVE_SIGN_DATA2
	int result = gnutls_privkey_sign_data2(ctx->key->private_key,
					       ctx->sign_algorithm,
					       0, &data, &raw);
#else
	gnutls_digest_algorithm_t digest_algorithm = get_digest_algorithm(ctx->key);
	int result = gnutls_privkey_sign_data(ctx->key->private_key,
					      digest_algorithm,
					      0, &data, &raw);
#endif
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

	gnutls_datum_t data = {
		.data = vpool_get_buf(&ctx->buffer),
		.size = vpool_get_length(&ctx->buffer)
	};

	_cleanup_binary_ dnssec_binary_t bin_raw = { 0 };
	int result = ctx->functions->dnssec_to_x509(ctx, signature, &bin_raw);
	if (result != DNSSEC_EOK) {
		return result;
	}

	gnutls_datum_t raw = binary_to_datum(&bin_raw);

	assert(ctx->key->public_key);
	result = gnutls_pubkey_verify_data2(ctx->key->public_key,
					    ctx->sign_algorithm,
					    0, &data, &raw);
	if (result == GNUTLS_E_PK_SIG_VERIFY_FAILED) {
		return DNSSEC_INVALID_SIGNATURE;
	} else if (result < 0) {
		return DNSSEC_ERROR;
	}

	return DNSSEC_EOK;
}
