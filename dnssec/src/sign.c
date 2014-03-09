#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "error.h"
#include "key.h"
#include "shared.h"
#include "sign.h"

/*!
 * DNSSEC signgin context.
 */
struct dnssec_sign_ctx {
	const dnssec_key_t *key;		  //!< Signing key.
	const algorithm_functions_t *functions;	  //!< Implementation specific.

	gnutls_digest_algorithm_t hash_algorithm; //!< Used algorithm.
	gnutls_hash_hd_t hash;			  //!< Hash computation context.
};

/**
 * Get digest algorithm used with a given key.
 */
gnutls_digest_algorithm_t get_digest_algorithm(const dnssec_key_t *key)
{
	dnssec_key_algorithm_t key_algorithm = dnssec_key_get_algorithm(key);
	switch (key_algorithm) {
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
	default:
		return GNUTLS_DIG_UNKNOWN;
	}
}

int dnssec_sign_new(dnssec_sign_ctx_t **ctx_ptr, const dnssec_key_t *key)
{
	if (!ctx_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_sign_ctx_t *ctx = malloc(sizeof(*ctx));
	clear_struct(ctx);

	ctx->key = key;
	ctx->hash_algorithm = get_digest_algorithm(key);

	int result = dnssec_sign_init(ctx);
	if (result != DNSSEC_EOK) {
		free(ctx);
		return result;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

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

static gnutls_sign_algorithm_t get_sign_algorithm(const dnssec_sign_ctx_t *ctx)
{
	assert(ctx);
	assert(ctx->key && ctx->key->public_key);

	gnutls_pk_algorithm_t pubkey_algorithm =
		gnutls_pubkey_get_pk_algorithm(ctx->key->public_key, NULL);

	return gnutls_pk_to_sign(pubkey_algorithm, ctx->hash_algorithm);
}

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
	_cleanup_datum_ gnutls_datum_t raw_signature = { 0 };
	result = gnutls_privkey_sign_hash(ctx->key->private_key,
					  ctx->hash_algorithm,
					  0, &hash, &raw_signature);
	if (!result) {
		return DNSSEC_SIGN_ERROR;
	}

	// TODO: conversion

	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature)
{
	if (!ctx || !signature) {
		return DNSSEC_EINVAL;
	}

	if (!dnssec_key_can_sign(ctx->key)) {
		return DNSSEC_NO_PUBLIC_KEY;
	}

	_cleanup_datum_ gnutls_datum_t hash = { 0 };
	int result = finish_hash(ctx, &hash);
	if (result != DNSSEC_EOK) {
		return result;
	}

	_cleanup_datum_ gnutls_datum_t raw_signature = { 0 };
	gnutls_sign_algorithm_t algorithm = get_sign_algorithm(ctx);

	assert(ctx->key->public_key);
	result = gnutls_pubkey_verify_hash2(ctx->key->public_key, algorithm,
					    0, &hash, &raw_signature);
	if (result < 0) {
		assert(result == GNUTLS_E_PK_SIG_VERIFY_FAILED);
		return DNSSEC_INVALID_SIGNATURE;
	}

	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}
