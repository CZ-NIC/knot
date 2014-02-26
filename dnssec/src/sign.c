#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "error.h"
#include "key.h"
#include "sign.h"

struct dnssec_sign_ctx {
	const dnssec_key_t *key;
	const gnutls_hash_hd_t *digest;

	int a[10];
};

dnssec_sign_ctx_t *dnssec_sign_new(dnssec_key_t *key)
{
	if (!key) {
		return NULL;
	}

	dnssec_sign_ctx_t *result = malloc(sizeof(*result));
	assert(sizeof(*result) == sizeof(dnssec_sign_ctx_t));
	memset(result, 0, sizeof(*result));

	result->key = key;


	return result;
}

void dnssec_sign_free(dnssec_sign_ctx_t *ctx)
{
	free(ctx);
}

int dnssec_sign_init(dnssec_sign_ctx_t *ctx)
{
	return DNSSEC_ERROR;
}

int dnssec_sign_add(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size)
{
	return DNSSEC_ERROR;
}

size_t dnssec_sign_size(dnssec_sign_ctx_t *ctx)
{
	return 0;
}

int dnssec_sign_write(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size)
{
	return DNSSEC_ERROR;
}

int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size)
{
	return DNSSEC_ERROR;
}
