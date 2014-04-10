#include <gnutls/gnutls.h>

#include "error.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"

/*!
 * PKCS #11 key store context.
 */
typedef struct pkcs11_ctx {
	int tmp;
} pkcs11_ctx_t;

/* -- internal API --------------------------------------------------------- */

static int pkcs11_ctx_new(void **ctx_ptr, _unused_ void *data)
{
	pkcs11_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void pkcs11_ctx_free(void *ctx)
{
	free(ctx);
}

static int pkcs11_open(void *_ctx, const char *config)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_close(void *_ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_list_keys(void *ctx, void *list)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_delete_key(void *_ctx, const char *id)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

const keystore_functions_t PKCS11_FUNCTIONS = {
	.ctx_new = pkcs11_ctx_new,
	.ctx_free = pkcs11_ctx_free,
	.open = pkcs11_open,
	.close = pkcs11_close,
	.list_keys = pkcs11_list_keys,
	.generate_key = pkcs11_generate_key,
	.delete_key = pkcs11_delete_key,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store_ptr, const char *config)
{
	if (!config) {
		return DNSSEC_EINVAL;
	}

	return keystore_create(store_ptr, &PKCS11_FUNCTIONS, NULL, config);
}
