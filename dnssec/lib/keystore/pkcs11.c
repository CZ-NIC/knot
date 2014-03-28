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

static void *pkcs11_ctx_new(_unused_ void *data)
{
	return calloc(1, sizeof(pkcs11_ctx_t));
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

static int pkcs11_generate_key(void *_ctx, dnssec_key_algorithm_t algorithm,
			       unsigned bits, dnssec_key_id_t id)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_delete_key(void *_ctx, const dnssec_key_id_t id)
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

int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store_ptr, const char *config)
{
	if (!config) {
		return DNSSEC_EINVAL;
	}

	return keystore_create(store_ptr, &PKCS11_FUNCTIONS, NULL, config);
}
