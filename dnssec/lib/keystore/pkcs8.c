#include <assert.h>

#include "error.h"
#include "key/algorithm.h"
#include "key/keyid.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "keystore/pem.h"
#include "shared.h"

/*!
 * PKCS #8 key store context.
 */
typedef struct pkcs8_ctx {
	/*! Storage implementation callbacks. */
	const dnssec_keystore_pkcs8_functions_t *functions;
	/*! Implementation specific context data. */
	void *data;
} pkcs8_ctx_t;

/* -- internal API --------------------------------------------------------- */

static int pkcs8_ctx_new(void **ctx_ptr, void *data)
{
	assert(ctx_ptr);
	assert(data);

	pkcs8_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	dnssec_keystore_pkcs8_functions_t *functions = data;
	ctx->functions = functions;

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void pkcs8_ctx_free(void *ctx)
{
	free(ctx);
}

static int pkcs8_open(void *_ctx, const char *config)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->open(&ctx->data, config);
}

static int pkcs8_close(void *_ctx)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->close(ctx->data);
}

static int pkcs8_list_keys(void *_ctx, void *list)
{
	pkcs8_ctx_t *ctx = _ctx;
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs8_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			      unsigned bits, dnssec_key_id_t id)
{
	assert(_ctx);
	assert(id);

	pkcs8_ctx_t *ctx = _ctx;

	// generate key

	dnssec_key_id_t new_id = { 0 };
	_cleanup_binary_ dnssec_binary_t data = { 0 };
	int r = pem_generate(algorithm, bits, &data, new_id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// save key

	r = ctx->functions->write(ctx->data, id, &data);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// finish

	dnssec_key_id_copy(new_id, id);

	return DNSSEC_EOK;
}

static int pkcs8_delete_key(void *_ctx, const dnssec_key_id_t id)
{
	pkcs8_ctx_t *ctx = _ctx;
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs8_get_private(void *_ctx, const dnssec_key_id_t id,
			     gnutls_privkey_t *key_ptr)
{
	assert(_ctx);
	assert(id);
	assert(key_ptr);

	pkcs8_ctx_t *ctx = _ctx;

	// load private key data

	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	int r = ctx->functions->read(ctx->data, id, &pem);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// construct the key

	gnutls_privkey_t key = NULL;
	dnssec_key_id_t key_id = { 0 };
	r = pem_to_privkey(&pem, &key, key_id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// check the result

	if (!dnssec_key_id_equal(key_id, id)) {
		gnutls_privkey_deinit(key);
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

const keystore_functions_t PKCS8_FUNCTIONS = {
	.ctx_new = pkcs8_ctx_new,
	.ctx_free = pkcs8_ctx_free,
	.open = pkcs8_open,
	.close = pkcs8_close,
	.list_keys = pkcs8_list_keys,
	.generate_key = pkcs8_generate_key,
	.delete_key = pkcs8_delete_key,
	.get_private = pkcs8_get_private,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_create_pkcs8_custom(dnssec_keystore_t **store_ptr,
		const dnssec_keystore_pkcs8_functions_t *store_functions,
		const char *config)
{
	if (!store_ptr || !store_functions) {
		return DNSSEC_EINVAL;
	}

	return keystore_create(store_ptr, &PKCS8_FUNCTIONS,
			       (void *)store_functions, config);
}
