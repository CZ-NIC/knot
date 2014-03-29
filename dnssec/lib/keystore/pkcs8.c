#include <assert.h>

#include "error.h"
#include "key.h"
#include "key/algorithm.h"
#include "key/keyid.h"
#include "keystore.h"
#include "keystore/internal.h"
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

static void *pkcs8_ctx_new(void *data)
{
	assert(data);

	pkcs8_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return NULL;
	}

	dnssec_keystore_pkcs8_functions_t *functions = data;
	ctx->functions = functions;

	return ctx;
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

static int pkcs8_generate_key(void *_ctx, dnssec_key_algorithm_t _algorithm,
			      unsigned bits, dnssec_key_id_t new_id)
{
	assert(_ctx);

	pkcs8_ctx_t *ctx = _ctx;

	// check parameters

	gnutls_pk_algorithm_t algorithm = algorithm_to_gnutls(_algorithm);
	if (algorithm == GNUTLS_PK_UNKNOWN) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (!dnssec_algorithm_key_size_check(_algorithm, bits)) {
		return DNSSEC_INVALID_KEY_SIZE;
	}

	// generate the key

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int r = gnutls_x509_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	r = gnutls_x509_privkey_generate(key, algorithm, bits, 0);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_GENERATE_ERROR;
	}

	// export key

	dnssec_key_id_t id = { 0 };
	gnutls_x509_privkey_to_key_id(key, id);

	_cleanup_datum_ gnutls_datum_t pem = { 0 };
	r = gnutls_x509_privkey_export2_pkcs8(key, GNUTLS_X509_FMT_PEM, NULL, 0, &pem);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_EXPORT_ERROR;
	}

	// save key

	dnssec_binary_t data = { 0 };
	datum_to_binary(&pem, &data);
	r = ctx->functions->write(ctx->data, id, &data);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// finish

	dnssec_key_id_copy(id, new_id);

	return DNSSEC_EOK;
}

static int pkcs8_delete_key(void *_ctx, const dnssec_key_id_t id)
{
	pkcs8_ctx_t *ctx = _ctx;
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

const keystore_functions_t PKCS8_FUNCTIONS = {
	.ctx_new = pkcs8_ctx_new,
	.ctx_free = pkcs8_ctx_free,
	.open = pkcs8_open,
	.close = pkcs8_close,
	.list_keys = pkcs8_list_keys,
	.generate_key = pkcs8_generate_key,
	.delete_key = pkcs8_delete_key,
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
