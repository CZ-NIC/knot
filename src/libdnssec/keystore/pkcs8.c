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

#include "error.h"
#include "key/algorithm.h"
#include "keyid.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared/pem.h"
#include "shared/shared.h"

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

static int pkcs8_ctx_new(void **ctx_ptr, void *_functions)
{
	assert(ctx_ptr);
	assert(_functions);

	pkcs8_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	ctx->functions = _functions;

	int r = ctx->functions->handle_new(&ctx->data);
	if (r != DNSSEC_EOK) {
		free(ctx);
		return r;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

static int pkcs8_ctx_free(void *_ctx)
{
	pkcs8_ctx_t *ctx = _ctx;
	int r = ctx->functions->handle_free(ctx->data);

	free(ctx);

	return r;
}

static int pkcs8_init(void *_ctx, const char *config)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->init(ctx->data, config);
}

static int pkcs8_open(void *_ctx, const char *config)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->open(ctx->data, config);
}

static int pkcs8_close(void *_ctx)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->close(ctx->data);
}

static int pkcs8_list_keys(void *_ctx, dnssec_list_t **list)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->list(ctx->data, list);
}

static int pkcs8_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			      unsigned bits, char **id_ptr)
{
	assert(_ctx);
	assert(id_ptr);

	pkcs8_ctx_t *ctx = _ctx;

	// generate key

	char *new_id = NULL;
	_cleanup_binary_ dnssec_binary_t data = { 0 };
	int r = pem_generate(algorithm, bits, &data, &new_id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// save key

	r = ctx->functions->write(ctx->data, new_id, &data);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// finish

	*id_ptr = new_id;

	return DNSSEC_EOK;
}

static int pkcs8_import_key(void *_ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	pkcs8_ctx_t *ctx = _ctx;

	// retrieve key ID

	char *id = NULL;
	int r = pem_keyid(pem, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// save the key

	r = ctx->functions->write(ctx->data, id, pem);
	if (r != DNSSEC_EOK) {
		free(id);
		return r;
	}

	*id_ptr = id;

	return DNSSEC_EOK;
}

static int pkcs8_remove_key(void *_ctx, const char *id)
{
	pkcs8_ctx_t *ctx = _ctx;
	return ctx->functions->remove(ctx->data, id);
}

static int pkcs8_get_private(void *_ctx, const char *id, gnutls_privkey_t *key_ptr)
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
	r = pem_privkey(&pem, &key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

static const keystore_functions_t PKCS8_FUNCTIONS = {
	.ctx_new      = pkcs8_ctx_new,
	.ctx_free     = pkcs8_ctx_free,
	.init         = pkcs8_init,
	.open         = pkcs8_open,
	.close        = pkcs8_close,
	.list_keys    = pkcs8_list_keys,
	.generate_key = pkcs8_generate_key,
	.import_key   = pkcs8_import_key,
	.remove_key   = pkcs8_remove_key,
	.get_private  = pkcs8_get_private,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_init_pkcs8_custom(dnssec_keystore_t **store_ptr,
			const dnssec_keystore_pkcs8_functions_t *store_functions)
{
	if (!store_ptr || !store_functions) {
		return DNSSEC_EINVAL;
	}

	return keystore_create(store_ptr, &PKCS8_FUNCTIONS, (void *)store_functions);
}
