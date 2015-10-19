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

#include <gnutls/gnutls.h>
#include <pthread.h>

#include "error.h"
#include "hex_gnutls.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"

struct pkcs11_ctx {
	char *url;
	char *pin;
};

typedef struct pkcs11_ctx pkcs11_ctx_t;

/* -- internal API --------------------------------------------------------- */

static void disable_pkcs11_callbacks(void)
{
	gnutls_pkcs11_set_pin_function(NULL, NULL);
	gnutls_pkcs11_set_token_function(NULL, NULL);
}

static int pkcs11_ctx_new(void **ctx_ptr, _unused_ void *data)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	pthread_once(&once, disable_pkcs11_callbacks);

	pkcs11_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

static int pkcs11_ctx_free(void *ctx)
{
	if (ctx) {
		free(ctx);
	}

	return DNSSEC_EOK;
}

static int pkcs11_init(void *ctx, const char *config)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

/**
 * Parse configuration string. Accepted format: "<pkcs11-uri>[ <module-path>]"
 */
static int parse_config(const char *config, char **uri_ptr, char **module_ptr)
{
	const char *space = strchr(config, ' ');

	char *uri = NULL;
	char *module = NULL;

	if (space != NULL) {
		uri = strndup(config, space - config);
		module = strdup(space + 1);
	} else {
		uri = strdup(config);
		module = NULL;
	}

	if (!uri || (space && !module)) {
		free(uri);
		free(module);
		return DNSSEC_ENOMEM;
	}

	*uri_ptr = uri;
	*module_ptr = module;

	return DNSSEC_EOK;
}

static int pkcs11_open(void *_ctx, const char *config)
{
	pkcs11_ctx_t *ctx = _ctx;

	char *module = NULL;
	int r = parse_config(config, &ctx->url, &module);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (module) {
		r = gnutls_pkcs11_add_provider(module, NULL);
		free(module);
		if (r != GNUTLS_E_SUCCESS) {
			return DNSSEC_PKCS11_FAILED_TO_LOAD;
		}
	}

	return DNSSEC_EOK;
}

static int pkcs11_close(void *ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_list_keys(void *ctx, dnssec_list_t **list)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, char **id_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;

	// generate the key in the token

	int flags = GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE |
		    GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE |
		    GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	gnutls_datum_t ckaid = { .data = (uint8_t *)"\x42", .size = 1 };
	_cleanup_datum_ gnutls_datum_t der = { 0 };
	int r = gnutls_pkcs11_privkey_generate3(ctx->url, algorithm, bits, NULL, &ckaid, GNUTLS_X509_FMT_DER, &der, 0, flags);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_GENERATE_ERROR;
	}

	// get the key ID

	_cleanup_pubkey_ gnutls_pubkey_t pubkey = NULL;
	r = gnutls_pubkey_init(&pubkey);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	r = gnutls_pubkey_import(pubkey, &der, GNUTLS_X509_FMT_DER);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	char *id = gnutls_pubkey_hex_key_id(pubkey);
	if (!id) {
		return DNSSEC_ENOMEM;
	}

	*id_ptr = id;
	return DNSSEC_EOK;
}

static int pkcs11_import_key(void *ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_remove_key(void *ctx, const char *id)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_get_private(void *ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_init_pkcs11(dnssec_keystore_t **store_ptr)
{
	static const keystore_functions_t IMPLEMENTATION = {
		.ctx_new      = pkcs11_ctx_new,
		.ctx_free     = pkcs11_ctx_free,
		.init         = pkcs11_init,
		.open         = pkcs11_open,
		.close        = pkcs11_close,
		.list_keys    = pkcs11_list_keys,
		.generate_key = pkcs11_generate_key,
		.import_key   = pkcs11_import_key,
		.remove_key   = pkcs11_remove_key,
		.get_private  = pkcs11_get_private,
	};

	return keystore_create(store_ptr, &IMPLEMENTATION, NULL);
}
