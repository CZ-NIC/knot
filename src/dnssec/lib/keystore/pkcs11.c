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
#include "hex.h"
#include "keyid.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"

#ifdef HAVE_GNUTLS_PKCS11_PRIVKEY_GENERATE3
#  define PKCS11_ENABLED
#else
#  undef PKCS11_ENABLED
#endif

#ifdef PKCS11_ENABLED

struct pkcs11_ctx {
	char *url;
	char *pin;
};

typedef struct pkcs11_ctx pkcs11_ctx_t;

static char *key_url(const char *token_uri, const char *key_id)
{
	assert(token_uri);
	assert(key_id);

	if (!dnssec_keyid_is_valid(key_id)) {
		return NULL;
	}

	size_t token_len = strlen(token_uri);
	size_t id_len = strlen(key_id);

	// url: <token-url>;id=%aa%bb%cc..

	size_t len = token_len + 4 + (id_len / 2 * 3);
	char *url = malloc(len + 1);
	if (!url) {
		return NULL;
	}

	size_t prefix = snprintf(url, len, "%s;id=", token_uri);
	if (prefix != token_len + 4) {
		free(url);
		return NULL;
	}

	assert(id_len % 2 == 0);
	char *pos = url + prefix;
	for (int i = 0; i < id_len; i += 2, pos += 3) {
		pos[0] = '%';
		pos[1] = key_id[i];
		pos[2] = key_id[i+1];
	}
	assert(url + len == pos);
	url[len] = '\0';

	return url;
}

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
 * Parse configuration string. Accepted format: "<pkcs11-url>[ <module-path>]"
 */
static int parse_config(const char *config, char **uri_ptr, char **module_ptr)
{
	const char *space = strchr(config, ' ');

	char *url = NULL;
	char *module = NULL;

	if (space != NULL) {
		url = strndup(config, space - config);
		module = strdup(space + 1);
	} else {
		url = strdup(config);
		module = NULL;
	}

	if (!url || (space && !module)) {
		free(url);
		free(module);
		return DNSSEC_ENOMEM;
	}

	*uri_ptr = url;
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
	return DNSSEC_EOK;
}

static int pkcs11_list_keys(void *ctx, dnssec_list_t **list)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, char **id_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;

	uint8_t buf[20] = { 0 };
	gnutls_rnd(GNUTLS_RND_RANDOM, buf, sizeof(buf));
	dnssec_binary_t cka_id = { .data = buf, .size = sizeof(buf) };

	int flags = GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE |
		    GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE |
		    GNUTLS_PKCS11_OBJ_FLAG_LOGIN;

	gnutls_datum_t gt_cka_id = binary_to_datum(&cka_id);
	int r = gnutls_pkcs11_privkey_generate3(ctx->url, algorithm, bits, NULL, &gt_cka_id, 0, NULL, 0, flags);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_GENERATE_ERROR;
	}

	char *id = NULL;
	r = bin_to_hex(&cka_id, &id);
	if (r != DNSSEC_EOK) {
		return DNSSEC_ENOMEM;
	}

	*id_ptr = id;

	return DNSSEC_EOK;
}

static int pkcs11_import_key(void *ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_remove_key(void *_ctx, const char *id)
{
	pkcs11_ctx_t *ctx = _ctx;

	_cleanup_free_ char *url = key_url(ctx->url, id);
	if (!url) {
		return DNSSEC_EINVAL;
	}

	int r = gnutls_pkcs11_delete_url(url, GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ERROR; // TODO
	}

	return DNSSEC_EOK;
}

static int pkcs11_get_private(void *_ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;
	_cleanup_free_ char *url = key_url(ctx->url, id);
	if (!url) {
		return DNSSEC_EINVAL;
	}

	gnutls_privkey_t key = NULL;
	int r = gnutls_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	r = gnutls_privkey_import_pkcs11_url(key, url);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(key);
		return DNSSEC_INVALID_PRIVATE_KEY;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
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

#else // !PKCS11_ENABLED

_public_
int dnssec_keystore_init_pkcs11(dnssec_keystore_t **store_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

#endif
