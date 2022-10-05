/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <gnutls/gnutls.h>
#include <pthread.h>

#include "contrib/string.h"
#include "libdnssec/error.h"
#include "libdnssec/keyid.h"
#include "libdnssec/shared/keyid_gnutls.h"
#include "libdnssec/keystore.h"
#include "libdnssec/keystore/internal.h"
#include "libdnssec/p11/p11.h"
#include "libdnssec/pem.h"
#include "libdnssec/shared/shared.h"

#ifdef ENABLE_PKCS11

struct pkcs11_ctx {
	char *url;
};

typedef struct pkcs11_ctx pkcs11_ctx_t;

/*!
 * Flags used when generating/import key into the token.
 */
static const int TOKEN_ADD_FLAGS = GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE
				 | GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE;

static int key_url(const char *token_uri, const char *key_id, char **url_ptr)
{
	assert(token_uri);
	assert(key_id);
	assert(url_ptr);

	if (!dnssec_keyid_is_valid(key_id)) {
		return DNSSEC_INVALID_KEY_ID;
	}

	size_t token_len = strlen(token_uri);
	size_t id_len = strlen(key_id);

	// url: <token-url>;id=%aa%bb%cc..

	size_t len = token_len + 4 + (id_len / 2 * 3);
	char *url = malloc(len + 1);
	if (!url) {
		return DNSSEC_ENOMEM;
	}

	size_t prefix = snprintf(url, len, "%s;id=", token_uri);
	if (prefix != token_len + 4) {
		free(url);
		return DNSSEC_ENOMEM;
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

	*url_ptr = url;
	return DNSSEC_EOK;
}

/*!
 * Parse configuration string. Accepted format: "<pkcs11-url> <module-path>"
 */
static int parse_config(const char *config, char **uri_ptr, char **module_ptr)
{
	const char *space = strchr(config, ' ');
	if (!space) {
		return DNSSEC_KEYSTORE_INVALID_CONFIG;
	}

	char *url = strndup(config, space - config);
	char *module = strdup(space + 1);

	if (!url || !module) {
		free(url);
		free(module);
		return DNSSEC_ENOMEM;
	}

	*uri_ptr = url;
	*module_ptr = module;

	return DNSSEC_EOK;
}

/*!
 * Load PKCS #11 module and check if the token is available.
 */
static int safe_open(const char *config, char **url_ptr)
{
	char *url = NULL;
	char *module = NULL;

	int r = parse_config(config, &url, &module);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = p11_load_module(module);
	free(module);
	if (r != GNUTLS_E_SUCCESS) {
		free(url);
		return DNSSEC_P11_FAILED_TO_LOAD_MODULE;
	}

	unsigned int flags = 0;
	r = gnutls_pkcs11_token_get_flags(url, &flags);
	if (r != GNUTLS_E_SUCCESS) {
		free(url);
		return DNSSEC_P11_TOKEN_NOT_AVAILABLE;
	}

	*url_ptr = url;

	return DNSSEC_EOK;
}

/* -- internal API --------------------------------------------------------- */

static void disable_pkcs11_callbacks(void)
{
	gnutls_pkcs11_set_pin_function(NULL, NULL);
	gnutls_pkcs11_set_token_function(NULL, NULL);
}

static int pkcs11_ctx_new(void **ctx_ptr)
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

static void pkcs11_ctx_free(void *ctx)
{
	free(ctx);
}

static int pkcs11_init(void *ctx, const char *config)
{
	/*
	 * Current keystore initialization is idempotent. We don't really
	 * initialize the token because don't want to wipe the data. We just
	 * check that the token is available the same way pkcs11_open() does.
	 */

	_cleanup_free_ char *url = NULL;

	return safe_open(config, &url);
}

static int pkcs11_open(void *_ctx, const char *config)
{
	pkcs11_ctx_t *ctx = _ctx;

	return safe_open(config, &ctx->url);
}

static int pkcs11_close(void *_ctx)
{
	pkcs11_ctx_t *ctx = _ctx;

	free(ctx->url);
	clear_struct(ctx);

	return DNSSEC_EOK;
}

static int pkcs11_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, const char *label, char **id_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;

	uint8_t buf[20] = { 0 };
	gnutls_rnd(GNUTLS_RND_RANDOM, buf, sizeof(buf));
	dnssec_binary_t cka_id = { .data = buf, .size = sizeof(buf) };

	int flags = TOKEN_ADD_FLAGS | GNUTLS_PKCS11_OBJ_FLAG_LOGIN;
	gnutls_datum_t gt_cka_id = binary_to_datum(&cka_id);
	int r = gnutls_pkcs11_privkey_generate3(ctx->url, algorithm, bits, label,
	                                        &gt_cka_id, 0, NULL, 0, flags);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_GENERATE_ERROR;
	}

	char *id = bin_to_hex(cka_id.data, cka_id.size, false);
	if (id == NULL) {
		return DNSSEC_ENOMEM;
	}

	*id_ptr = id;

	return DNSSEC_EOK;
}

static int import_pem(const dnssec_binary_t *pem,
		      gnutls_x509_privkey_t *key_ptr,
		      gnutls_pubkey_t *pubkey_ptr)
{
	gnutls_x509_privkey_t x509_key = NULL;
	gnutls_privkey_t key = NULL;
	gnutls_pubkey_t pubkey = NULL;

	int r = dnssec_pem_to_x509(pem, &x509_key);
	if (r != DNSSEC_EOK) {
		goto fail;
	}

	if (gnutls_privkey_init(&key) != GNUTLS_E_SUCCESS ||
	    gnutls_pubkey_init(&pubkey) != GNUTLS_E_SUCCESS
	) {
		r = DNSSEC_ENOMEM;
		goto fail;
	}

	if (gnutls_privkey_import_x509(key, x509_key, 0) != GNUTLS_E_SUCCESS ||
	    gnutls_pubkey_import_privkey(pubkey, key, 0, 0) != GNUTLS_E_SUCCESS
	) {
		r = DNSSEC_KEY_IMPORT_ERROR;
		goto fail;
	}

fail:
	gnutls_privkey_deinit(key);

	if (r == DNSSEC_EOK) {
		*key_ptr = x509_key;
		*pubkey_ptr = pubkey;
	} else {
		gnutls_x509_privkey_deinit(x509_key);
		gnutls_pubkey_deinit(pubkey);
	}

	return r;
}

static int pkcs11_import_key(void *_ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	_cleanup_pubkey_ gnutls_pubkey_t pubkey = NULL;

	int r = import_pem(pem, &key, &pubkey);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_binary_ dnssec_binary_t id = { 0 };
	r = keyid_x509(key, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	int flags = TOKEN_ADD_FLAGS | GNUTLS_PKCS11_OBJ_FLAG_LOGIN;
	gnutls_datum_t gid = binary_to_datum(&id);

	r = gnutls_pkcs11_copy_x509_privkey2(ctx->url, key, NULL, &gid, 0, flags);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	r = gnutls_pkcs11_copy_pubkey(ctx->url, pubkey, NULL, &gid, 0, flags);
	if (r != GNUTLS_E_SUCCESS) {
		// note, we result with dangling private key in the token
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	*id_ptr = bin_to_hex(id.data, id.size, false);
	if (*id_ptr == NULL) {
		return DNSSEC_ENOMEM;
	}

	return DNSSEC_EOK;
}

static int pkcs11_remove_key(void *_ctx, const char *id)
{
	pkcs11_ctx_t *ctx = _ctx;

	_cleanup_free_ char *url = NULL;
	int r = key_url(ctx->url, id, &url);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = gnutls_pkcs11_delete_url(url, GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
	if (r < 0) {
		return DNSSEC_ERROR;
	} else if (r == 0) {
		return DNSSEC_ENOENT;
	}

	return DNSSEC_EOK;
}

static int pkcs11_get_private(void *_ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	pkcs11_ctx_t *ctx = _ctx;

	_cleanup_free_ char *url = NULL;
	int r = key_url(ctx->url, id, &url);
	if (r != DNSSEC_EOK) {
		return r;
	}

	gnutls_privkey_t key = NULL;
	r = gnutls_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	r = gnutls_privkey_import_pkcs11_url(key, url);
	if (r != GNUTLS_E_SUCCESS) {
		gnutls_privkey_deinit(key);
		return DNSSEC_NOT_FOUND;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

static int pkcs11_set_private(void *ctx, gnutls_privkey_t key)
{
	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	int r = dnssec_pem_from_privkey(key, &pem);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_free_ char *keyid = NULL;

	return pkcs11_import_key(ctx, &pem, &keyid);
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
		.generate_key = pkcs11_generate_key,
		.import_key   = pkcs11_import_key,
		.remove_key   = pkcs11_remove_key,
		.get_private  = pkcs11_get_private,
		.set_private  = pkcs11_set_private,
	};

	return keystore_create(store_ptr, &IMPLEMENTATION);
}

#else // !ENABLE_PKCS11

_public_
int dnssec_keystore_init_pkcs11(dnssec_keystore_t **store_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

#endif
