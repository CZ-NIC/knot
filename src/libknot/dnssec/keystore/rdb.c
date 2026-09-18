/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "contrib/files.h"
#include "contrib/rdb/common.h"
#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"
#include "libknot/dnssec/keystore.h"
#include "libknot/dnssec/keystore/internal.h"
#include "libknot/dnssec/pem.h"
#include "libknot/dnssec/shared/shared.h"
#include "libknot/dnssec/shared/keyid_gnutls.h"

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>

/*!
 * Context for PKCS #8 key directory.
 */
typedef struct {
	redisContext *rdb;
	char *password;
} rdb_handle_t;

#if 0

static bool key_is_duplicate(int open_error, pkcs8_dir_handle_t *handle,
			     const char *id, const dnssec_binary_t *pem)
{
	assert(handle);
	assert(id);
	assert(pem);

	if (open_error != KNOT_EEXIST) {
		return false;
	}

	_cleanup_binary_ dnssec_binary_t old = { 0 };
	int r = pkcs8_dir_read(handle, id, &old);
	if (r != KNOT_EOK) {
		return false;
	}

	return dnssec_binary_cmp(&old, pem) == 0;
}

static int pem_generate(gnutls_pk_algorithm_t algorithm, unsigned bits,
			dnssec_binary_t *pem, const char *password, char **id)
{
	assert(pem);
	assert(id);

	// generate key

	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int r = gnutls_x509_privkey_init(&key);
	if (r != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	r = gnutls_x509_privkey_generate(key, algorithm, bits, 0);
	if (r != GNUTLS_E_SUCCESS) {
		return KNOT_KEY_EGENERATE;
	}

	// convert to PEM and export the ID

	dnssec_binary_t _pem = { 0 };
	r = dnssec_pem_from_x509(key, &_pem, password);
	if (r != KNOT_EOK) {
		return r;
	}

	// export key ID

	char *_id = NULL;
	r = keyid_x509_hex(key, &_id);
	if (r != KNOT_EOK) {
		dnssec_binary_free(&_pem);
		return r;
	}

	*id = _id;
	*pem = _pem;

	return KNOT_EOK;
}
#endif
/* -- internal API --------------------------------------------------------- */

static int rdb_ctx_new(void **ctx_ptr)
{
	if (!ctx_ptr) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return KNOT_ENOMEM;
	}

	*ctx_ptr = ctx;

	return KNOT_EOK;
}

static void rdb_ctx_free(void *ctx)
{
	free(ctx);
}

static int rdb_init(void *ctx, _unused_ const char *config, void *conn)
{
	if (!ctx || !conn) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

	handle->rdb = conn;

	return KNOT_EOK;
}

static int rdb_open(void *ctx, const char *config, const char *password)
{
	if (!ctx || !config) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

	if (!rdb_ping(handle->rdb)) {
		return KNOT_NET_ECONNECT;
	}

	char *pass = NULL;
	if (password) {
		pass = strdup(password);
		if (!pass) {
			return KNOT_ENOMEM;
		}
	}

	handle->password = pass;

	return KNOT_EOK;
}

static int rdb_close(void *ctx)
{
	if (!ctx) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

	free(handle->password);
	memset(handle, 0, sizeof(*handle));

	return KNOT_EOK;
}

static int rdb_generate_key(void *ctx, gnutls_pk_algorithm_t algorithm,
			      unsigned bits, const char *label, char **id_ptr)
{
	if (!ctx || !id_ptr) {
		return KNOT_EINVAL;
	}

	(void)label;

	rdb_handle_t *handle = ctx;

/*
	// generate key

	char *id = NULL;
	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	int r = pem_generate(algorithm, bits, &pem, handle->password, &id);
	if (r != KNOT_EOK) {
		return r;
	}

	// create the file

	_cleanup_close_ int file = -1;
	r = key_open_write(handle->dir_name, id, &file);
	if (r != KNOT_EOK) {
		if (key_is_duplicate(r, handle, id, &pem)) {
			return KNOT_EOK;
		}
		free(id);
		return r;
	}

	// write the data

	ssize_t wrote_count = write(file, pem.data, pem.size);
	if (wrote_count == -1) {
		free(id);
		return knot_map_errno();
	}

	assert(wrote_count == pem.size);

	// finish

	*id_ptr = id;

*/
	return KNOT_EOK;
}

static int rdb_import_key(void *ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	if (!ctx || !pem || !id_ptr) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

/*
	// retrieve key ID

	char *id = NULL;
	_cleanup_x509_privkey_ gnutls_x509_privkey_t key = NULL;
	int r = dnssec_pem_to_x509(pem, &key, handle->password);
	if (r != KNOT_EOK) {
		return r;
	}

	r = keyid_x509_hex(key, &id);
	if (r != KNOT_EOK) {
		return r;
	}

	// create the file

	_cleanup_close_ int file = -1;
	r = key_open_write(handle->dir_name, id, &file);
	if (r != KNOT_EOK) {
		if (key_is_duplicate(r, handle, id, pem)) {
			*id_ptr = id;
			return KNOT_EOK;
		}
		free(id);
		return r;
	}

	// write the data

	ssize_t wrote_count = write(file, pem->data, pem->size);
	if (wrote_count == -1) {
		free(id);
		return knot_map_errno();
	}

	assert(wrote_count == pem->size);

	// finish

	*id_ptr = id;

*/
	return KNOT_EOK;
}

static int rdb_remove_key(void *ctx, const char *id)
{
	if (!ctx || !id) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

/*
	_cleanup_free_ char *filename = key_path(handle->dir_name, id);
	if (!filename) {
		return KNOT_ENOMEM;
	}

	if (unlink(filename) == -1) {
		return knot_map_errno();
	}

*/
	return KNOT_EOK;
}

static int rdb_get_private(void *ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	if (!ctx || !id || !key_ptr) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

/*
	// load private key data

	_cleanup_close_ int file = -1;
	int r = key_open_read(handle->dir_name, id, &file);
	if (r != KNOT_EOK) {
		return r;
	}

	size_t size = 0;
	r = file_size(file, &size);
	if (r != KNOT_EOK) {
		return r;
	}

	if (size == 0) {
		return KNOT_EMALF;
	}

	// read the stored data

	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	r = dnssec_binary_alloc(&pem, size);
	if (r != KNOT_EOK) {
		return r;
	}

	ssize_t read_count = read(file, pem.data, pem.size);
	if (read_count == -1) {
		dnssec_binary_free(&pem);
		return knot_map_errno();
	}

	assert(read_count == pem.size);

	// construct the key

	gnutls_privkey_t key = NULL;
	r = dnssec_pem_to_privkey(&pem, &key, handle->password);
	if (r != KNOT_EOK) {
		return r;
	}

	// finish

	*key_ptr = key;

*/
	return KNOT_EOK;
}

static int rdb_set_private(void *ctx, gnutls_privkey_t key)
{
	if (!ctx) {
		return KNOT_EINVAL;
	}

	rdb_handle_t *handle = ctx;

/*
	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	int r = dnssec_pem_from_privkey(key, &pem, handle->password);
	if (r != KNOT_EOK) {
		return r;
	}

	_cleanup_free_ char *keyid = NULL;

	return pkcs8_import_key(ctx, &pem, &keyid);
*/
return 0;
}

_public_
int dnssec_keystore_init_rdb(dnssec_keystore_t **store_ptr)
{
	static const keystore_functions_t IMPLEMENTATION = {
		.ctx_new      = rdb_ctx_new,
		.ctx_free     = rdb_ctx_free,
		.init         = rdb_init,
		.open         = rdb_open,
		.close        = rdb_close,
		.generate_key = rdb_generate_key,
		.import_key   = rdb_import_key,
		.remove_key   = rdb_remove_key,
		.get_private  = rdb_get_private,
		.set_private  = rdb_set_private,
	};

	return keystore_create(store_ptr, &IMPLEMENTATION);
}

#else // ENABLE_REDIS

_public_
int dnssec_keystore_init_rdb(dnssec_keystore_t **store_ptr)
{
	return KNOT_ENOTSUP;
}

#endif // ENABLE_REDIS
