/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "contrib/files.h"
#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key/algorithm.h"
#include "libdnssec/keyid.h"
#include "libdnssec/keystore.h"
#include "libdnssec/keystore/internal.h"
#include "libdnssec/shared/pem.h"
#include "libdnssec/shared/shared.h"

#define DIR_INIT_MODE 0750

/*!
 * Context for PKCS #8 key directory.
 */
typedef struct pkcs8_dir_handle {
	char *dir_name;
} pkcs8_dir_handle_t;

/* -- internal functions --------------------------------------------------- */

/*!
 * Get path to a private key in PKCS #8 PEM format.
 */
static char *key_path(const char *dir, const char *id)
{
	char *strp = NULL;

	int ret = asprintf(&strp, "%s/%s.pem", dir, id);
	if (ret < 0) {
		return NULL;
	}
	return strp;
}

/*!
 * Get size of the file and reset the position to the beginning of the file.
 */
static int file_size(int fd, size_t *size)
{
	off_t offset = lseek(fd, 0, SEEK_END);
	if (offset == -1) {
		return dnssec_errno_to_error(errno);
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		return dnssec_errno_to_error(errno);
	}

	assert(offset >= 0);
	*size = offset;

	return DNSSEC_EOK;
}

/*!
 * Open a key file and get the descriptor.
 */
static int key_open(const char *dir_name, const char *id, int flags,
		    mode_t mode, int *fd_ptr)
{
	assert(dir_name);
	assert(id);
	assert(fd_ptr);

	_cleanup_free_ char *filename = key_path(dir_name, id);
	if (!filename) {
		return DNSSEC_ENOMEM;
	}

	int fd = open(filename, flags, mode);
	if (fd == -1) {
		return dnssec_errno_to_error(errno);
	}

	*fd_ptr = fd;

	return DNSSEC_EOK;
}

static int key_open_read(const char *dir_name, const char *id, int *fd_ptr)
{
	return key_open(dir_name, id, O_RDONLY, 0, fd_ptr);
}

static int key_open_write(const char *dir_name, const char *id, int *fd_ptr)
{
	return key_open(dir_name, id, O_WRONLY|O_CREAT|O_EXCL,
			S_IRUSR|S_IWUSR|S_IRGRP, fd_ptr);
}

static int pkcs8_dir_read(pkcs8_dir_handle_t *handle, const char *id, dnssec_binary_t *pem)
{
	if (!handle || !id || !pem) {
		return DNSSEC_EINVAL;
	}

	// open file and get it's size

	_cleanup_close_ int file = 0;
	int result = key_open_read(handle->dir_name, id, &file);
	if (result != DNSSEC_EOK) {
		return result;
	}

	size_t size = 0;
	result = file_size(file, &size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	if (size == 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	// read the stored data

	dnssec_binary_t read_pem = { 0 };
	result = dnssec_binary_alloc(&read_pem, size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	ssize_t read_count = read(file, read_pem.data, read_pem.size);
	if (read_count == -1) {
		dnssec_binary_free(&read_pem);
		return dnssec_errno_to_error(errno);
	}

	assert(read_count == read_pem.size);
	*pem = read_pem;

	return DNSSEC_EOK;
}

static bool key_is_duplicate(int open_error, pkcs8_dir_handle_t *handle,
			     const char *id, const dnssec_binary_t *pem)
{
	assert(handle);
	assert(id);
	assert(pem);

	if (open_error != dnssec_errno_to_error(EEXIST)) {
		return false;
	}

	_cleanup_binary_ dnssec_binary_t old = { 0 };
	int r = pkcs8_dir_read(handle, id, &old);
	if (r != DNSSEC_EOK) {
		return false;
	}

	return dnssec_binary_cmp(&old, pem) == 0;
}

/* -- internal API --------------------------------------------------------- */

static int pkcs8_ctx_new(void **ctx_ptr)
{
	if (!ctx_ptr) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	*ctx_ptr = ctx;

	return DNSSEC_EOK;
}

static void pkcs8_ctx_free(void *ctx)
{
	free(ctx);
}

static int pkcs8_init(void *ctx, const char *config)
{
	if (!ctx || !config) {
		return DNSSEC_EINVAL;
	}

	return make_dir(config, DIR_INIT_MODE, true);
}

static int pkcs8_open(void *ctx, const char *config)
{
	if (!ctx || !config) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	char *path = realpath(config, NULL);
	if (!path) {
		return DNSSEC_NOT_FOUND;
	}

	handle->dir_name = path;

	return DNSSEC_EOK;
}

static int pkcs8_close(void *ctx)
{
	if (!ctx) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	free(handle->dir_name);
	memset(handle, 0, sizeof(*handle));

	return DNSSEC_EOK;
}

static int pkcs8_generate_key(void *ctx, gnutls_pk_algorithm_t algorithm,
			      unsigned bits, char **id_ptr)
{
	if (!ctx) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	// generate key

	char *id = NULL;
	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	int r = pem_generate(algorithm, bits, &pem, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// create the file

	_cleanup_close_ int file = 0;
	r = key_open_write(handle->dir_name, id, &file);
	if (r != DNSSEC_EOK) {
		if (key_is_duplicate(r, handle, id, &pem)) {
			return DNSSEC_EOK;
		}
		return r;
	}

	// write the data

	ssize_t wrote_count = write(file, pem.data, pem.size);
	if (wrote_count == -1) {
		return dnssec_errno_to_error(errno);
	}

	assert(wrote_count == pem.size);

	// finish

	*id_ptr = id;

	return DNSSEC_EOK;
}

static int pkcs8_import_key(void *ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	if (!ctx || !pem || !id_ptr) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	// retrieve key ID

	char *id = NULL;
	int r = pem_keyid(pem, &id);
	if (r != DNSSEC_EOK) {
		return r;
	}

	// create the file

	_cleanup_close_ int file = 0;
	r = key_open_write(handle->dir_name, id, &file);
	if (r != DNSSEC_EOK) {
		if (key_is_duplicate(r, handle, id, pem)) {
			return DNSSEC_EOK;
		}
		return r;
	}

	// write the data

	ssize_t wrote_count = write(file, pem->data, pem->size);
	if (wrote_count == -1) {
		return dnssec_errno_to_error(errno);
	}

	assert(wrote_count == pem->size);

	*id_ptr = id;

	return DNSSEC_EOK;
}

static int pkcs8_remove_key(void *ctx, const char *id)
{
	if (!ctx || !id) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	_cleanup_free_ char *filename = key_path(handle->dir_name, id);
	if (!filename) {
		return DNSSEC_ENOMEM;
	}

	if (unlink(filename) == -1) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

static int pkcs8_get_private(void *ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	if (!ctx || !id || !key_ptr) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = ctx;

	// load private key data

	_cleanup_close_ int file = 0;
	int r = key_open_read(handle->dir_name, id, &file);
	if (r != DNSSEC_EOK) {
		return r;
	}

	size_t size = 0;
	r = file_size(file, &size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (size == 0) {
		return DNSSEC_MALFORMED_DATA;
	}

	// read the stored data

	_cleanup_binary_ dnssec_binary_t pem = { 0 };
	r = dnssec_binary_alloc(&pem, size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	ssize_t read_count = read(file, pem.data, pem.size);
	if (read_count == -1) {
		dnssec_binary_free(&pem);
		return dnssec_errno_to_error(errno);
	}

	assert(read_count == pem.size);

	// construct the key

	gnutls_privkey_t key = NULL;
	r = pem_privkey(&pem, &key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_init_pkcs8(dnssec_keystore_t **store_ptr)
{
	static const keystore_functions_t IMPLEMENTATION = {
		.ctx_new      = pkcs8_ctx_new,
		.ctx_free     = pkcs8_ctx_free,
		.init         = pkcs8_init,
		.open         = pkcs8_open,
		.close        = pkcs8_close,
		.generate_key = pkcs8_generate_key,
		.import_key   = pkcs8_import_key,
		.remove_key   = pkcs8_remove_key,
		.get_private  = pkcs8_get_private,
	};

	return keystore_create(store_ptr, &IMPLEMENTATION);
}
