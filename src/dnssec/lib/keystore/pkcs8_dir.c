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

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "binary.h"
#include "error.h"
#include "fs.h"
#include "key.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "path.h"
#include "shared.h"

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
	char buffer[PATH_MAX] = { 0 };
	int wrote = snprintf(buffer, PATH_MAX, "%s/%s.pem", dir, id);
	if (wrote < 0 || wrote >= PATH_MAX) {
		return NULL;
	}

	return strdup(buffer);
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

/*!
 * Strip '.pem' suffix, basename has to be valid key ID.
 */
static char *filename_to_keyid(const char *filename)
{
	assert(filename);

	size_t len = strlen(filename);

	const char ext[] = ".pem";
	const size_t ext_len = sizeof(ext) - 1;

	if (len < ext_len || strcmp(filename + len - ext_len, ext) != 0) {
		return NULL;
	}

	return strndup(filename, len - ext_len);
}

/* -- PKCS #8 dir access API ----------------------------------------------- */

static int pkcs8_dir_handle_new(void **handle_ptr)
{
	if (!handle_ptr) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = calloc(1, sizeof(*handle));
	if (!handle) {
		return DNSSEC_ENOMEM;
	}

	*handle_ptr = handle;

	return DNSSEC_EOK;
}

static int pkcs8_dir_handle_free(void *handle)
{
	free(handle);

	return DNSSEC_EOK;
}

static int pkcs8_dir_init(void *handle, const char *path)
{
	if (!handle || !path) {
		return DNSSEC_EINVAL;
	}

	return fs_mkdir(path, DIR_INIT_MODE, true);
}

static int pkcs8_dir_open(void *_handle, const char *config)
{
	if (!_handle || !config) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

	char *path = path_normalize(config);
	if (!path) {
		return DNSSEC_NOT_FOUND;
	}

	handle->dir_name = path;

	return DNSSEC_EOK;
}

static int pkcs8_dir_close(void *_handle)
{
	if (!_handle) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

	free(handle->dir_name);
	memset(handle, 0, sizeof(*handle));

	return DNSSEC_EOK;
}

static int pkcs8_dir_read(void *_handle, const char *id, dnssec_binary_t *pem)
{
	if (!_handle || !id || !pem) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

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

static int pkcs8_dir_write(void *_handle, const char *id, const dnssec_binary_t *pem)
{
	if (!_handle || !id || !pem) {
		return DNSSEC_EINVAL;
	}

	if (pem->size == 0 || pem->data == NULL) {
		return DNSSEC_MALFORMED_DATA;
	}

	pkcs8_dir_handle_t *handle = _handle;

	// create the file

	_cleanup_close_ int file = 0;
	int result = key_open_write(handle->dir_name, id, &file);
	if (result != DNSSEC_EOK) {
		if (key_is_duplicate(result, handle, id, pem)) {
			return DNSSEC_EOK;
		}
		return result;
	}

	// write the data

	ssize_t wrote_count = write(file, pem->data, pem->size);
	if (wrote_count == -1) {
		return dnssec_errno_to_error(errno);
	}

	assert(wrote_count == pem->size);

	return DNSSEC_EOK;
}

static int pkcs8_dir_list(void *_handle, dnssec_list_t **list_ptr)
{
	if (!_handle || !list_ptr) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

	_cleanup_closedir_ DIR *dir = opendir(handle->dir_name);
	if (!dir) {
		return DNSSEC_NOT_FOUND;
	}

	dnssec_list_t *list = dnssec_list_new();
	if (!list) {
		return DNSSEC_ENOMEM;
	}

	int error;
	struct dirent entry, *result;
	while (error = readdir_r(dir, &entry, &result), error == 0 && result) {
		char *keyid = filename_to_keyid(entry.d_name);
		if (keyid) {
			dnssec_list_append(list, keyid);
		}
	}

	if (error != 0) {
		dnssec_list_free_full(list, NULL, NULL);
		return dnssec_errno_to_error(error);
	}

	*list_ptr = list;

	return DNSSEC_EOK;
}

static int pkcs8_dir_remove(void *_handle, const char *id)
{
	if (!_handle || !id) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

	_cleanup_free_ char *filename = key_path(handle->dir_name, id);
	if (!filename) {
		return DNSSEC_ENOMEM;
	}

	if (unlink(filename) == -1) {
		return dnssec_errno_to_error(errno);
	}

	return DNSSEC_EOK;
}

const dnssec_keystore_pkcs8_functions_t PKCS8_DIR_FUNCTIONS = {
	.handle_new  = pkcs8_dir_handle_new,
	.handle_free = pkcs8_dir_handle_free,
	.init        = pkcs8_dir_init,
	.open        = pkcs8_dir_open,
	.close       = pkcs8_dir_close,
	.read        = pkcs8_dir_read,
	.write       = pkcs8_dir_write,
	.list        = pkcs8_dir_list,
	.remove      = pkcs8_dir_remove,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_init_pkcs8_dir(dnssec_keystore_t **store_ptr)
{
	if (!store_ptr) {
		return DNSSEC_EINVAL;
	}

	return dnssec_keystore_init_pkcs8_custom(store_ptr, &PKCS8_DIR_FUNCTIONS);
}
