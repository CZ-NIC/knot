#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "binary.h"
#include "error.h"
#include "key.h"
#include "keystore.h"
#include "shared.h"
#include "keystore/internal.h"

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

/*!
 * Context for PKCS #8 key directory.
 */
typedef struct pkcs8_dir_handle {
	char *dir_name;
} pkcs8_dir_handle_t;

/* -- internal functions --------------------------------------------------- */

/*!
 * Normalize path to a directory.
 */
static char *normalize_dir(const char *path)
{
	char real[MAX_PATH] = { '\0' };
	if (!realpath(path, real)) {
		return NULL;
	};

	struct stat st = { 0 };
	if (stat(real, &st) == -1) {
		return NULL;
	}

	if (!S_ISDIR(st.st_mode)) {
		return NULL;
	}

	return strdup(real);
}

/*!
 * Get path to a private key in PKCS #8 PEM format.
 */
static char *key_path(const char *dir, const dnssec_key_id_t id)
{
	char buffer[MAX_PATH] = { 0 };

	_cleanup_free_ char *keyname = dnssec_key_id_to_string(id);
	if (!keyname) {
		return NULL;
	}

	int wrote = snprintf(buffer, MAX_PATH, "%s/%s.pem", dir, keyname);
	if (wrote < 0 || wrote > MAX_PATH) {
		return NULL;
	}

	return strdup(buffer);
}

/*!
 * Get size of the file and reset the position to the beginning of the file.
 */
static int file_size(int fd, size_t *size)
{
	loff_t offset = lseek(fd, 0, SEEK_END);
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
static int key_open(const char *dir_name, const dnssec_key_id_t id, int flags,
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

static int key_open_read(const char *dir_name, const dnssec_key_id_t id, int *fd_ptr)
{
	return key_open(dir_name, id, O_RDONLY, 0, fd_ptr);
}

static int key_open_write(const char *dir_name, const dnssec_key_id_t id, int *fd_ptr)
{
	return key_open(dir_name, id, O_WRONLY|O_CREAT|O_EXCL,
			S_IRUSR|S_IWUSR|S_IRGRP, fd_ptr);
}

/* -- PKCS #8 dir access API ----------------------------------------------- */

static int pkcs8_dir_open(void **handle_ptr, const char *path)
{
	if (!handle_ptr || !path) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = calloc(1, sizeof(pkcs8_dir_handle_t));
	if (!handle) {
		return DNSSEC_ENOMEM;
	}

	handle->dir_name = normalize_dir(path);
	if (!handle->dir_name) {
		free(handle);
		return DNSSEC_ERROR;
	}

	*handle_ptr = handle;

	return DNSSEC_EOK;
}

static int pkcs8_dir_close(void *_handle)
{
	if (!_handle) {
		return DNSSEC_EINVAL;
	}

	pkcs8_dir_handle_t *handle = _handle;

	free(handle->dir_name);
	free(handle);

	return DNSSEC_EOK;
}

static int pkcs8_dir_read(void *_handle, const dnssec_key_id_t id, dnssec_binary_t *pem)
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

static int pkcs8_dir_write(void *_handle, const dnssec_key_id_t id, const dnssec_binary_t *pem)
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

const dnssec_keystore_pkcs8_functions_t PKCS8_DIR_FUNCTIONS = {
	.open    = pkcs8_dir_open,
	.close   = pkcs8_dir_close,
	.read    = pkcs8_dir_read,
	.write   = pkcs8_dir_write,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_create_pkcs8_dir(dnssec_keystore_t **store_ptr,
				     const char *path)
{
	if (!store_ptr || !path) {
		return DNSSEC_EINVAL;
	}

	return dnssec_keystore_create_pkcs8_custom(store_ptr,
						   &PKCS8_DIR_FUNCTIONS,
						   path);
}
