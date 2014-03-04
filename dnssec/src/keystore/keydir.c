#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "error.h"
#include "key.h"
#include "keystore/keydir.h"
#include "keystore/keystore.h"
#include "shared.h"

typedef struct keydir_ctx {
	char *path;
} keydir_ctx_t;

static int keydir_open(void **context, const char *path)
{
	if (!context || !path) {
		return DNSSEC_EINVAL;
	}

	keydir_ctx_t *ctx = malloc(sizeof(keydir_ctx_t));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	memset(ctx, 0, sizeof(keydir_ctx_t));
	// TODO: convert to absolute path and normalize
	ctx->path = strdup(path);

	*context = ctx;

	return DNSSEC_EOK;
}

static void keydir_close(void *context)
{
	if (!context) {
		return;
	}

	keydir_ctx_t *ctx = context;

	free(ctx->path);
	free(ctx);
}

static int keydir_refresh(void *context)
{
	if (!context) {
		return DNSSEC_EINVAL;
	}

	// nothing to do

	return DNSSEC_EOK;
}

static char *get_key_path(keydir_ctx_t *ctx, dnssec_key_id_t key_id)
{
	assert(key_id);

	_cleanup_free_ char *key_id_str = dnssec_key_id_to_string(key_id);
	if (!key_id_str) {
		return NULL;;
	}

	// <path> / <key-id> .pem <null>
	size_t len = strlen(ctx->path) + 1 + DNSSEC_KEY_ID_STRING_SIZE + 4 + 1;
	char *path = malloc(len);
	if (!path) {
		return NULL;
	}

	int wrote = snprintf(path, len, "%s/%s.pem", ctx->path, key_id_str);
	assert(wrote == len);

	return path;
}

static int keydir_load_key(void *context, dnssec_key_id_t key_id, dnssec_binary_t *data)
{
	if (!context || !key_id || !data) {
		return DNSSEC_EINVAL;
	}

	keydir_ctx_t *ctx = context;

	return DNSSEC_ERROR;
}

static int keydir_store_key(void *context, const dnssec_key_id_t key_id, const dnssec_binary_t *data)
{
	if (!context || !key_id || !data) {
		return DNSSEC_EINVAL;
	}

	keydir_ctx_t *ctx = context;

	_cleanup_free_ char *filename = get_key_path(ctx, key_id);
	if (!filename) {
		return DNSSEC_ENOMEM;
	}

	_cleanup_close_ int fd = open(filename, O_WRONLY|O_CREAT||O_EXCL, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		return dnssec_errno_to_error(errno);
	}

	_cleanup_fclose_ FILE *file = fdopen(fd, "w");
	if (!file) {
		return dnssec_errno_to_error(errno);
	}

	int written = fwrite(data->data, data->size, 1, keyfile);

	return written == 1 ? DNSSEC_EOK : DNSSEC_EIO;
}

const dnssec_keystore_impl_t DNSSEC_KEYSTORE_KEYDIR_IMPL = {
	.foo = 1,
	.bar = 2,
};
