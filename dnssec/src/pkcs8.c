#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "shared.h"
#include "error.h"
#include "key.h"
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

static int keydir_load_key(void *context, dnssec_key_id_t key_id, dnssec_binary_t *data)
{
	return DNSSEC_ERROR;
}

static int keydir_store_key(void *context, const dnssec_key_id_t key_id, const dnssec_binary_t *data)
{
	if (!context || !key_id || !data) {
		return DNSSEC_EINVAL;
	}

	keydir_ctx_t *ctx = context;

	char filename[PATH_MAX] = { 0 };
	_cleanup_free_ char *key_id_str = dnssec_key_id_to_string(key_id);

	if (snprintf(filename, PATH_MAX, "%s/%s.pem", ctx->path, key_id_str) < 0) {
		return DNSSEC_ENOMEM;
	}

	// TODO: check existence
	// TODO: create with correct permissions
	_cleanup_fclose_ FILE *keyfile = fopen(filename, "w");
	if (!keyfile) {
		return dnssec_errno_to_error(errno);
	}

	int written = fwrite(data->data, data->size, 1, keyfile);

	return written == 1 ? DNSSEC_EOK : DNSSEC_EIO;
}

//static dnssec_key_storage_keydir_implementation = {
//	.open = keydir_open,
//	.close = keydir_close,
//	.refresh = keydir_refresh,
//	.load_key = keydir_load_key,
//};
