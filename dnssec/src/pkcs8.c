#include <assert.h>

#include "error.h"
#include "key.h"

static int keydir_open(void *context, const char *path)
{
	return DNSSEC_ERROR;
}

static int keydir_close(void *context)
{
	return DNSSEC_ERROR;
}

static int keydir_refresh(void *context)
{
	return DNSSEC_ERROR;
}

static int keydir_load_key(void *context, dnssec_key_id_t key_id, dnssec_binary_t data)
{
	return DNSSEC_ERROR;
}

static int keydir_store_key(void *context, dnssec_key_id_t key_id, dnssec_binary_t data)
{
	return DNSSEC_ERROR;
}

//static dnssec_key_storage_keydir_implementation = {
//	.open = keydir_open,
//	.close = keydir_close,
//	.refresh = keydir_refresh,
//	.load_key = keydir_load_key,
//	.generate_key = keydir_generate_key
//};
