#include <assert.h>
#include <stdlib.h>

#include "error.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"

/* -- private API ---------------------------------------------------------- */

int keystore_create(dnssec_keystore_t **store_ptr,
		    const keystore_functions_t *functions,
		    void *ctx_custom_data, const char *open_config)
{
	assert(store_ptr);
	assert(functions);

	dnssec_keystore_t *store = calloc(1, sizeof(*store));
	if (!store) {
		return DNSSEC_ENOMEM;
	}

	store->functions = functions;

	store->ctx = functions->ctx_new(ctx_custom_data);
	if (!store->ctx) {
		free(store);
		return DNSSEC_ENOMEM;
	}

	int result = functions->open(store->ctx, open_config);
	if (result != DNSSEC_EOK) {
		dnssec_keystore_close(store);
		return result;
	}

	*store_ptr = store;
	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_close(dnssec_keystore_t *store)
{
	if (!store) {
		return DNSSEC_EINVAL;
	}

	store->functions->close(store->ctx);
	free(store->ctx);
	free(store);

	return DNSSEC_EOK;
}

_public_
int dnssec_keystore_list_keys(dnssec_keystore_t *store, void *list)
{
	if (!store || !list) {
		return DNSSEC_EINVAL;
	}

	return store->functions->list_keys(store, list);

}

_public_
int dnssec_keystore_generate_key(dnssec_keystore_t *store,
				 dnssec_key_algorithm_t algorithm,
				 unsigned bits, dnssec_key_id_t key_id)
{
	if (!store || !algorithm || !key_id) {
		return DNSSEC_EINVAL;
	}

	return store->functions->generate_key(store, algorithm, bits, key_id);
}

_public_
int dnssec_keystore_delete_key(dnssec_keystore_t *store,
			       const dnssec_key_id_t key_id)
{
	if (!store || !key_id) {
		return DNSSEC_EINVAL;
	}

	return store->functions->delete_key(store, key_id);
}
