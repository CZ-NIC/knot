#include <assert.h>
#include <stdlib.h>

#include "error.h"
#include "key.h"
#include "key/algorithm.h"
#include "key/dnskey.h"
#include "key/internal.h"
#include "key/keyid.h"
#include "key/privkey.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"
#include "wire.h"

/* -- internal API --------------------------------------------------------- */

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

	int result = functions->ctx_new(&store->ctx, ctx_custom_data);
	if (result != DNSSEC_EOK) {
		free(store);
		return DNSSEC_ENOMEM;
	}

	result = functions->open(store->ctx, open_config);
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
				 dnssec_key_algorithm_t _algorithm,
				 unsigned bits, dnssec_key_id_t key_id)
{
	if (!store || !_algorithm || !key_id) {
		return DNSSEC_EINVAL;
	}

	// prepare parameters

	gnutls_pk_algorithm_t algorithm = algorithm_to_gnutls(_algorithm);
	if (algorithm == GNUTLS_PK_UNKNOWN) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (!dnssec_algorithm_key_size_check(_algorithm, bits)) {
		return DNSSEC_INVALID_KEY_SIZE;
	}

	return store->functions->generate_key(store->ctx, algorithm, bits, key_id);
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

static bool valid_params(dnssec_key_t *key, dnssec_key_id_t id,
			 dnssec_key_algorithm_t algorithm)
{
	assert(key);

	// no public key, parameters must be present

	if (key->public_key == NULL) {
		return (id != NULL && algorithm != 0);
	}

	// public key present, parameters must match or be NULL

	if (algorithm != 0) {
		uint8_t current_algorithm = 0;
		dnssec_key_get_algorithm(key, &current_algorithm);
		if (algorithm != current_algorithm) {
			return false;
		}
	}

	if (id != NULL && !dnssec_key_id_equal(key->id, id)) {
		return false;
	}

	return true;
}


_public_
int dnssec_key_import_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore,
			       dnssec_key_id_t id, dnssec_key_algorithm_t algorithm)
{
	if (!key || !keystore || !valid_params(key, id, algorithm)) {
		return DNSSEC_EINVAL;
	}

	if (key->private_key) {
		return DNSSEC_KEY_ALREADY_PRESENT;
	}

	// define search ID and algorithm

	if (id == NULL) {
		assert(key->public_key);
		id = key->id;
	}

	if (algorithm == 0) {
		assert(key->public_key);
		uint8_t algorithm8 = 0;
		dnssec_key_get_algorithm(key, &algorithm8);
		algorithm = algorithm8;
	}

	// retrieve and set the private key

	gnutls_privkey_t privkey = NULL;
	int r = keystore->functions->get_private(keystore->ctx, id, &privkey);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = key_set_private_key(key, privkey);
	if (r != DNSSEC_EOK) {
		gnutls_privkey_deinit(privkey);
		return r;
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_key_import_private_keystore(dnssec_key_t *key,
				       dnssec_keystore_t *keystore)
{
	return dnssec_key_import_keystore(key, keystore, NULL, 0);
}
