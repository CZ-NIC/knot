/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdlib.h>

#include "libknot/dnssec/error.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/key/algorithm.h"
#include "libknot/dnssec/key/dnskey.h"
#include "libknot/dnssec/key/internal.h"
#include "libknot/dnssec/key/privkey.h"
#include "libknot/dnssec/keyid.h"
#include "libknot/dnssec/keystore.h"
#include "libknot/dnssec/keystore/internal.h"
#include "libknot/dnssec/shared/shared.h"

/* -- internal API --------------------------------------------------------- */

int keystore_create(dnssec_keystore_t **store_ptr,
		    const keystore_functions_t *functions)
{
	assert(store_ptr);
	assert(functions);

	dnssec_keystore_t *store = calloc(1, sizeof(*store));
	if (!store) {
		return KNOT_ENOMEM;
	}

	store->functions = functions;

	int result = functions->ctx_new(&store->ctx);
	if (result != KNOT_EOK) {
		free(store);
		return KNOT_ENOMEM;
	}

	*store_ptr = store;
	return KNOT_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_deinit(dnssec_keystore_t *store)
{
	if (!store) {
		return KNOT_EINVAL;
	}

	dnssec_keystore_close(store);
	store->functions->ctx_free(store->ctx);

	free(store);

	return KNOT_EOK;
}

_public_
int dnssec_keystore_init(dnssec_keystore_t *store, const char *config)
{
	if (!store) {
		return KNOT_EINVAL;
	}

	return store->functions->init(store->ctx, config);
}

_public_
int dnssec_keystore_open(dnssec_keystore_t *store, const char *config)
{
	if (!store) {
		return KNOT_EINVAL;
	}

	return store->functions->open(store->ctx, config);
}

_public_
int dnssec_keystore_close(dnssec_keystore_t *store)
{
	if (!store) {
		return KNOT_EINVAL;
	}

	return store->functions->close(store->ctx);
}

_public_
int dnssec_keystore_generate(dnssec_keystore_t *store,
			     dnssec_key_algorithm_t _algorithm,
			     unsigned bits, const char *label, char **id_ptr)
{
	if (!store || !_algorithm || !id_ptr) {
		return KNOT_EINVAL;
	}

	// prepare parameters

	gnutls_pk_algorithm_t algorithm = algorithm_to_gnutls(_algorithm);
	if (algorithm == GNUTLS_PK_UNKNOWN) {
		return KNOT_INVALID_KEY_ALGORITHM;
	}

	if (!dnssec_algorithm_key_size_check(_algorithm, bits)) {
		return KNOT_INVALID_KEY_SIZE;
	}

	return store->functions->generate_key(store->ctx, algorithm, bits, label, id_ptr);
}

_public_
int dnssec_keystore_import(dnssec_keystore_t *store, const dnssec_binary_t *pem,
			   char **id_ptr)
{
	if (!store || !pem || !id_ptr) {
		return KNOT_EINVAL;
	}

	return store->functions->import_key(store->ctx, pem, id_ptr);
}

_public_
int dnssec_keystore_remove(dnssec_keystore_t *store, const char *id)
{
	if (!store || !id) {
		return KNOT_EINVAL;
	}

	return store->functions->remove_key(store->ctx, id);
}

_public_
int dnssec_keystore_get_private(dnssec_keystore_t *store, const char *id,
				dnssec_key_t *key)
{
	if (!store || !id || dnssec_key_get_algorithm(key) == 0 || !key) {
		return KNOT_EINVAL;
	}

	if (key->private_key) {
		return DNSSEC_KEY_ALREADY_PRESENT;
	}

	gnutls_privkey_t privkey = NULL;
	int r = store->functions->get_private(store->ctx, id, &privkey);
	if (r != KNOT_EOK) {
		return r;
	}

	r = key_set_private_key(key, privkey);
	if (r != KNOT_EOK) {
		gnutls_privkey_deinit(privkey);
		return r;
	}

	return KNOT_EOK;
}

_public_
int dnssec_keystore_set_private(dnssec_keystore_t *store, dnssec_key_t *key)
{
	if (!store || !key) {
		return KNOT_EINVAL;
	}

	if (!key->private_key) {
		return KNOT_NO_PRIVATE_KEY;
	}

	return store->functions->set_private(store->ctx, key->private_key);
}
