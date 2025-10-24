/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/error.h"
#include "libknot/dnssec/key/algorithm.h"
#include "libknot/dnssec/key/convert.h"
#include "libknot/dnssec/key/dnskey.h"
#include "libknot/dnssec/key/internal.h"
#include "libknot/dnssec/key/privkey.h"
#include "libknot/dnssec/shared/shared.h"
#include "libknot/dnssec/shared/binary_wire.h"

/* -- internal functions --------------------------------------------------- */

/*!
 * Check if the algorithm number is valid for given DNSKEY.
 */
static bool valid_algorithm(dnssec_key_t *key, gnutls_privkey_t privkey)
{
	uint8_t current = dnssec_key_get_algorithm(key);
	int gnu_algorithm = gnutls_privkey_get_pk_algorithm(privkey, NULL);

	return (gnu_algorithm == algorithm_to_gnutls(current));
}

/*!
 * Create GnuTLS public key from private key.
 */
static int public_from_private(gnutls_privkey_t privkey, gnutls_pubkey_t *pubkey)
{
	assert(privkey);
	assert(pubkey);

	gnutls_pubkey_t new_key = NULL;
	int result = gnutls_pubkey_init(&new_key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = gnutls_pubkey_import_privkey(new_key, privkey, 0, 0);
	if (result != GNUTLS_E_SUCCESS) {
		gnutls_pubkey_deinit(new_key);
		return DNSSEC_KEY_IMPORT_ERROR;
	}

	*pubkey = new_key;

	return DNSSEC_EOK;
}

/*!
 * Create public key (GnuTLS and DNSKEY RDATA) from a private key.
 */
static int create_public_key(gnutls_privkey_t privkey,
			     gnutls_pubkey_t *pubkey_ptr,
			     dnssec_binary_t *rdata)
{
	assert(privkey);
	assert(pubkey_ptr);
	assert(rdata);

	// crypto public key

	gnutls_pubkey_t pubkey = NULL;
	int result = public_from_private(privkey, &pubkey);
	if (result != DNSSEC_EOK) {
		return result;
	}

	// dnssec public key

	_cleanup_binary_ dnssec_binary_t rdata_pubkey = { 0 };
	result = convert_pubkey_to_dnskey(pubkey, &rdata_pubkey);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(pubkey);
		return result;
	}

	size_t rdata_size = DNSKEY_RDATA_OFFSET_PUBKEY + rdata_pubkey.size;
	result = dnssec_binary_resize(rdata, rdata_size);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(pubkey);
		return result;
	}

	// updated RDATA

	wire_ctx_t wire = binary_init(rdata);
	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	binary_write(&wire, &rdata_pubkey);
	assert(wire_ctx_offset(&wire) == rdata->size);

	*pubkey_ptr = pubkey;

	return DNSSEC_EOK;
}

/* -- internal API --------------------------------------------------------- */

/*!
 * Load a private key into a DNSSEC key, create a public part if necessary.
 */
int key_set_private_key(dnssec_key_t *key, gnutls_privkey_t privkey)
{
	assert(key);
	assert(privkey);
	assert(key->private_key == NULL);

	if (!valid_algorithm(key, privkey)) {
		return DNSSEC_INVALID_KEY_ALGORITHM;
	}

	if (!key->public_key) {
		int r = create_public_key(privkey, &key->public_key, &key->rdata);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	key->private_key = privkey;

	return DNSSEC_EOK;
}
