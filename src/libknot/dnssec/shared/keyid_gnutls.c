/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <string.h>

#include "contrib/string.h"
#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/error.h"
#include "libknot/dnssec/keyid.h"
#include "libknot/dnssec/shared/keyid_gnutls.h"
#include "libknot/dnssec/shared/shared.h"

/*!
 * Get binary key ID from a key (public or private).
 */
static int keyid_bin(gnutls_x509_privkey_t key, gnutls_pubkey_t pubkey, dnssec_binary_t *id)
{
	assert(key || pubkey);
	assert(id);

	// Flags can be used to enable SHA-2 since GnuTLS 3.4.7.

	int flags = 0;
	uint8_t buffer[DNSSEC_KEYID_BINARY_SIZE];
	size_t size = DNSSEC_KEYID_SIZE;

	int r = key ? gnutls_x509_privkey_get_key_id(key, flags, buffer, &size)
	            : gnutls_pubkey_get_key_id(pubkey, flags, buffer, &size);

	if (r != GNUTLS_E_SUCCESS || size != DNSSEC_KEYID_BINARY_SIZE) {
		return KNOT_INVALID_KEY_ID;
	}

	assert(size == DNSSEC_KEYID_BINARY_SIZE);
	r = dnssec_binary_resize(id, size);
	if (r != KNOT_EOK) {
		return r;
	}

	memcpy(id->data, buffer, size);

	return KNOT_EOK;
}

/*!
 * Get hexadecimal key ID from a key (public or private).
 */
static int keyid_hex(gnutls_x509_privkey_t key, gnutls_pubkey_t pubkey, char **id)
{
	_cleanup_binary_ dnssec_binary_t bin = { 0 };
	int r = keyid_bin(key, pubkey, &bin);
	if (r != KNOT_EOK) {
		return r;
	}

	*id = bin_to_hex(bin.data, bin.size, false);
	if (*id == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

int keyid_x509(gnutls_x509_privkey_t key, dnssec_binary_t *id)
{
	return keyid_bin(key, NULL, id);
}

int keyid_x509_hex(gnutls_x509_privkey_t key, char **id)
{
	return keyid_hex(key, NULL, id);
}

int keyid_pubkey(gnutls_pubkey_t pubkey, dnssec_binary_t *id)
{
	return keyid_bin(NULL, pubkey, id);
}

int keyid_pubkey_hex(gnutls_pubkey_t pubkey, char **id)
{
	return keyid_hex(NULL, pubkey, id);
}
