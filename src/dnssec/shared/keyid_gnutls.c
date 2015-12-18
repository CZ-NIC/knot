/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <string.h>

#include "binary.h"
#include "error.h"
#include "keyid.h"
#include "keyid_gnutls.h"
#include "shared.h"
#include "hex.h"

/*!
 * Get binary key ID from a key (public or private).
 */
static int keyid_bin(gnutls_x509_privkey_t key, gnutls_pubkey_t pubkey, dnssec_binary_t *id)
{
	assert(key || pubkey);
	assert(id);

	// Flags can be used to enable SHA-2 since GnuTLS 3.4.7.

	int flags = 0;
	uint8_t *buffer = alloca(DNSSEC_KEYID_BINARY_SIZE);
	size_t size = DNSSEC_KEYID_SIZE;

	int r = key ? gnutls_x509_privkey_get_key_id(key, flags, buffer, &size)
	            : gnutls_pubkey_get_key_id(pubkey, flags, buffer, &size);

	if (r != GNUTLS_E_SUCCESS || size != DNSSEC_KEYID_BINARY_SIZE) {
		return DNSSEC_INVALID_KEY_ID;
	}

	assert(size == DNSSEC_KEYID_BINARY_SIZE);
	dnssec_binary_resize(id, size);
	memcpy(id->data, buffer, size);

	return DNSSEC_EOK;
}

/*!
 * Get hexadecimal key ID from a key (public or private).
 */
static int keyid_hex(gnutls_x509_privkey_t key, gnutls_pubkey_t pubkey, char **id)
{
	_cleanup_binary_ dnssec_binary_t bin = { 0 };
	int r = keyid_bin(key, pubkey, &bin);
	if (r != DNSSEC_EOK) {
		return r;
	}

	return bin_to_hex(&bin, id);
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
