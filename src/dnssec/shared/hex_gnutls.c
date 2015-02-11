/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>

#include "binary.h"
#include "hex.h"

/*!
 * Get binary key identifier for a public or a private key.
 */
static int get_bin_key_id(gnutls_pubkey_t pubkey, gnutls_x509_privkey_t privkey,
			  uint8_t *buffer, size_t *size)
{
	if (pubkey) {
		return gnutls_pubkey_get_key_id(pubkey, 0, buffer, size);
	} else {
		return gnutls_x509_privkey_get_key_id(privkey, 0, buffer, size);
	}
}

/*!
 * Get HEX encoded key identifier for a public or a private key.
 */
static char *get_hex_key_id(gnutls_pubkey_t pubkey, gnutls_x509_privkey_t privkey)
{
	// get output size

	size_t size = 0;
	int r = get_bin_key_id(pubkey, privkey, NULL, &size);
	if (r != GNUTLS_E_SHORT_MEMORY_BUFFER || size == 0) {
		return NULL;
	}

	// get binary identifier

	uint8_t raw[size];
	r = get_bin_key_id(pubkey, privkey, raw, &size);
	if (r != GNUTLS_E_SUCCESS) {
		return NULL;
	}

	// convert to hex

	assert(size == sizeof(raw));
	dnssec_binary_t bin = { .size = size, .data = raw };
	char *hex_id = NULL;
	bin_to_hex(&bin, &hex_id);

	return hex_id;
}

/* -- internal API --------------------------------------------------------- */

char *gnutls_x509_privkey_hex_key_id(gnutls_x509_privkey_t key)
{
	assert(key);

	return get_hex_key_id(NULL, key);
}

char *gnutls_pubkey_hex_key_id(gnutls_pubkey_t key)
{
	assert(key);

	return get_hex_key_id(key, NULL);
}
