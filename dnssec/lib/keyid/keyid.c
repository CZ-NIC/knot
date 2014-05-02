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
#include <ctype.h>
#include <gnutls/abstract.h>
#include <string.h>

#include "error.h"
#include "hex.h"
#include "keyid.h"
#include "keyid/internal.h"
#include "shared.h"

/* -- internal API --------------------------------------------------------- */

char *gnutls_pubkey_hex_key_id(gnutls_pubkey_t key)
{
	assert(key);

	uint8_t raw[DNSSEC_KEYID_BINARY_SIZE] = { 0 };
	size_t size = sizeof(raw);
	gnutls_pubkey_get_key_id(key, 0, raw, &size);
	assert(size == sizeof(raw));

	dnssec_binary_t bin = { .size = size, .data = raw };
	char *hex_id = NULL;
	bin_to_hex(&bin, &hex_id);

	return hex_id;
}

char *gnutls_x509_privkey_hex_key_id(gnutls_x509_privkey_t key)
{
	assert(key);

	uint8_t raw[DNSSEC_KEYID_BINARY_SIZE] = { 0 };
	size_t size = sizeof(raw);
	gnutls_x509_privkey_get_key_id(key, 0, raw, &size);
	assert(size == sizeof(raw));

	dnssec_binary_t bin = { .size = size, .data = raw };
	char *hex_id = NULL;
	bin_to_hex(&bin, &hex_id);

	return hex_id;
}

/* -- public API ----------------------------------------------------------- */

_public_
bool dnssec_keyid_is_valid(const char *id)
{
	if (!id) {
		return false;
	}

	if (strlen(id) != DNSSEC_KEYID_SIZE) {
		return false;
	}

	for (int i = 0; i < DNSSEC_KEYID_SIZE; i++) {
		if (!isxdigit(id[i])) {
			return false;
		}
	}

	return true;
}

_public_
void dnssec_keyid_normalize(char *id)
{
	if (!id) {
		return;
	}

	for (size_t i = 0; i < DNSSEC_KEYID_SIZE; i++) {
		assert(id[i] != '\0' && isxdigit(id[i]));
		id[i] = tolower(id[i]);
	}
}

_public_
char *dnssec_keyid_copy(const char *id)
{
	if (!id) {
		return NULL;
	}

	char *copy = strdup(id);
	if (!copy) {
		return NULL;
	}

	dnssec_keyid_normalize(copy);

	return copy;
}

bool dnssec_keyid_equal(const char *one, const char *two)
{
	if (!one || !two) {
		return NULL;
	}

	return (strcasecmp(one, two) == 0);
}
