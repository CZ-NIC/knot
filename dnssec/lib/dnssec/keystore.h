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

#pragma once

#include <dnssec/binary.h>
#include <dnssec/key.h>

/*!
 * DNSSEC private keys storage.
 */
struct dnssec_keystore;
typedef struct dnssec_keystore dnssec_keystore_t;

/*!
 * PKCS #8 key store callback functions for custom providers.
 */
typedef struct dnssec_keystore_pkcs8_functions {
	int (*open)(void **handle_ptr, const char *config);
	int (*close)(void *handle);
	int (*read)(void *handle, const char *id, dnssec_binary_t *pem);
	int (*write)(void *handle, const char *id, const dnssec_binary_t *pem);
} dnssec_keystore_pkcs8_functions_t;

// store open

int dnssec_keystore_create_pkcs8_dir(dnssec_keystore_t **store, const char *path);

int dnssec_keystore_create_pkcs8_custom(dnssec_keystore_t **store,
					const dnssec_keystore_pkcs8_functions_t *impl,
					const char *config);

int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store, const char *config);

// store close

int dnssec_keystore_close(dnssec_keystore_t *store);

// store access

int dnssec_keystore_list_keys(dnssec_keystore_t *store, void *list);
int dnssec_keystore_generate_key(dnssec_keystore_t *store,
				 dnssec_key_algorithm_t algorithm,
				 unsigned bits, char **id_ptr);
int dnssec_keystore_delete_key(dnssec_keystore_t *store, const char *id);

// private key access

/*!
 * Import a key from the key store.
 *
 * \param keystore
 * \param key
 * \param id
 * \param algorithm
 *
 */
int dnssec_key_import_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore,
			       const char *id, dnssec_key_algorithm_t algorithm);

/*!
 * Import private key for known public key.
 */
int dnssec_key_import_private_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore);
