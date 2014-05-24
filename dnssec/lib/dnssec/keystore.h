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
/*!
 * \file keystore.h
 *
 * \defgroup keystore Key store
 *
 * Private key store access.
 *
 * @{
 */

#pragma once

#include <dnssec/binary.h>
#include <dnssec/key.h>

struct dnssec_keystore;

/*!
 * DNSSEC private keys store.
 */
typedef struct dnssec_keystore dnssec_keystore_t;

/*!
 * PKCS #8 key store callback functions for custom providers.
 */
typedef struct dnssec_keystore_pkcs8_functions {
	/*!
	 * Callback to open the key store.
	 *
	 * \param[out] handle_ptr  Allocated key store handle.
	 * \param[in]  config      Configuration string.
	 */
	int (*open)(void **handle_ptr, const char *config);

	/*!
	 * Callback to close the key store.
	 *
	 * \param handle  Key store handle.
	 */
	int (*close)(void *handle);

	/*!
	 * Callback to read a PEM key.
	 *
	 * \param[in]  handle  Key store handle.
	 * \param[in]  id      Key ID of the key to be retrieved (ASCII form).
	 * \param[out] pem     Key material in uncencrypted PEM format.
	 */
	int (*read)(void *handle, const char *id, dnssec_binary_t *pem);

	/*!
	 * Callback to write a PEM key.
	 *
	 * \param handle  Key store handle.
	 * \param id      Key ID of the key to be saved (ASCII form).
	 * \param pem     Key material in unencrypted PEM format.
	 */
	int (*write)(void *handle, const char *id, const dnssec_binary_t *pem);
} dnssec_keystore_pkcs8_functions_t;

/*!
 * Open default PKCS #8 private key store.
 *
 * The default store maintains the private keys in one directory on the file
 * system. The private keys are stored in unencrypted PEM format, named
 * key-id.pem.
 *
 * \param[out] store  Opened key store.
 * \param[in]  path   Path to the key store.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_create_pkcs8_dir(dnssec_keystore_t **store, const char *path);

/*!
 * Open custom PKCS #8 private key store.
 *
 * \param[out] store   Opened key store.
 * \param[in]  impl    Implementation of the key store provider.
 * \param[in]  config  Configuration string for initialization.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_create_pkcs8_custom(dnssec_keystore_t **store,
					const dnssec_keystore_pkcs8_functions_t *impl,
					const char *config);

/*!
 * Open PKCS #11 private key store.
 *
 * \todo Not implemented.
 *
 * \param[out]  store   Opened key store.
 * \param[in]   config  Configuration string.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store, const char *config);

/*!
 * Close private key store.
 *
 * \param store  Key store to be closed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_close(dnssec_keystore_t *store);

/*!
 * Get a list of key IDs stored in the key store.
 *
 * \todo Not implemented.
 *
 * \param[in]  store  Key store.
 * \param[out] list   Resulting list of key IDs.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_list_keys(dnssec_keystore_t *store, void *list);

/*!
 * Generate a new key in the key store.
 *
 * \param[in]  store      Key store.
 * \param[in]  algorithm  Algorithm.
 * \param[in]  bits       Bit length of the key to be generated.
 * \param[out] id_ptr     ID of the generated key. Must be freed by the caller.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_generate_key(dnssec_keystore_t *store,
				 dnssec_key_algorithm_t algorithm,
				 unsigned bits, char **id_ptr);

/*!
 * Delete a private key from the key store.
 *
 * \param store  Key store.
 * \param id     ID of the private key to be deleted.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_keystore_delete_key(dnssec_keystore_t *store, const char *id);

/*!
 * Import public and private key from the key store into a DNSSEC key.
 *
 * \param key        DNSSEC key to be initialized.
 * \param keystore   Private key store.
 * \param id         ID of the key.
 * \param algorithm  Algorithm of the key.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int dnssec_key_import_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore,
			       const char *id, dnssec_key_algorithm_t algorithm);

/*!
 * Import private key from the key store into a DNSSEC key.
 *
 * \param key       DNSSEC key, the public key must be already loaded.
 * \param keystore  Private key store.
 */
int dnssec_key_import_private_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore);

/*! @} */
