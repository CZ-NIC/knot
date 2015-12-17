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
 * \file
 *
 * Private key store access.
 *
 * \defgroup keystore Key store
 *
 * Private key store access.
 *
 * The module provides abstraction for private key store. Basically, PKCS #8
 * and PKCS #11 interfaces are supported.
 *
 * PKCS #8 uses unencrypted PEM, and allows implementation of custom stores.
 *
 * PKCS #11 allows to access Hardware Security Modules.
 *
 * Example of using default PKCS #8 and to generate an RSA key:
 *
 * ~~~~~ {.c}
 *
 * int result;
 * dnssec_keystore_t *store = NULL;
 *
 * // create key store access context
 * dnssec_keystore_init_pkcs8_dir(&store);
 *
 * // open the key store
 * result = dnssec_keystore_open(&store, "/path/to/keydb");
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * // generate new private key in the key store
 * int algorithm = DNSSEC_KEY_ALGORITHM_RSA_SHA256;
 * unsigned bits = 2048;
 * char *id = NULL;
 * int dnssec_keystore_generate_key(store, algorithm, bits, &key_id);
 * if (result != DNSSEC_EOK) {
 *     dnssec_keystore_close(store);
 *     return result;
 * }
 * printf("ID of the new key: %s\n", key_id);
 *
 * // create new signing key
 * dnssec_key_t *key = NULL;
 * result = dnssec_key_new(&key);
 * if (result != DNSSEC_EOK) {
 *     free(key_id);
 *     dnssec_keystore_close(store);
 *     return result;
 * }
 *
 * // import the key from the key store
 * result = dnssec_key_import_keystore(key, store, key_id, algorithm);
 * if (result != DNSSEC_EOK) {
 *     free(key_id);
 *     dnssec_key_free(key);
 *     dnssec_keystore_close(store);
 *     return result;
 * }
 *
 * // use the key for signing ...
 *
 * // cleanup
 * free(key_id);
 * dnssec_key_free(key);
 * dnssec_keystore_close(store);
 * dnssec_keystore_deinit(store);
 *
 * ~~~~~
 * @{
 */

#pragma once

#include <dnssec/binary.h>
#include <dnssec/key.h>
#include <dnssec/list.h>

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
	 * Callback to allocate key store handle.
	 *
	 * \param[out]  handle_ptr  Allocated key store handle.
	 */
	int (*handle_new)(void **handle_ptr);

	/*!
	 * Callback to deallocate key store handle.
	 *
	 * \param handle  Key store handle.
	 */
	int (*handle_free)(void *handle);

	/*!
	 * Callback to initialize the key store.
	 *
	 * \param handle  Key store handle.
	 * \param config  Configuration string.
	 */
	int (*init)(void *handle, const char *config);

	/*!
	 * Callback to open the key store.
	 *
	 * \param[out] handle  Key store handle.
	 * \param[in]  config  Configuration string.
	 */
	int (*open)(void *handle, const char *config);

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

	/*!
	 * Callback to get a list of all PEM key IDs.
	 *
	 * \param[in]  handle  Key store handle.
	 * \param[out] list    Allocated list of key IDs.
	 */
	int (*list)(void *handle, dnssec_list_t **list);

	/*!
	 * Callback to remove a PEM key.
	 *
	 * \param handle  Key store handle.
	 * \param id      Key ID of the key to be removed (ASCII form).
	 */
	int (*remove)(void *handle, const char *id);
} dnssec_keystore_pkcs8_functions_t;

/*!
 * Create default PKCS #8 private key store context.
 *
 * The default store maintains the private keys in one directory on the file
 * system. The private keys are stored in unencrypted PEM format, named
 * key-id.pem. The configuration string is a path to the directory.
 *
 * \param[out] store  Opened key store.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_init_pkcs8_dir(dnssec_keystore_t **store);

/*!
 * Create custom PKCS #8 private key store context.
 *
 * \param[out] store   Opened key store.
 * \param[in]  impl    Implementation of the key store provider.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_init_pkcs8_custom(dnssec_keystore_t **store,
				      const dnssec_keystore_pkcs8_functions_t *impl);

/*!
 * Crate new PKCS #11 private key store context.
 *
 * \param[out]  store   Opened key store.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_init_pkcs11(dnssec_keystore_t **store);

/*!
 * Deinitialize private key store context.
 *
 * \param store  Key store to be deinitialized.
 */
int dnssec_keystore_deinit(dnssec_keystore_t *store);

/*!
 * Initialize new private key store.
 */
int dnssec_keystore_init(dnssec_keystore_t *store, const char *config);

/*!
 * Open private key store.
 */
int dnssec_keystore_open(dnssec_keystore_t *store, const char *config);

/*!
 * Close private key store.
 *
 * \param store  Key store to be closed.
 *
 * \return Error code, DNSSEC_EOK if successful.
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
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_list_keys(dnssec_keystore_t *store, dnssec_list_t **list);

/*!
 * Generate a new key in the key store.
 *
 * \param[in]  store      Key store.
 * \param[in]  algorithm  Algorithm.
 * \param[in]  bits       Bit length of the key to be generated.
 * \param[out] id_ptr     ID of the generated key. Must be freed by the caller.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_generate_key(dnssec_keystore_t *store,
				 dnssec_key_algorithm_t algorithm,
				 unsigned bits, char **id_ptr);

/*!
 * Import an existing key into the key store.
 *
 * \param[in]  store   Key store.
 * \param[in]  pem     Private key material in PEM format.
 * \param[out] id_ptr  ID of the imported key. Must be freed by the caller.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_import(dnssec_keystore_t *store, const dnssec_binary_t *pem,
			   char **id_ptr);

/*!
 * Remove a private key from the key store.
 *
 * \param store  Key store.
 * \param id     ID of the private key to be deleted.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_keystore_remove_key(dnssec_keystore_t *store, const char *id);

/*!
 * Import public and/or private key from the key store into a DNSSEC key.
 *
 * The key algorithm has to be set before calling this function.
 *
 * \param key       DNSSEC key to be initialized.
 * \param keystore  Private key store.
 * \param id        ID of the key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_key_import_keystore(dnssec_key_t *key, dnssec_keystore_t *keystore,
			       const char *id);

/*! @} */
