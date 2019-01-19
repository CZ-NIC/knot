/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*!
 * \file
 *
 * \addtogroup keystore
 *
 * \brief Private key store access.
 *
 * The module provides abstraction for private key store. Basically, PKCS #8
 * and PKCS #11 interfaces are supported.
 *
 * PKCS #8 uses unencrypted PEM.
 *
 * PKCS #11 provides access Hardware Security Modules.
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

#include <libdnssec/binary.h>
#include <libdnssec/key.h>

struct dnssec_keystore;

/*!
 * DNSSEC private keys store.
 */
typedef struct dnssec_keystore dnssec_keystore_t;

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
int dnssec_keystore_init_pkcs8(dnssec_keystore_t **store);

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
