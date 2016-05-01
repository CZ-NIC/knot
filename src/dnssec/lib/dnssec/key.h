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
 * DNSSEC public and private key manipulation.
 *
 * \defgroup key Key
 *
 * DNSSEC public and private key manipulation.
 *
 * The \ref dnssec_key_t is an abstraction for a DNSSEC key pair. If the key
 * key is initialized with a public key data only, it can be used only for
 * signature verification. In order to use the key for signing, private key
 * has to be loaded. If only a private key is loaded into the structure,
 * the public key is automatically constructed.
 *
 * The module interface provides various functions to retrieve information
 * about the key. But the key is mostly used by other modules of the library.
 *
 * The following example shows construction of a key from DNSKEY RDATA:
 *
 * ~~~~~ {.c}
 *
 * dnssec_binary_t rdata = // ...;
 *
 * int result;
 * dnssec_key_t *key = NULL;
 *
 * // create new DNSSEC key
 * result = dnssec_key_new(&key);
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * // load the DNSKEY RDATA
 * result = dnssec_key_set_rdata(key, &rdata);
 * if (result != DNSSEC_EOK) {
 *     dnssec_key_free(key);
 *     return result;
 * }
 *
 * // print key tag
 * printf("key %s\n", dnssec_key_get_keytag(key));
 *
 * // make sure what we can do with the key
 * assert(dnssec_key_can_verify(key) == true);
 * assert(dnssec_key_can_sign(key) == false);
 *
 * // ...
 *
 * // cleanup
 * dnssec_key_free(key);
 *
 * ~~~~~
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <dnssec/binary.h>

/*!
 * DNSKEY algorithm numbers.
 *
 * \see https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 */
typedef enum dnssec_key_algorithm {
	DNSSEC_KEY_ALGORITHM_INVALID = 0,
	DNSSEC_KEY_ALGORITHM_DSA_SHA1 = 3,
	DNSSEC_KEY_ALGORITHM_RSA_SHA1 = 5,
	DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3 = 6,
	DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3 = 7,
	DNSSEC_KEY_ALGORITHM_RSA_SHA256 = 8,
	DNSSEC_KEY_ALGORITHM_RSA_SHA512 = 10,
	DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256 = 13,
	DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384 = 14,
} dnssec_key_algorithm_t;

struct dnssec_key;

/*!
 * DNSSEC key.
 */
typedef struct dnssec_key dnssec_key_t;

/*!
 * Allocate new DNSSEC key.
 *
 * The protocol field of the key is set to 3 (DNSSEC).
 * The flags field of the key is set to 256 (zone key, no SEP).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_key_new(dnssec_key_t **key);

/*!
 * Clear the DNSSEC key.
 *
 * Has the same effect as calling \ref dnssec_key_free and \ref dnssec_key_new.
 */
void dnssec_key_clear(dnssec_key_t *key);

/*!
 * Free the key allocated by \ref dnssec_key_new.
 */
void dnssec_key_free(dnssec_key_t *key);

/*!
 * Create a copy of a DNSSEC key.
 *
 * Only a public part of the key is copied.
 */
dnssec_key_t *dnssec_key_dup(const dnssec_key_t *key);

/*!
 * Get the key tag of the DNSSEC key.
 */
uint16_t dnssec_key_get_keytag(const dnssec_key_t *key);

/*!
 * Get the domain name of the DNSSEC key.
 */
const uint8_t *dnssec_key_get_dname(const dnssec_key_t *key);

/*!
 * Set the domain name of the DNSSEC key.
 */
int dnssec_key_set_dname(dnssec_key_t *key, const uint8_t *dname);

/*!
 * Get the flags field of the DNSSEC key.
 */
uint16_t dnssec_key_get_flags(const dnssec_key_t *key);

/*!
 * Set the flags field of the DNSSEC key.
 */
int dnssec_key_set_flags(dnssec_key_t *key, uint16_t flags);

/*!
 * Get the protocol field of the DNSSEC key.
 */
uint8_t dnssec_key_get_protocol(const dnssec_key_t *key);

/*!
 * Get the protocol field of the DNSSEC key.
 */
int dnssec_key_set_protocol(dnssec_key_t *key, uint8_t protocol);

/*!
 * Get the algorithm field of the DNSSEC key.
 */
uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key);

/*!
 * Set the algorithm field of the DNSSEC key.
 *
 * The function will fail if the algorithm is incompatible with the
 * loaded key. This means, that the function can be used to set the initial
 * algorithm and later, only the hashing algorithm can be changed.
 */
int dnssec_key_set_algorithm(dnssec_key_t *key, uint8_t algorithm);

/*!
 * Get the public key field of the DNSSEC key.
 *
 * The returned content must not be modified by the caller. A reference
 * to internally allocated structure is returned.
 */
int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey);

/*!
 * Set the public key field of the DNSSEC key.
 *
 * A valid algorithm has to be set prior to calling this function.
 *
 * The function will fail if the key is already loaded in the structure.
 */
int dnssec_key_set_pubkey(dnssec_key_t *key, const dnssec_binary_t *pubkey);

/*!
 * Get the bit size of the cryptographic key used with the DNSSEC key.
 */
unsigned dnssec_key_get_size(const dnssec_key_t *key);

/*!
 * Get the RDATA of the DNSSEC key.
 *
 * The returned content must not be modified by the caller. A reference
 * to internally allocated structure is returned.
 */
int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata);

/*!
 * Set the RDATA of the DNSSEC key.
 *
 * Calling this function has the same effect as setting the individual
 * fields of the key step-by-step. The same limitations apply.
 */
int dnssec_key_set_rdata(dnssec_key_t *key, const dnssec_binary_t *rdata);

/*!
 * Load PKCS #8 private key in the unencrypted PEM format.
 *
 * At least an algorithm must be set prior to calling this function.
 *
 * The function will create public key, unless it was already set (using
 * \ref dnssec_key_set_pubkey or \ref dnssec_key_set_rdata). If the public key
 * was set, the function will prevent loading of non-matching private key.
 */
int dnssec_key_load_pkcs8(dnssec_key_t *key, const dnssec_binary_t *pem);

/*!
 * Check if the key can be used for signing.
 */
bool dnssec_key_can_sign(const dnssec_key_t *key);

/*!
 * Check if the key can be used for verification.
 */
bool dnssec_key_can_verify(const dnssec_key_t *key);

/*!
 * Get private key size range for a DNSSEC algorithm.
 *
 * \param[in]  algorithm  DNSKEY algorithm.
 * \param[out] min        Minimal size of the private key (can be NULL).
 * \param[out] max        Maximal size of the private key (can be NULL).
 *
 * \return DNSSEC_EOK for valid parameters.
 */
int dnssec_algorithm_key_size_range(dnssec_key_algorithm_t algorithm,
				    unsigned *min, unsigned *max);

/*!
 * Check if the private key size matches DNSKEY constraints.
 *
 * \param algorithm  DNSKEY algorithm.
 * \param bits       Private key size.
 *
 * \return DNSKEY algorithm matches the key size constraints.
 */
bool dnssec_algorithm_key_size_check(dnssec_key_algorithm_t algorithm,
				     unsigned bits);

/*!
 * Get default key size for given algorithm.
 *
 * The default size is balance between security and response lengths with
 * respect to use in DNS.
 */
int dnssec_algorithm_key_size_default(dnssec_key_algorithm_t algorithm);

/*!
 * DS algorithm numbers.
 *
 * \see https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
 */
typedef enum dnssec_key_digest {
	DNSSEC_KEY_DIGEST_INVALID = 0,
	DNSSEC_KEY_DIGEST_SHA1 = 1,
	DNSSEC_KEY_DIGEST_SHA256 = 2,
	DNSSEC_KEY_DIGEST_SHA384 = 4,
} dnssec_key_digest_t;

/*!
 * Create DS (Delgation Signer) RDATA from DNSSEC key.
 *
 * \param[in]  key     DNSSEC key.
 * \param[in]  digest  Digest algorithm to be used.
 * \param[out] rdata   Allocated DS RDATA.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_key_create_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
			 dnssec_binary_t *rdata);

/** @} */
