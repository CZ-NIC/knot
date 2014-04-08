#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <dnssec/binary.h>

/*!
 * Unique DNSSEC key identifier (CKA_ID in PKCS #11).
 *
 * The value is a SHA-1 hash of public key material in X.509 DER.
 */
typedef uint8_t dnssec_key_id_t[20];
#define DNSSEC_KEY_ID_SIZE sizeof(dnssec_key_id_t)
#define DNSSEC_KEY_ID_STRING_SIZE (2 * DNSSEC_KEY_ID_SIZE)

/*!
 * Convert DNSSEC key id to hexadecimal string.
 */
int dnssec_key_id_to_string(const dnssec_key_id_t key_id, char **string);

/*!
 * Convert hexadecimal string to DNSSEC key id.
 */
int dnssec_key_id_from_string(const char *string, dnssec_key_id_t key_id);

/*!
 * Copy key ID.
 */
void dnssec_key_id_copy(const dnssec_key_id_t from, dnssec_key_id_t to);

/*!
 * Compare two key IDs, similar to memcmp.
 */
int dnssec_key_id_cmp(const dnssec_key_id_t one, const dnssec_key_id_t two);

/*!
 * Check if two key IDs are equal.
 */
bool dnssec_key_id_equal(const dnssec_key_id_t one, const dnssec_key_id_t two);

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

/*!
 * DNSSEC key.
 */
struct dnssec_key;
typedef struct dnssec_key dnssec_key_t;

/*!
 * Allocate new DNSSEC key.
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
 * Get the key tag of the DNSKEY.
 */
int dnssec_key_get_keytag(const dnssec_key_t *key, uint16_t *keytag);

/*!
 * Get the ID of the associated public key.
 */
int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id);

int dnssec_key_get_flags(const dnssec_key_t *key, uint16_t *flags);
int dnssec_key_set_flags(dnssec_key_t *key, uint16_t flags);

int dnssec_key_get_protocol(const dnssec_key_t *key, uint8_t *protocol);
int dnssec_key_set_protocol(dnssec_key_t *key, uint8_t protocol);

int dnssec_key_get_algorithm(const dnssec_key_t *key, uint8_t *algorithm);
int dnssec_key_set_algorithm(dnssec_key_t *key, uint8_t algorithm);

int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey);
int dnssec_key_set_pubkey(dnssec_key_t *key, const dnssec_binary_t *pubkey);

int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata);
int dnssec_key_set_rdata(dnssec_key_t *key, const dnssec_binary_t *rdata);

/*!
 * Load PKCS #8 private key in unencrypted PEM format.
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
 * Check if the private key size matches DNSKEY contraints.
 *
 * \param algorithm  DNSKEY algorithm.
 * \param bits       Private key size.
 *
 * \return DNSKEY algorithm matches the key size constraints.
 */
bool dnssec_algorithm_key_size_check(dnssec_key_algorithm_t algorithm,
				     unsigned bits);

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
