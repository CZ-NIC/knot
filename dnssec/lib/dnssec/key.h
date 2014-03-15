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

/*!
 * DNSSEC key.
 */
struct dnssec_key;
typedef struct dnssec_key dnssec_key_t;

/*!
 * Unique DNSSEC key identifier (CKA_ID in PKCS #11).
 *
 * The value is a SHA-1 hash of public key material in X.509 DER.
 */
typedef uint8_t dnssec_key_id_t[20];
#define DNSSEC_KEY_ID_SIZE sizeof(dnssec_key_id_t)
#define DNSSEC_KEY_ID_STRING_SIZE (2 * DNSSEC_KEY_ID_SIZE)

/*!
 * Allocate new DNSSEC key.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_key_new(dnssec_key_t **key);

/*!
 * Clear the DNSSEC key.
 */
void dnssec_key_clear(dnssec_key_t *key);

/*!
 * Free the key allocated by \ref dnssec_key_new.
 */
void dnssec_key_free(dnssec_key_t *key);

// public key import
int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key);
int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata);

// identifiers
int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id);
int dnssec_key_get_keytag(const dnssec_key_t *key, uint16_t *keytag);

// parameters
int dnssec_key_get_rdata(const dnssec_key_t *key, dnssec_binary_t *rdata);
int dnssec_key_get_flags(const dnssec_key_t *key, uint16_t *flags);
int dnssec_key_get_protocol(const dnssec_key_t *key, uint8_t *protocol);
int dnssec_key_get_algorithm(const dnssec_key_t *key, uint8_t *algorithm);
int dnssec_key_get_pubkey(const dnssec_key_t *key, dnssec_binary_t *pubkey);

// key availability
bool dnssec_key_can_sign(const dnssec_key_t *key);
bool dnssec_key_can_verify(const dnssec_key_t *key);

/*!
 * Convert DNSSEC key id to hexadecimal string.
 */
char *dnssec_key_id_to_string(const dnssec_key_id_t key_id);

// private key import (PKCS #8, #11)
// TODO

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
