#pragma once

#include <gnutls/abstract.h>
#include <stdint.h>
#include "binary.h"
#include "shared.h"

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

typedef enum dnssec_key_digest {
	DNSSEC_KEY_DIGEST_INVALID = 0,
	DNSSEC_KEY_DIGEST_SHA1 = 1,
	DNSSEC_KEY_DIGEST_SHA256 = 2,
	DNSSEC_KEY_DIGEST_SHA384 = 4,
} dnssec_key_digest_t;

typedef uint8_t dnssec_key_id_t[20];
#define DNSSEC_KEY_ID_SIZE sizeof(dnssec_key_id_t)
#define DNSSEC_KEY_ID_STRING_SIZE (2 * DNSSEC_KEY_ID_SIZE)

char *dnssec_key_id_to_string(const dnssec_key_id_t key_id);

// TODO: library internal API
struct dnssec_key {
	dnssec_key_id_t id;
	uint16_t keytag;

	dnssec_binary_t rdata;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
};

typedef struct dnssec_key dnssec_key_t;

#define _cleanup_key_ _cleanup_(dnssec_key_free)

int dnssec_key_new(dnssec_key_t **key);
void dnssec_key_clear(dnssec_key_t *key);
void dnssec_key_free(dnssec_key_t **key);

int dnssec_key_get_id(const dnssec_key_t *key, dnssec_key_id_t id);

uint16_t dnssec_key_get_keytag(const dnssec_key_t *key);
uint16_t dnssec_key_get_flags(const dnssec_key_t *key);
uint8_t dnssec_key_get_protocol(const dnssec_key_t *key);
uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key);

// TODO: PKCS 8

// TODO: PKCS 11

// FORMAT CONVERSION

int dnssec_key_from_params(dnssec_key_t *key, uint16_t flags, uint8_t protocol,
			   uint8_t algorithm, const dnssec_binary_t *public_key);

int dnssec_key_from_dnskey(dnssec_key_t *key, const dnssec_binary_t *rdata);

int dnssec_key_get_dnskey(const dnssec_key_t *key, dnssec_binary_t *rdata);

int dnssec_key_get_ds(const dnssec_key_t *key, dnssec_key_digest_t digest,
		      dnssec_binary_t *rdata);

// HASH FUNCTIONS
