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

struct dnssec_key;
typedef struct dnssec_key dnssec_key_t;

#define _cleanup_key_ _cleanup_(dnssec_key_free)

int dnssec_key_new(dnssec_key_t **key);
void dnssec_key_free(dnssec_key_t **key);

// LEGACY API

int dnssec_key_from_rsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *modulus,
			       const dnssec_binary_t *public_exponent,
			       const dnssec_binary_t *private_exponent,
			       const dnssec_binary_t *first_prime,
			       const dnssec_binary_t *second_prime,
			       const dnssec_binary_t *coefficient);

int dnssec_key_from_dsa_params(dnssec_key_t *key,
			       dnssec_key_algorithm_t algorithm,
			       const dnssec_binary_t *p,
			       const dnssec_binary_t *q,
			       const dnssec_binary_t *g,
			       const dnssec_binary_t *y,
			       const dnssec_binary_t *x);

int dnssec_key_from_ecdsa_params(dnssec_key_t *key,
                                 dnssec_key_algorithm_t algorithm,
			         const dnssec_binary_t *x_coordinate,
			         const dnssec_binary_t *y_coordinate,
			         const dnssec_binary_t *private_key);

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
