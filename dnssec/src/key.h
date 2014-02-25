#pragma once

#include <stdint.h>
#include "binary.h"

enum dnssec_dnskey_algorithm {
	DNSKEY_ALGORITHM_INVALID = 0,

	DNSKEY_ALGORITHM_DSA_SHA1 = 3,
	DNSKEY_ALGORITHM_RSA_SHA1 = 5,
	DNSKEY_ALGORITHM_DSA_SHA1_NSEC3 = 6,
	DNSKEY_ALGORITHM_RSA_SHA1_NSEC3 = 7,
	DNSKEY_ALGORITHM_RSA_SHA256 = 8,
	DNSKEY_ALGORITHM_RSA_SHA512 = 10,
	DNSKEY_ALGORITHM_ECDSA_P256_SHA256 = 13,
	DNSKEY_ALGORITHM_ECDSA_P384_SHA384 = 14
};

typedef uint8_t dnssec_key_id_t[20];

typedef struct dnssec_key {
	dnssec_key_id_t id;
	uint16_t keytag;

	struct {
		uint16_t flags;
		uint8_t algorithm;
		dnssec_binary_t *public_key;
	} dnskey_rdata;

	void *public_key;
	void *private_key;
} dnssec_key_t;

int dnssec_key_to_dnskey(const dnssec_key_t *key, dnssec_binary_t *dnskey);
int dnssec_dnskey_to_key(const dnssec_binary_t *dnskey, dnssec_key_t *key);

uint8_t dnssec_key_get_algorithm(const dnssec_key_t *key);
uint16_t dnssec_key_get_keytag(const dnssec_key_t *key);
