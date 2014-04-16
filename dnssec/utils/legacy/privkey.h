#pragma once

#include <stdint.h>
#include <time.h>

#include "dnssec/binary.h"

/*!
 * Legacy private key parameters.
 */
typedef struct legacy_privkey {
	// key information
	uint8_t algorithm;

	// RSA
	dnssec_binary_t modulus;
	dnssec_binary_t public_exponent;
	dnssec_binary_t private_exponent;
	dnssec_binary_t prime_one;
	dnssec_binary_t prime_two;
	dnssec_binary_t exponent_one;
	dnssec_binary_t exponent_two;
	dnssec_binary_t coefficient;

	// DSA
	dnssec_binary_t prime;
	dnssec_binary_t subprime;
	dnssec_binary_t base;
	dnssec_binary_t private_value;
	dnssec_binary_t public_value;

	// ECDSA
	dnssec_binary_t private_key;

	// key lifetime
	time_t time_created;
	time_t time_publish;
	time_t time_activate;
	time_t time_revoke;
	time_t time_inactive;
	time_t time_delete;
} legacy_privkey_t;

/*!
 * Extract parameters from legacy private key file.
 */
int legacy_privkey_parse(const char *filename, legacy_privkey_t *params);

/*!
 * Free private key parameters.
 */
void legacy_privkey_free(legacy_privkey_t *params);
