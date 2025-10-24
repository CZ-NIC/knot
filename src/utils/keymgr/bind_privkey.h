/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdint.h>
#include <time.h>

#include "libknot/dnssec/binary.h"
#include "knot/dnssec/kasp/policy.h"

/*!
 * Legacy private key parameters.
 */
typedef struct {
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

	// ECDSA
	dnssec_binary_t private_key;

	// key lifetime
	time_t time_created;
	time_t time_publish;
	time_t time_activate;
	time_t time_revoke;
	time_t time_inactive;
	time_t time_delete;
} bind_privkey_t;

/*!
 * Extract parameters from legacy private key file.
 */
int bind_privkey_parse(const char *filename, bind_privkey_t *params);

/*!
 * Free private key parameters.
 */
void bind_privkey_free(bind_privkey_t *params);

/*!
 * Generate PEM from pub&priv key.
 */
int bind_privkey_to_pem(dnssec_key_t *key, bind_privkey_t *params, dnssec_binary_t *pem);

/*!
 * Extract timing info.
 */
void bind_privkey_to_timing(bind_privkey_t *params, knot_kasp_key_timing_t *timing);
