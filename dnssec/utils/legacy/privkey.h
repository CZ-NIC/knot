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
