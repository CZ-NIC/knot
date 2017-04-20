/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdbool.h>
#include <time.h>

#include "dnssec/lib/dnssec/key.h"

/*!
 * KASP key timing information.
 */
typedef struct {
	time_t created;		/*!< Time the key was generated/imported. */
	time_t publish;		/*!< Time of DNSKEY record publication. */
	time_t ready;		/*!< Start of RRSIG generation, waiting for parent zone. */
	time_t active;		/*!< RRSIG records generating, other keys can be retired */
	time_t retire;		/*!< End of RRSIG records generating. */
	time_t remove;		/*!< Time of DNSKEY record removal. */
} knot_kasp_key_timing_t;

/*!
 * Key parameters as writing in zone config file.
 */
typedef struct {
	char *id;
	bool is_ksk;
	uint16_t keytag;
	uint8_t algorithm;
	dnssec_binary_t public_key;
	knot_kasp_key_timing_t timing;
} key_params_t;

/*!
 * Zone key.
 */
typedef struct {
	char *id;			/*!< Keystore unique key ID. */
	dnssec_key_t *key;		/*!< Instance of the key. */
	knot_kasp_key_timing_t timing;	/*!< Key timing information. */
} knot_kasp_key_t;

/*!
 * Key and signature policy.
 */
typedef struct {
	bool manual;
	char *string;
	// DNSKEY
	dnssec_key_algorithm_t algorithm;
	uint16_t ksk_size;
	uint16_t zsk_size;
	uint32_t dnskey_ttl;
	uint32_t zsk_lifetime;
	uint32_t ksk_lifetime;
	bool ksk_shared;
	bool singe_type_signing;
	// RRSIG
	uint32_t rrsig_lifetime;
	uint32_t rrsig_refresh_before;
	// NSEC3
	bool nsec3_enabled;
	uint32_t nsec3_salt_lifetime;
	uint16_t nsec3_iterations;
	uint8_t nsec3_salt_length;
	// SOA
	uint32_t soa_minimal_ttl;
	// zone
	uint32_t zone_maximal_ttl;
	// data propagation delay
	uint32_t propagation_delay;
} knot_kasp_policy_t;
