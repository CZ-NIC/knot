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

#include "contrib/time.h"
#include "dnssec/lib/dnssec/key.h"
#include "knot/conf/conf.h"

/*!
 * KASP key timing information.
 */
typedef struct {
	knot_time_t created;		/*!< Time the key was generated/imported. */
	knot_time_t pre_active;		/*!< Signing start with new algorithm. */
	knot_time_t publish;		/*!< Time of DNSKEY record publication. */
	knot_time_t ready;		/*!< Start of RRSIG generation, waiting for parent zone. */
	knot_time_t active;		/*!< RRSIG records generating, other keys can be retired */
	knot_time_t retire_active;	/*!< Still active, but obsoleted. */
	knot_time_t retire;		/*!< End of RRSIG records generating. */
	knot_time_t post_active;	/*!< Still signing with old algorithm, not published. */
	knot_time_t remove;		/*!< Time of DNSKEY record removal. */
} knot_kasp_key_timing_t;

/*!
 * Key parameters as writing in zone config file.
 */
typedef struct {
	char *id;
	bool is_ksk;
	bool is_csk;
	bool is_pub_only;
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
	bool is_pub_only;
	bool is_ksk;
	bool is_zsk;
} knot_kasp_key_t;

/*!
 * Parent for DS checks.
 */
typedef struct {
        conf_remote_t *addr;
        size_t addrs;
} knot_kasp_parent_t;

dynarray_declare(parent, knot_kasp_parent_t, DYNARRAY_VISIBILITY_PUBLIC, 3)

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
	bool nsec3_opt_out;
	uint32_t nsec3_salt_lifetime;
	uint16_t nsec3_iterations;
	uint8_t nsec3_salt_length;
	// SOA
	uint32_t soa_minimal_ttl;
	// zone
	uint32_t zone_maximal_ttl;
	// data propagation delay
	uint32_t propagation_delay;
	// various
	uint32_t ksk_sbm_timeout;
	uint32_t ksk_sbm_check_interval;
	unsigned child_records_publish;
	parent_dynarray_t parents;
} knot_kasp_policy_t;
// TODO make the time parameters knot_timediff_t ??
