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
/*!
 * \file
 *
 * Key and Signature Policy access.
 *
 * \defgroup kasp KASP
 *
 * Key and Signature Policy access.
 *
 * The module provides access to Key and Signature Policy (KASP), which
 * keeps a signing state of a zone, zone signing policies, a reference
 * to key stores.
 *
 * The functionality of the module is incomplete.
 *
 * Example use:
 *
 * ~~~~~ {.c}
 *
 * int result;
 * dnssec_kasp_t *kasp = NULL;
 * dnssec_kasp_zone_t *zone = NULL;
 * dnssec_list_t *keys = NULL;
 *
 * // create API context
 * dnssec_kasp_init_dir(&kasp);
 *
 * // open KASP
 * result = dnssec_kasp_open_dir(kasp, "keydir");
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * // get zone state of 'example.com.'
 * result = dnssec_kasp_zone_load(kasp, "example.com", &zone);
 * if (result != DNSSEC_EOK) {
 *     dnssec_kasp_close(kasp);
 *     return result;
 * }
 *
 * // retrieve zone keys
 * keys = dnssec_kasp_zone_get_keys(zone);
 * if (keys == NULL) {
 *     dnssec_kasp_zone_free(zone);
 *     dnssec_kasp_close(kasp);
 *     return KNOT_ENOMEM;
 * }
 *
 * // list key IDs and it they are active
 * time_t now = time(NULL);
 * dnssec_list_foreach(item, keys) {
 *     dnssec_kasp_key_t *key = dnssec_item_get(item);
 *     bool active = key->timing.active <= now && now < key->timing.retire;
 *     printf("key %s is %s\n", dnssec_key_get_id(key->key),
 *                              active ? "active" : "inactive");
 * }
 *
 * // cleanup
 * dnssec_kasp_zone_free_keys(keys);
 * dnssec_kasp_zone_free(zone);
 * dnssec_kasp_close(kasp);
 * dnssec_kasp_deinit(kasp);
 *
 * ~~~~~
 *
 * @{
 */

#pragma once

#include <dnssec/key.h>
#include <dnssec/list.h>
#include <dnssec/nsec.h>
#include <stdbool.h>
#include <time.h>

struct dnssec_kasp_store_functions;

/*!
 * KASP key timing information.
 */
typedef struct dnssec_kasp_key_timing {
	time_t created;		/*!< Time the key was generated/imported. */
	time_t publish;		/*!< Time of DNSKEY record publication. */
	time_t active;		/*!< Start of RRSIG records generating. */
	time_t retire;		/*!< End of RRSIG records generating. */
	time_t remove;		/*!< Time of DNSKEY record removal. */
} dnssec_kasp_key_timing_t;

/*!
 * Key parameters as writing in zone config file.
 */
struct key_params {
	char *id;
	uint16_t keytag;
	uint8_t algorithm;
	dnssec_binary_t public_key;
	bool is_ksk;
	struct dnssec_kasp_key_timing timing;
};

typedef struct key_params key_params_t;

/*!
 * Zone key.
 */
typedef struct dnssec_kasp_key {
	char *id;				/*!< Keystore unique key ID. */
	dnssec_key_t *key;			/*!< Instance of the key. */
	dnssec_kasp_key_timing_t timing;	/*!< Key timing information. */
} dnssec_kasp_key_t;

/*!
 * Key and signature policy.
 *
 * \todo Move into internal API and add getters/setters (probably).
 */
typedef struct dnssec_kasp_policy {
	char *name;
	bool manual;
	char *keystore;
	// DNSKEY
	dnssec_key_algorithm_t algorithm;
	uint16_t ksk_size;
	uint16_t zsk_size;
	uint32_t dnskey_ttl;
	uint32_t zsk_lifetime;
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
} dnssec_kasp_policy_t;

/*!
 * Create new KASP policy.
 *
 * \param name  Name of the policy to be created.
 *
 * \return Pointer to KASP policy.
 */
dnssec_kasp_policy_t *dnssec_kasp_policy_new(const char *name);

/*!
 * Free a KASP policy.
 *
 * \param policy  Policy to be freed.
 */
void dnssec_kasp_policy_free(dnssec_kasp_policy_t *policy);

/*!
 * Validate a KASP policy.
 *
 * \param policy  Policy to be validated.
 */
int dnssec_kasp_policy_validate(const dnssec_kasp_policy_t *policy);

/*!
 * Set default policy.
 *
 * \param policy  Policy to be set to defaults.
 */
void dnssec_kasp_policy_defaults(dnssec_kasp_policy_t *policy);

/*
 * TODO: workaround, PKCS 8 dir keystore needs to know KASP base path
 */

#define DNSSEC_KASP_KEYSTORE_PKCS8  "pkcs8"
#define DNSSEC_KASP_KEYSTORE_PKCS11 "pkcs11"

/*! @} */
