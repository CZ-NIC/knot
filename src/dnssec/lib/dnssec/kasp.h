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
 * DNSSEC KASP reference.
 */
typedef struct dnssec_kasp {
	const struct dnssec_kasp_store_functions *functions;
	void *ctx;
} dnssec_kasp_t;

/*!
 * Initialize default KASP state store context.
 *
 * This KASP provider stores the state in JSON files in a directory.
 *
 * \param[out] kasp  Pointer to KASP store instance.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_init_dir(dnssec_kasp_t **kasp);

/*!
 * Deinitialize KASP store context.
 *
 * \param kasp    KASP store handle.
 */
void dnssec_kasp_deinit(dnssec_kasp_t *kasp);

/*!
 * Initialize KASP store.
 *
 * \param kasp    KASP store handle.
 * \param config  KASP store configuration string.
 */
int dnssec_kasp_init(dnssec_kasp_t *kasp, const char *config);

/*!
 * Open KASP store.
 *
 * \param kasp    KASP store handle.
 * \param config  KASP store configuration string.
 */
int dnssec_kasp_open(dnssec_kasp_t *kasp, const char *config);

/*!
 * Close KASP store.
 *
 * \param kasp  KASP store to be closed.
 */
void dnssec_kasp_close(dnssec_kasp_t *kasp);

/*!
 * Zone state structure in the KASP.
 */
typedef struct dnssec_kasp_zone {
	char *name;
	uint8_t *dname;

	char *policy;

	dnssec_list_t *keys;

	dnssec_binary_t nsec3_salt;
	time_t nsec3_salt_created;
} dnssec_kasp_zone_t;

/*!
 * Create new KASP zone.
 *
 * \param name  Name of the zone to be created.
 *
 * \return Pointer to KASP zone.
 */
dnssec_kasp_zone_t *dnssec_kasp_zone_new(const char *name);

/*!
 * Free a KASP zone instance.
 *
 * \param zone  Zone to be freed.
 */
void dnssec_kasp_zone_free(dnssec_kasp_zone_t *zone);

/*!
 * Retrieve a zone from the KASP.
 *
 * \param[in]  kasp  KASP instance.
 * \param[in]  name  Name of the zone to be retrieved.
 * \param[out] zone  Loaded zone.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_zone_load(dnssec_kasp_t *kasp, const char *name,
			  dnssec_kasp_zone_t **zone);

/*!
 * Save the zone state into the KASP.
 *
 * \param kasp  KASP instance.
 * \param zone  Zone to be saved.
 */
int dnssec_kasp_zone_save(dnssec_kasp_t *kasp, const dnssec_kasp_zone_t *zone);

/*!
 * Remove zone from KASP.
 *
 * \param kasp       KASP instance.
 * \param zone_name  Zone to be removed.
 */
int dnssec_kasp_zone_remove(dnssec_kasp_t *kasp, const char *zone_name);

/*!
 * Get list of zone names in the KASP.
 *
 * \param[in]  kasp  KASP instance.
 * \param[out] list  List of zone names (as strings).
 */
int dnssec_kasp_zone_list(dnssec_kasp_t *kasp, dnssec_list_t **list);

/*!
 * Check if a zone exists in the KASP.
 *
 * \param kasp       KASP instance.
 * \param zone_name  Name of the zone.
 *
 * \return Error code.
 * \retval DNSSEC_EOK        Zone exists.
 * \retval DNSSEC_NOT_FOUND  Zone doesn't exist.
 */
int dnssec_kasp_zone_exists(dnssec_kasp_t *kasp, const char *zone_name);

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
 * Zone key.
 */
typedef struct dnssec_kasp_key {
	char *id;				/*!< Keystore unique key ID. */
	dnssec_key_t *key;			/*!< Instance of the key. */
	dnssec_kasp_key_timing_t timing;	/*!< Key timing information. */
} dnssec_kasp_key_t;

/*!
 * Check if DNSKEY is published in the zone.
 */
bool dnssec_kasp_key_is_published(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Check if RRSIGs are present in the zone.
 */
bool dnssec_kasp_key_is_active(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Check if key is published or active.
 *
 * \param timing  Key timing metadata.
 * \param at      Time to check the metadata against.
 */
bool dnssec_kasp_key_is_used(dnssec_kasp_key_timing_t *timing, time_t at);

/*!
 * Get name of the zone.
 */
const char *dnssec_kasp_zone_get_name(dnssec_kasp_zone_t *zone);

/*!
 * Get the set of keys associated with the zone.
 */
dnssec_list_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone);

/*!
 * Get zone policy name.
 *
 * \param zone  KASP zone.
 *
 * \return Name of the policy, NULL if the policy is unset.
 */
const char *dnssec_kasp_zone_get_policy(dnssec_kasp_zone_t *zone);

/*!
 * Set or clear zone policy name.
 *
 * \param zone  KASP zone.
 * \param name  Name of the policy to set, NULL to clear the policy.
 */
int dnssec_kasp_zone_set_policy(dnssec_kasp_zone_t *zone, const char *name);

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

/*!
 * Retrieve a policy from the KASP.
 *
 * \param[in]  kasp    KASP instance.
 * \param[in]  name    Name of the policy.
 * \param[out] policy  Retrieved policy.
 */
int dnssec_kasp_policy_load(dnssec_kasp_t *kasp, const char *name,
			    dnssec_kasp_policy_t **policy);

/*!
 * Save the policy into the KASP.
 *
 * \param kasp    KASP instance.
 * \param policy  Policy to be saved.
 */
int dnssec_kasp_policy_save(dnssec_kasp_t *kasp, const dnssec_kasp_policy_t *policy);

/*!
 * Remove a policy from the KASP.
 *
 * \param kasp  KASP instance.
 * \param name  Name of the policy to be removed.
 */
int dnssec_kasp_policy_remove(dnssec_kasp_t *kasp, const char *name);

/*!
 * Get a list of policy names in the KASP.
 *
 * \param[in]  kasp  KASP instance.
 * \param[out] list  List of policy names (as strings).
 */
int dnssec_kasp_policy_list(dnssec_kasp_t *kasp, dnssec_list_t **list);

/*!
 * Check if a policy exists in the KASP.
 *
 * \param kasp         KASP instance.
 * \param policy_name  Name of the policy.
 *
 * \return Error code.
 * \retval DNSSEC_EOK        Policy exists.
 * \retval DNSSEC_NOT_FOUND  Policy doesn't exist.
 */
int dnssec_kasp_policy_exists(dnssec_kasp_t *kasp, const char *policy_name);

typedef struct dnssec_kasp_keystore {
	char *name;
	char *backend;
	char *config;
} dnssec_kasp_keystore_t;

dnssec_kasp_keystore_t *dnssec_kasp_keystore_new(const char *name);
void dnssec_kasp_keystore_free(dnssec_kasp_keystore_t *keystore);

int dnssec_kasp_keystore_load(dnssec_kasp_t *kasp, const char *name, dnssec_kasp_keystore_t **keystore);
int dnssec_kasp_keystore_save(dnssec_kasp_t *kasp, const dnssec_kasp_keystore_t *keystore);
int dnssec_kasp_keystore_remove(dnssec_kasp_t *kasp, const char *name);
int dnssec_kasp_keystore_list(dnssec_kasp_t *kasp, dnssec_list_t **names);
int dnssec_kasp_keystore_exists(dnssec_kasp_t *kasp, const char *name);

/*
 * TODO: workaround, PKCS 8 dir keystore needs to know KASP base path
 */

#define DNSSEC_KASP_KEYSTORE_PKCS8  "pkcs8"
#define DNSSEC_KASP_KEYSTORE_PKCS11 "pkcs11"

struct dnssec_keystore;

int dnssec_kasp_keystore_init(dnssec_kasp_t *kasp, const char *backend,
			      const char *config, struct dnssec_keystore **store);
int dnssec_kasp_keystore_open(dnssec_kasp_t *kasp, const char *backend,
			      const char *config, struct dnssec_keystore **store);

/*!
 * KASP store API implementation.
 */
typedef struct dnssec_kasp_store_functions {
	int (*init)(const char *config);
	// internal context initialization
	int (*open)(void **ctx_ptr, const char *config);
	void (*close)(void *ctx);
	// internal information
	const char *(*base_path)(void *ctx);
	// zone serialization/deserialization
	int (*zone_load)(void *ctx, dnssec_kasp_zone_t *zone);
	int (*zone_save)(void *ctx, const dnssec_kasp_zone_t *zone);
	int (*zone_remove)(void *ctx, const char *zone_name);
	int (*zone_list)(void *ctx, dnssec_list_t *zone_names);
	int (*zone_exists)(void *ctx, const char *zone_name);
	// policy serialization/deserialization
	int (*policy_load)(void *ctx, dnssec_kasp_policy_t *policy);
	int (*policy_save)(void *ctx, const dnssec_kasp_policy_t *policy);
	int (*policy_remove)(void *ctx, const char *name);
	int (*policy_list)(void *ctx, dnssec_list_t *policy_names);
	int (*policy_exists)(void *ctx, const char *name);
	// keystore serialization/deserialization
	int (*keystore_load)(void *ctx, dnssec_kasp_keystore_t *keystore);
	int (*keystore_save)(void *ctx, const dnssec_kasp_keystore_t *keystore);
	int (*keystore_remove)(void *ctx, const char *name);
	int (*keystore_list)(void *ctx, dnssec_list_t *names);
	int (*keystore_exists)(void *ctx, const char *name);
} dnssec_kasp_store_functions_t;

/*!
 * Get KASP store API implementation.
 *
 * \return Pointer to functions.
 */
const dnssec_kasp_store_functions_t *dnssec_kasp_dir_api(void);

/*!
 * Initialize custom KASP state store context.
 *
 * \param[out] kasp  Pointer to KASP store instance.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_init_custom(dnssec_kasp_t **kasp,
			    const dnssec_kasp_store_functions_t *implementation);

/*! @} */
