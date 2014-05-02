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
 */

#pragma once

#include <dnssec/key.h>
#include <time.h>

/*!
 * KASP store.
 */
struct dnssec_kasp;
typedef struct dnssec_kasp dnssec_kasp_t;

/*!
 * Open default KASP state store.
 *
 * This KASP provider stores the state in YAML files in a directory.
 *
 * \param[in]  path   Path to the KASP storage.
 * \param[out] store  Pointer to KASP store instance.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_open_dir(const char *path, dnssec_kasp_t **kasp);

/*!
 * Close KASP store.
 *
 * \param store  KASP store to be closed.
 */
void dnssec_kasp_close(dnssec_kasp_t *kasp);

/*!
 * Zone state structure in the KASP.
 */
struct dnssec_kasp_zone;
typedef struct dnssec_kasp_zone dnssec_kasp_zone_t;

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
 * Retrieve a zone from the KASP
 *
 * \param kasp       KASP instance.
 * \param zone_name  Name of the zone to be retrieved.
 * \param zone       Loaded zone.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_kasp_load_zone(dnssec_kasp_t *kasp, const char *zone_name,
			  dnssec_kasp_zone_t **zone);

/*!
 * Save the zone state into the KASP.
 *
 * \param kasp  KASP instance.
 * \param zone  Zone to be saved.
 */
int dnssec_kasp_save_zone(dnssec_kasp_t *kasp, dnssec_kasp_zone_t *zone);

/*!
 * Key and signature policy.
 */
struct dnssec_kasp_policy;
typedef struct dnssec_kasp_policy dnssec_kasp_policy_t;

/*!
 * External signing policy event.
 */
struct dnssec_kasp_event;
typedef struct dnssec_kasp_event dnssec_kasp_event_t;

/*!
 * KASP key timing information.
 */
typedef struct dnssec_kasp_key_timing {
	time_t publish;		/*!< Time of DNSKEY record publication. */
	time_t active;		/*!< Start of RRSIG records generating. */
	time_t retire;		/*!< End of RRSIG records generating. */
	time_t remove;		/*!< Time of DNSKEY record removal. */
} dnssec_kasp_key_timing_t;

/*!
 * Zone key.
 */
typedef struct dnssec_kasp_key {
	dnssec_key_t *key;			/*!< Instance of the key. */
	dnssec_kasp_key_timing_t timing;	/*!< Key timing information. */
} dnssec_kasp_key_t;

/*!
 * A set of zone keys.
 */
struct dnssec_kasp_keyset;
typedef struct dnssec_kasp_keyset dnssec_kasp_keyset_t;

/*!
 * Create an empty set of keys.
 */
dnssec_kasp_keyset_t *dnssec_kasp_keyset_new(void);

/*!
 * Empty a key set, do not free the keys.
 */
void dnssec_kasp_keyset_init(dnssec_kasp_keyset_t *keys);

/*!
 * Free the key set, including the keys.
 */
void dnssec_kasp_keyset_free(dnssec_kasp_keyset_t *keyset);

/*!
 * Get a number of keys within a key set.
 */
size_t dnssec_kasp_keyset_count(dnssec_kasp_keyset_t *keys);

/*!
 * Get a key at a given index in the key set.
 */
dnssec_kasp_key_t *dnssec_kasp_keyset_at(dnssec_kasp_keyset_t *keys, size_t number);

/*!
 * Add a key into the keyset.
 *
 * The key set is responsible for freeing the key.
 */
int dnssec_kasp_keyset_add(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *key);

/*!
 * Remove the key from the keyset.
 */
int dnssec_kasp_keyset_remove(dnssec_kasp_keyset_t *keys, dnssec_kasp_key_t *key);

/*!
 * Empty the key set while freeing the keys.
 */
void dnssec_kasp_keyset_empty(dnssec_kasp_keyset_t *keys);

/*!
 * Get the set of keys associated with the zone.
 */
dnssec_kasp_keyset_t *dnssec_kasp_zone_get_keys(dnssec_kasp_zone_t *zone);
