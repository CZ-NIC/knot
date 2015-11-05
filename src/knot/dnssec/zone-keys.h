/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 
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
 * \file zone-keys.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Loading of zone keys.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "common-knot/lists.h"
#include "libknot/dname.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/nsec5hash.h"


typedef struct {
    node_t node;
    
    knot_dnssec_key_t dnssec_key;
    knot_nsec5_key_t nsec5_key;
    knot_dnssec_sign_context_t *context;
    knot_nsec5_hash_context_t *nsec5_ctx;
    uint32_t next_event;                 //!< Timestamp of next key event.
    bool is_ksk;                         //!< Is key-signing.
    bool is_zsk;                         //!< Is zone-signing.
    bool is_public;                      //!< Currently in zone.
    bool is_active;                      //!< Currently used for signing.
    bool is_nsec5;
} knot_zone_key_t;

/*!
 * \brief Keys used for zone signing.
 */
typedef struct {
    list_t list;
} knot_zone_keys_t;

/*!
 * \brief Initialize zone keys structure.
 */
void knot_init_zone_keys(knot_zone_keys_t *keys);

/*!
 * \brief Load zone keys from a key directory.
 *
 * \param keydir_name    Name of the directory with DNSSEC keys.
 * \param zone_name      Domain name of the zone.
 * \param nsec3_enabled  NSEC3 enabled for zone (determines allowed algorithms).
 * \param keys           Structure with loaded keys.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
                        bool nsec3_enabled, knot_zone_keys_t *keys);
/*!
 * \brief Get zone key by a keytag.
 *
 * \param keys    Zone keys.
 * \param keytag  Keytag to lookup a key for.
 *
 * \return Pointer to key or NULL if not found.
 */
const knot_zone_key_t *knot_get_zone_key(const knot_zone_keys_t *keys,
                                         uint16_t keytag);

/*!
 * \brief Get (unique) NSEC5 key.
 *
 * \param keys    Zone keys.
 *
 * \return Pointer to key or NULL if not found.
 */
knot_zone_key_t *knot_get_nsec5_key(const knot_zone_keys_t *keys);
                                         


/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 *
 * \param keys    Zone keys.
 */
void knot_free_zone_keys(knot_zone_keys_t *keys);

void knot_free_zone_key(knot_zone_key_t *key);


/*!
 * \brief Get timestamp of next key event.
 *
 * \param keys  Zone keys.
 *
 * \return Timestamp of next key event.
 */
uint32_t knot_get_next_zone_key_event(const knot_zone_keys_t *keys);

knot_zone_key_t *knot_load_nsec5_key(const char *keydir_name, const knot_dname_t *zone_name);


/*! @} */
