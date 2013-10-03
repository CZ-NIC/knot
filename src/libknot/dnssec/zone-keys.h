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

#ifndef _KNOT_DNSSEC_ZONE_KEYS_H_
#define _KNOT_DNSSEC_ZONE_KEYS_H_

#include <stdbool.h>
#include "libknot/dname.h"
#include "libknot/dnssec/sign.h"

/*!
 * Maximal count of active keys for one zone.
 */
#define KNOT_MAX_ZONE_KEYS 8

/*!
 * \brief Keys used for zone signing.
 */
typedef struct {
	unsigned count;
	knot_dnssec_key_t keys[KNOT_MAX_ZONE_KEYS];
	knot_dnssec_sign_context_t *contexts[KNOT_MAX_ZONE_KEYS];
	bool is_ksk[KNOT_MAX_ZONE_KEYS];
} knot_zone_keys_t;

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
int load_zone_keys(const char *keydir_name, const knot_dname_t *zone_name,
		   bool nsec3_enabled, knot_zone_keys_t *keys);
/*!
 * \brief Get zone key by a keytag.
 *
 * \param keys    Zone keys.
 * \param keytag  Keytag to lookup a key for.
 *
 * \return Pointer to key or NULL if not found.
 */
const knot_dnssec_key_t *get_zone_key(const knot_zone_keys_t *keys,
                                      uint16_t keytag);

/*!
 * \brief Free structure with zone keys and associated DNSSEC contexts.
 *
 * \param keys    Zone keys.
 */
void free_zone_keys(knot_zone_keys_t *keys);

#endif // _KNOT_DNSSEC_ZONE_KEYS_H_

/*! @} */
