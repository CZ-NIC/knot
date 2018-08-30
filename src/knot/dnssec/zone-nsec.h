/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>

#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/contents.h"

/*!
 * Check if NSEC3 is enabled for the given zone.
 *
 * \param zone  Zone to be checked.
 *
 * \return NSEC3 is enabled.
 */
inline static bool knot_is_nsec3_enabled(const zone_contents_t *zone)
{
	return zone != NULL && zone->nsec3_params.algorithm != 0;
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 *
 * \param out        Output buffer.
 * \param out_size   Size of the output buffer.
 * \param hash       Raw hash.
 * \param hash_size  Size of the hash.
 * \param zone_apex  Zone apex.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec3_hash_to_dname(uint8_t *out, size_t out_size, const uint8_t *hash,
                             size_t hash_size, const knot_dname_t *zone_apex);

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param out        Output buffer.
 * \param out_size   Size of the output buffer.
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_create_nsec3_owner(uint8_t *out, size_t out_size,
                            const knot_dname_t *owner, const knot_dname_t *zone_apex,
                            const dnssec_nsec3_params_t *params);

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param update          Zone Update with current zone contents and to be updated with NSEC chain.
 * \param zone_keys       Zone keys used for NSEC(3) creation.
 * \param ctx             Signing context.
 * \param sign_nsec_chain If true, the created NSEC(3) chain is signed at the end.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(zone_update_t *update,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *ctx,
                                bool sign_nsec_chain);

/*!
 * \brief Fix NSEC or NSEC3 chain after zone was updated.
 *
 * \param update           Zone Update with the update and to be update with NSEC chain.
 * \param zone_keys        Zone keys used for NSEC(3) creation.
 * \param ctx              Signing context.
 * \param sign_nsec_chain  If true, the created NSEC(3) chain is signed at the end.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_fix_nsec_chain(zone_update_t *update,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *ctx,
                             bool sign_nsec_chain);
