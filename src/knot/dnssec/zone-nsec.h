/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Interface for generating of NSEC/NSEC3 records in zone.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdbool.h>
#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"

/*!
 * Check if NSEC3 is enabled for the given zone.
 *
 * \param zone  Zone to be checked.
 *
 * \return NSEC3 is enabled.
 */
bool knot_is_nsec3_enabled(const zone_contents_t *zone);

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 *
 * \param hash       Raw hash.
 * \param hash_size  Size of the hash.
 * \param zone_apex  Zone apex.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex);

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
knot_dname_t *knot_create_nsec3_owner(const knot_dname_t *owner,
                                      const knot_dname_t *zone_apex,
                                      const knot_nsec3_params_t *params);

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param zone       Zone for which the NSEC(3) chain will be created.
 * \param changeset  Changeset into which the changes will be added.
 * \param zone_keys  Zone keys used for NSEC(3) creation.
 * \param policy     DNSSEC signing policy.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(const zone_contents_t *zone,
                                changeset_t *changeset,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx);

/*! @} */
