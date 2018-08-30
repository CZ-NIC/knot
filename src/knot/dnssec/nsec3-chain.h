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

#include <stdint.h>
#include "libdnssec/nsec.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/contents.h"

/*!
 * \brief Creates new NSEC3 chain, add differences from current into a changeset.
 *
 * \param zone       Zone to be checked.
 * \param params     NSEC3 parameters.
 * \param ttl        TTL for new records.
 * \param opt_out    NSEC3 opt-out enabled for insecure delegations.
 * \param changeset  Changeset to store changes into.
 *
 * \return KNOT_E*
 */
int knot_nsec3_create_chain(const zone_contents_t *zone,
                            const dnssec_nsec3_params_t *params,
                            uint32_t ttl,
                            bool opt_out,
                            changeset_t *changeset);

/*!
 * \brief Updates zone's NSEC3 chain to follow the differences in zone update.
 *
 * \param update     Zone Update structure holding the zone and its update. Also modified!
 * \param params     NSEC3 parameters.
 * \param ttl        TTL for new records.
 * \param opt_out    NSEC3 opt-out enabled for insecure delegations.
 * \param changeset  Changeset to store changes into. Some changes are pushed directly to update.
 *
 * \retval KNOT_ENORECORD if the chain must be recreated from scratch.
 * \return KNOT_E*
 */
int knot_nsec3_fix_chain(zone_update_t *update,
                         const dnssec_nsec3_params_t *params,
                         uint32_t ttl, bool opt_out,
                         changeset_t *changeset);
