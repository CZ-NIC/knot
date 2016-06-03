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
 * \brief NSEC3 chain creation.
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include "knot/updates/changesets.h"

/*!
 * \brief Creates new NSEC3 chain, add differences from current into a changeset.
 *
 * \param zone       Zone to be checked.
 * \param ttl        TTL for new records.
 * \param changeset  Changeset to store changes into.
 *
 * \return KNOT_E*
 */
int knot_nsec3_create_chain(const zone_contents_t *zone, uint32_t ttl,
                            changeset_t *changeset);

/*! @} */
