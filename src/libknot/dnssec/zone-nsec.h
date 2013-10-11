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
 * \file zone-sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Interface for generating of NSEC/NSEC3 records in zone.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_ZONE_NSEC_H_
#define _KNOT_DNSSEC_ZONE_NSEC_H_

#include <stdbool.h>
#include "libknot/updates/changesets.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/zone/zone-contents.h"

/*!
 * Check if NSEC3 is enabled for the given zone.
 *
 * \param zone  Zone to be checked.
 *
 * \return NSEC3 is enabled.
 */
bool is_nsec3_enabled(const knot_zone_contents_t *zone);

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
knot_dname_t *create_nsec3_owner(const knot_dname_t *owner,
                                 const knot_dname_t *zone_apex,
                                 const knot_nsec3_params_t *params);

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param zone       Zone for which the NSEC(3) chain will be created.
 * \param changeset  Changeset into which the changes will be added.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(const knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy);

#endif // _KNOT_DNSSEC_ZONE_NSEC_H_

/*! @} */
