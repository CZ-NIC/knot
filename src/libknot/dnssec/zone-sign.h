/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 *
 * \brief Interface for DNSSEC signing of zones.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_ZONE_SIGN_H_
#define _KNOT_DNSSEC_ZONE_SIGN_H_

#include "libknot/updates/changesets.h"
#include "libknot/zone/zone-contents.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/dnssec/policy.h"

int knot_zone_sign(const knot_zone_contents_t *zone,
                   const knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   knot_changeset_t *changeset);

int knot_zone_sign_update_soa(const knot_zone_contents_t *zone,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
			      knot_changeset_t *changeset);

bool knot_zone_sign_soa_changed(const knot_zone_contents_t *zone,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy);

#endif // _KNOT_DNSSEC_ZONE_SIGN_H_

/*! @} */
