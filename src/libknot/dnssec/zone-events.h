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
 * \file zone-events.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief DNSSEC operations triggered on zone events.
 *
 * \addtogroup dnssec
 * @{
 */
#ifndef _KNOT_DNSSEC_ZONE_EVENTS_H_
#define _KNOT_DNSSEC_ZONE_EVENTS_H_

#include "libknot/zone/zone.h"
#include "libknot/updates/changesets.h"

int knot_dnssec_zone_sign(knot_zone_t *zone, knot_changeset_t *out_ch);
int knot_dnssec_zone_sign_force(knot_zone_t *zone, knot_changeset_t *out_ch);

#endif // _KNOT_DNSSEC_ZONE_EVENTS_H_
/*! @} */
