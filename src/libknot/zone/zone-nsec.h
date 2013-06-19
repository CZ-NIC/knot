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
#ifndef _KNOT_ZONE_NSEC_H_
#define _KNOT_ZONE_NSEC_H_

#include "zone.h"

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param zone  Zone for which the NSEC(3) chain will be created.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(knot_zone_t *zone);

/*!
 * \brief Connect regular and NSEC3 nodes in the zone.
 *
 * \note No need to call this function after 'knot_zone_create_nsec_chain'.
 * \note Exits succesfully if NSEC3 is not enabled.
 * \note Skips nodes with missing related NSEC3 nodes.
 *
 * \param zone  Zone for which the operation is performed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_connect_nsec_nodes(knot_zone_contents_t *zone);

#endif // _KNOT_ZONE_NSEC_H_
