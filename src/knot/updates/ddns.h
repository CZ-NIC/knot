/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Dynamic updates processing.
 *
 * \addtogroup ddns
 * @{
 */

#pragma once

#include "knot/updates/zone-update.h"
#include "knot/zone/zone.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief Checks update prerequisite section.
 *
 * \param query   DNS message containing the update.
 * \param update  Zone to be checked.
 * \param rcode   Returned DNS RCODE.
 *
 * \return KNOT_E*
 */
int ddns_process_prereqs(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode);

/*!
 * \brief Processes DNS update and creates a changeset out of it. Zone is left
 *        intact.
 *
 * \param zone        Zone to be updated.
 * \param query       DNS message containing the update.
 * \param update      Output changeset.
 * \param rcode       Output DNS RCODE.
 *
 * \return KNOT_E*
 */
int ddns_process_update(const zone_t *zone, const knot_pkt_t *query,
                        zone_update_t *update, uint16_t *rcode);

/*! @} */
