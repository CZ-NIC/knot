/*!
 * \file ddns.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Dynamic updates processing.
 *
 * \addtogroup ddns
 * @{
 */
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

#ifndef _KNOT_DDNS_H_
#define _KNOT_DDNS_H_

#include "knot/updates/changesets.h"
#include "knot/zone/zone.h"
#include "libknot/packet/pkt.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "common/lists.h"

int knot_ddns_check_zone(const knot_zone_contents_t *zone,
                         const knot_pkt_t *query, uint16_t *rcode);

int knot_ddns_process_prereqs(const knot_pkt_t *query, const knot_zone_contents_t *zone, uint16_t *rcode);

int knot_ddns_process_update(knot_zone_contents_t *zone,
                              const knot_pkt_t *query,
                              knot_changeset_t *changeset,
                              uint16_t *rcode, uint32_t new_serial);

#endif /* _KNOT_DDNS_H_ */

/*! @} */
