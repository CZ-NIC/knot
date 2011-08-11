/*!
 * \file ddns.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Dynamic updates processing.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC Labs

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

#include "updates/changesets.h"
#include "zone/zone.h"
#include "packet/packet.h"

typedef struct knot_ddns_prereq_t {

} knot_ddns_prereq_t;

int knot_ddns_check_zone(const knot_zone_t *zone, knot_packet_t *query,
                         uint8_t *rcode);

int knot_ddns_process_prereqs(knot_packet_t *query,
                              knot_ddns_prereq_t **prereqs, uint8_t *rcode);

int knot_ddns_check_prereqs(const knot_zone_contents_t *zone,
                            knot_ddns_prereq_t **prereqs, uint8_t *rcode);

int knot_ddns_process_update(knot_packet_t *query,
                             knot_changeset_t **changeset, uint8_t *rcode);

#endif /* _KNOT_DDNS_H_ */

/*! @} */
