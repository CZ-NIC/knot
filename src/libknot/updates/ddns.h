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

#include "libknot/updates/changesets.h"
#include "libknot/zone/zone.h"
#include "libknot/packet/packet.h"
#include "libknot/rrset.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "common/lists.h"

typedef struct knot_ddns_prereq_t {
	knot_rrset_t **exist;
	size_t exist_count;
	size_t exist_allocd;

	knot_rrset_t **exist_full;
	size_t exist_full_count;
	size_t exist_full_allocd;

	knot_rrset_t **not_exist;
	size_t not_exist_count;
	size_t not_exist_allocd;

	knot_dname_t **in_use;
	size_t in_use_count;
	size_t in_use_allocd;

	knot_dname_t **not_in_use;
	size_t not_in_use_count;
	size_t not_in_use_allocd;
} knot_ddns_prereq_t;

int knot_ddns_check_zone(const knot_zone_contents_t *zone,
                         const knot_packet_t *query, knot_rcode_t *rcode);

int knot_ddns_process_prereqs(const knot_packet_t *query,
                              knot_ddns_prereq_t **prereqs, knot_rcode_t *rcode);

int knot_ddns_check_prereqs(const knot_zone_contents_t *zone,
                            knot_ddns_prereq_t **prereqs, knot_rcode_t *rcode);

int knot_ddns_process_update(knot_zone_contents_t *zone,
                              const knot_packet_t *query,
                              knot_changeset_t *changeset,
                              knot_changes_t *changes,
                              knot_rcode_t *rcode, uint32_t new_serial);

void knot_ddns_prereqs_free(knot_ddns_prereq_t **prereq);

#endif /* _KNOT_DDNS_H_ */

/*! @} */
