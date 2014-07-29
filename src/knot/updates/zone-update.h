/*!
 * \file zone_update.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief API for quering zone that is being updated.
 *
 * \addtogroup server
 * @{
 */
/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"
#include "common/mempattern.h"

typedef struct {
	const zone_contents_t *zone;
	const changeset_t *change;
	mm_ctx_t mm;
} zone_update_t;

struct zone_node;

void zone_update_init(zone_update_t *update, const zone_contents_t *zone, changeset_t *change);

/* Node is either zone original or synthesized, cannot free or modify. */
const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname);

void zone_update_clear(zone_update_t *update);

