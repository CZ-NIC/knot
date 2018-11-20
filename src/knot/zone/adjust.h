/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/zone/contents.h"
#include "knot/updates/zone-update.h"

typedef int (*adjust_cb_t)(zone_node_t *, const zone_contents_t *);

int zone_adjust_node_pointers(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_nsec3_pointers(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_nsec3_chain(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_additionals(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_normal(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_pointers(zone_node_t *node, const zone_contents_t *zone);

int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb);

int zone_adjust_update(zone_update_t *update, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb);
