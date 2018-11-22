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

/*
 * \brief Varoius callbacks for adjusting zone node's params and pointers.
 *
 * \param node   Node to be adjusted. Must be already inside the zone contents!
 * \param zone   Zone being adjusted.
 *
 * \return KNOT_E*
 */

// fix NORMAL node flags, like NODE_FLAGS_NONAUTH, NODE_FLAGS_DELEG etc.
int adjust_cb_flags(zone_node_t *node, const zone_contents_t *zone);

// fix NORMAL node pointer to corresponding NSEC3 node
int adjust_cb_point_to_nsec3(zone_node_t *node, const zone_contents_t *zone);

// fix NORMAL node pointer to NSEC3 node proving nonexistence of wildcard
int adjust_cb_wildcard_nsec3(zone_node_t *node, const zone_contents_t *zone);

// fix NSEC3 node flags: NODE_FLAGS_IN_NSEC3_CHAIN
int adjust_cb_nsec3_flags(zone_node_t *node, const zone_contents_t *zone);

// fix NORMAL node flags to additionals, like NS records and glue...
int adjust_cb_additionals(zone_node_t *node, const zone_contents_t *zone);

// adjust_cb_flags and adjust_cb_additionals at once
int adjust_cb_flags_and_additionals(zone_node_t *node, const zone_contents_t *zone);

// adjust_cb_flags and adjust_cb_flags at once
int adjust_cb_flags_and_nsec3(zone_node_t *node, const zone_contents_t *zone);

// adjust_cb_point_to_nsec3, adjust_cb_wildcard_nsec3 and adjust_cb_additionals at once
int adjust_cb_nsec3_and_additionals(zone_node_t *node, const zone_contents_t *zone);

// dummy callback, just make prev pointers adjusting and zone size measuring work
int adjust_cb_void(zone_node_t *node, const zone_contents_t *zone);

/*!
 * \brief Apply callback to NSEC3 and NORMAL nodes. Fix PREV pointers and measure zone size.
 *
 * \param zone       Zone to be adjusted.
 * \param nodes_cb   Callback for NORMAL nodes.
 * \param nsec3_cb   Callback for NSEC3 nodes.
 *
 * \return KNOT_E*
 */
int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb);

/*!
 * \brief Apply callback to nodes affected by the zone update.
 *
 * \note Fixing PREV pointers and zone measurement does not make sense since we are not
 *       iterating over whole zone. The same applies for callback that reference other
 *       (unchanged, but indirecty affected) zone nodes.
 *
 * \param update     Zone update being finalized.
 * \param nodes_cb   Callback for NORMAL nodes.
 * \param nsec3_cb   Callback for NSEC3 nodes.
 *
 * \return KNOT_E*
 */
int zone_adjust_update(zone_update_t *update, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb);

/*!
 * \brief Do a general-purpose full update.
 *
 * This operates in two phases, first fix basic node flags and prev pointers,
 * than nsec3-related pointers and additionals.
 *
 * \param zone   Zone to be adjusted.
 *
 * \return KNOT_E*
 */
int zone_adjust_full(zone_contents_t *zone);
