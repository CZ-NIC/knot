/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

typedef struct {
	const zone_contents_t *zone;
	zone_tree_t *changed_nodes;
	bool nsec3_param_changed;
} adjust_ctx_t;

typedef int (*adjust_cb_t)(zone_node_t *, adjust_ctx_t *);

/*
 * \brief Varoius callbacks for adjusting zone node's params and pointers.
 *
 * \param node   Node to be adjusted. Must be already inside the zone contents!
 * \param zone   Zone being adjusted.
 *
 * \return KNOT_E*
 */

// fix NORMAL node flags, like NODE_FLAGS_NONAUTH, NODE_FLAGS_DELEG etc.
int adjust_cb_flags(zone_node_t *node, adjust_ctx_t *ctx);

// reset pointer to NSEC3 node
int unadjust_cb_point_to_nsec3(zone_node_t *node, adjust_ctx_t *ctx);

// fix NORMAL node pointer to NSEC3 node proving nonexistence of wildcard
int adjust_cb_wildcard_nsec3(zone_node_t *node, adjust_ctx_t *ctx);

// fix NSEC3 node flags: NODE_FLAGS_IN_NSEC3_CHAIN
int adjust_cb_nsec3_flags(zone_node_t *node, adjust_ctx_t *ctx);

// fix pointer at corresponding NSEC3 node
int adjust_cb_nsec3_pointer(zone_node_t *node, adjust_ctx_t *ctx);

// fix NORMAL node flags to additionals, like NS records and glue...
int adjust_cb_additionals(zone_node_t *node, adjust_ctx_t *ctx);

// adjust_cb_flags and adjust_cb_nsec3_pointer at once
int adjust_cb_flags_and_nsec3(zone_node_t *node, adjust_ctx_t *ctx);

// adjust_cb_nsec3_pointer, adjust_cb_wildcard_nsec3 and adjust_cb_additionals at once
int adjust_cb_nsec3_and_additionals(zone_node_t *node, adjust_ctx_t *ctx);

// adjust_cb_wildcard_nsec3 and adjust_cb_nsec3_pointer at once
int adjust_cb_nsec3_and_wildcard(zone_node_t *node, adjust_ctx_t *ctx);

// dummy callback, just make prev pointers adjusting and zone size measuring work
int adjust_cb_void(zone_node_t *node, adjust_ctx_t *ctx);

/*!
 * \brief Apply callback to NSEC3 and NORMAL nodes. Fix PREV pointers and measure zone size.
 *
 * \param zone          Zone to be adjusted.
 * \param nodes_cb      Callback for NORMAL nodes.
 * \param nsec3_cb      Callback for NSEC3 nodes.
 * \param measure_zone  While adjusting, count the size and max TTL of the zone.
 * \param adjust_prevs  Also (re-)generate node->prev pointers.
 * \param threads       Operate in parallel using specified threads.
 * \param add_changed   Special tree to add any changed node (by adjusting) into.
 *
 * \return KNOT_E*
 */
int zone_adjust_contents(zone_contents_t *zone, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb,
                         bool measure_zone, bool adjust_prevs, unsigned threads,
                         zone_tree_t *add_changed);

/*!
 * \brief Apply callback to nodes affected by the zone update.
 *
 * \note Fixing PREV pointers and zone measurement does not make sense since we are not
 *       iterating over whole zone. The same applies for callback that reference other
 *       (unchanged, but indirectly affected) zone nodes.
 *
 * \param update     Zone update being finalized.
 * \param nodes_cb   Callback for NORMAL nodes.
 * \param nsec3_cb   Callback for NSEC3 nodes.
 * \param measure_diff  While adjusting, count the size difference and max TTL change.
 *
 * \return KNOT_E*
 */
int zone_adjust_update(zone_update_t *update, adjust_cb_t nodes_cb, adjust_cb_t nsec3_cb, bool measure_diff);

/*!
 * \brief Do a general-purpose full update.
 *
 * This operates in two phases, first fix basic node flags and prev pointers,
 * than nsec3-related pointers and additionals.
 *
 * \param zone     Zone to be adjusted.
 * \param threads  Parallelize some adjusting using specified threads.
 *
 * \return KNOT_E*
 */
int zone_adjust_full(zone_contents_t *zone, unsigned threads);

/*!
 * \brief Do a generally approved adjust after incremental update.
 *
 * \param update   Zone update to be adjusted incrementally.
 * \param threads  Parallelize some adjusting using specified threads.
 *
 * \return KNOT_E*
 */
int zone_adjust_incremental_update(zone_update_t *update, unsigned threads);
