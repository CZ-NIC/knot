/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/updates/zone-update.h"

typedef enum {
	MEASURE_SIZE_NONE = 0, // don't measure size of zone
	MEASURE_SIZE_WHOLE,    // measure complete size of zone nodes
	MEASURE_SIZE_DIFF,     // measure difference in size for bi-nodes in zone update
} measure_size_t;

typedef enum {
	MEASURE_TTL_NONE = 0,  // don't measure max TTL of zone records
	MEASURE_TTL_WHOLE,     // measure max TTL among all zone records
	MEASURE_TTL_DIFF,      // check out zone update (bi-nodes) if the max TTL is affected
	MEASURE_TTL_LIMIT,     // measure max TTL whole; stop if a specific value is reached
} measure_ttl_t;

typedef struct {
	measure_size_t how_size;
	measure_ttl_t how_ttl;
	ssize_t zone_size;
	uint32_t max_ttl;
	uint32_t rem_max_ttl;
	uint32_t limit_max_ttl;
} measure_t;

/*! \brief Initialize measure struct. */
measure_t knot_measure_init(bool measure_whole, bool measure_diff);

/*!
 * \brief Measure one node's size and max TTL, collecting into measure struct.
 *
 * \param node   Node to be measured.
 * \param m      Measure context with instructions and results.
 *
 * \return False if no more measure is needed.
 * \note You will probably ignore the return value.
 */
bool knot_measure_node(zone_node_t *node, measure_t *m);

/*!
 * \brief Collect the measured results and update the new zone with measured properties.
 *
 * \param zone     Zone.
 * \param m        Measured results.
 */
void knot_measure_finish_zone(measure_t *m, zone_contents_t *zone);

/*!
 * \brief Collect the measured results and update the new zone with measured properties.
 *
 * \param update   Zone update with the zone.
 * \param m        Measured results.
 */
void knot_measure_finish_update(measure_t *m, zone_update_t *update);
