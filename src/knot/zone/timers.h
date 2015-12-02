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

#include "libknot/internal/namedb/namedb.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"

/*!
 * \brief Opens zone timers db.
 *
 * \param[in]  path      Path to a directory with the database.
 * \param[out] timer_db  Created database.
 *
 * \return KNOT_E*
 */
int open_timers_db(const char *path, namedb_t **timer_db);

/*!
 * \brief Closes zone timers db.
 *
 * \param timer_db  Timer database.
 */
void close_timers_db(namedb_t *timer_db);

/*!
 * \brief Reads zone timers from timers db.
 *        Currently these events are read (and stored):
 *          ZONE_EVENT_REFRESH
 *          ZONE_EVENT_EXPIRE
 *          ZONE_EVENT_FLUSH
 *
 * \param timer_db  Timer database.
 * \param zone      Zone to read timers for.
 * \param timers    Output array with timers (size must be ZONE_EVENT_COUNT).
 *
 * \return KNOT_E*
 */
int read_zone_timers(namedb_t *timer_db, const zone_t *zone, time_t *timers);

/*!
 * \brief Writes all zone timers to timers db.
 *
 * \param timer_db  Timer database.
 * \param zone_db   Zone database.
 *
 * \return KNOT_E*
 */
int write_timer_db(namedb_t *timer_db, knot_zonedb_t *zone_db);

/*!
 * \brief Removes stale zones info from timers db.
 *
 * \param timer_db  Timer database.
 * \param zone_db   Current zone database.
 * \return KNOT_EOK or an error
 */
int sweep_timer_db(namedb_t *timer_db, knot_zonedb_t *zone_db);
