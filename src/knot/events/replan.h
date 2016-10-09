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

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"

/*!
 * \brief Replan events when the zone is reloaded and updated.
 */
void zone_events_replan_updated(zone_t *zone, zone_t *old_zone);

/*!
 * \brief Replan events when the zone is reloaded and current.
 */
void zone_events_replan_current(conf_t *conf, zone_t *zone, zone_t *old_zone);

/*!
 * \brief Replan events when zone timers change.
 */
void zone_events_replan_after_timers(conf_t *conf, zone_t *zone);
