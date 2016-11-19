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
 * \brief Replan timer dependent refresh, expire, and flush.
 */
void replan_from_timers(conf_t *conf, zone_t *zone);

/*!
 * \defgroup replan_load Replan timers after zone load or reload.
 * @{
 */
void replan_load_new(zone_t *zone);
void replan_load_bootstrap(conf_t *conf, zone_t *zone);
void replan_load_current(conf_t *conf, zone_t *zone, zone_t *old_zone);
void replan_load_updated(zone_t *zone, zone_t *old_zone);
/*! @} */
