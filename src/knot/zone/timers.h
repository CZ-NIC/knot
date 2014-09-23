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

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"
#include "knot/zone/events/events.h"
#include "knot/zone/zonedb.h"

#pragma once

int open_timers_db(conf_t *conf);

void close_timers_db(conf_t *conf);

int write_zone_timers(conf_t *conf, zone_t *zone);

int read_zone_timers(conf_t *conf, const zone_t *zone, time_t *timers);

int sweep_timer_db(conf_t *conf, knot_zonedb_t *zone_db);

