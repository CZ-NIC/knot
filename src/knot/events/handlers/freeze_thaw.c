/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "contrib/macros.h"
#include "knot/events/events.h"
#include "knot/conf/conf.h"
#include "knot/zone/zone.h"
#include "knot/common/log.h"

int event_ufreeze(conf_t *conf, zone_t *zone)
{
	UNUSED(conf);
	assert(zone);

	pthread_mutex_lock(&zone->events.mx);
	zone->events.ufrozen = true;
	pthread_mutex_unlock(&zone->events.mx);

	log_zone_info(zone->name, "zone updates frozen");

	return KNOT_EOK;
}

int event_uthaw(conf_t *conf, zone_t *zone)
{
	UNUSED(conf);
	assert(zone);

	pthread_mutex_lock(&zone->events.mx);
	zone->events.ufrozen = false;
	pthread_mutex_unlock(&zone->events.mx);

	log_zone_info(zone->name, "zone updates unfrozen");

	return KNOT_EOK;
}
