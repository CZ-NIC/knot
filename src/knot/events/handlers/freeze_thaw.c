/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/events.h"
#include "knot/zone/zone.h"

int event_ufreeze(conf_t *conf, zone_t *zone)
{
	assert(zone);

	pthread_mutex_lock(&zone->events.mx);
	zone->events.ufrozen = true;
	pthread_mutex_unlock(&zone->events.mx);

	log_zone_info(zone->name, "zone updates frozen");

	return KNOT_EOK;
}

int event_uthaw(conf_t *conf, zone_t *zone)
{
	assert(zone);

	pthread_mutex_lock(&zone->events.mx);
	zone->events.ufrozen = false;
	pthread_mutex_unlock(&zone->events.mx);

	log_zone_info(zone->name, "zone updates unfrozen");

	return KNOT_EOK;
}
