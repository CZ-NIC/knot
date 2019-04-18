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

#include <assert.h>
#include <urcu.h>

#include "contrib/trim.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/handlers.h"
#include "knot/events/replan.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"

int event_expire(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	log_zone_info(zone->name, "zone expired");

	synchronize_rcu();
	knot_sem_wait(&zone->cow_lock);
	zone_contents_deep_free(expired);
	knot_sem_post(&zone->cow_lock);

	zone->zonefile.exists = false;
	mem_trim();

	// NOTE: must preserve zone->timers.soa_expire
	zone->timers.next_refresh = time(NULL);
	replan_from_timers(conf, zone);

	return KNOT_EOK;
}
