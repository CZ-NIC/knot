/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <urcu.h>

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

	pthread_mutex_lock(&zone->cu_lock);
	assert(zone->control_update == NULL || !(zone->control_update->flags & UPDATE_WFEV));
	zone_control_clear(zone);
	pthread_mutex_unlock(&zone->cu_lock);

	knot_sem_wait(&zone->cow_lock);
	zone_contents_deep_free(expired);
	knot_sem_post(&zone->cow_lock);

	zone->zonefile.exists = false;

	zone_set_last_master(zone, NULL);

	zone_timers_lock(zone);
	zone->timers.next_expire = time(NULL);
	zone->timers.next_refresh = zone->timers.next_expire;
	zone_timers_unlock(zone, true);
	replan_from_timers(conf, zone);

	return KNOT_EOK;
}
