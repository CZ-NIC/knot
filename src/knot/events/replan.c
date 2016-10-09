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

#include <assert.h>

#include "knot/events/replan.h"

/*!< \brief Creates new DDNS q in the new zone - q contains references from the old zone. */
static void duplicate_ddns_q(zone_t *zone, zone_t *old_zone)
{
	ptrnode_t *node = NULL;
	WALK_LIST(node, old_zone->ddns_queue) {
		ptrlist_add(&zone->ddns_queue, node->d, NULL);
	}
	zone->ddns_queue_size = old_zone->ddns_queue_size;

	// Reset the list, new zone will free the data.
	ptrlist_free(&old_zone->ddns_queue, NULL);
}

void replan_ddns(zone_t *zone, zone_t *old_zone)
{
	const bool have_updates = old_zone->ddns_queue_size > 0;
	if (have_updates) {
		duplicate_ddns_q(zone, old_zone);
	}

	if (have_updates) {
		zone_events_schedule_now(zone, ZONE_EVENT_UPDATE);
	}
}

static void replan_dnssec(conf_t *conf, zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		/* Keys could have changed, force resign. */
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}
}

static void replan_notify(zone_t *zone, const zone_t *old_zone)
{
	if (!old_zone) {
		return;
	}

	time_t notify = zone_events_get_time(old_zone, ZONE_EVENT_NOTIFY);
	if (notify > 0) {
		zone_events_schedule_at(zone, notify);
	}
}

/*!
 * \brief Replan events that depend on zone timers.
 */
static void replan_from_timers(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	time_t refresh = 0;
	if (zone_is_slave(conf, zone)) {
		refresh = zone->timers.next_refresh;
		assert(refresh > 0);
	}

	time_t expire = 0;
	// TODO: does this condition cover all cases?
	if (zone_is_slave(conf, zone) && !zone_expired(zone) && zone->timers.soa_expire > 0) {
		expire = zone->timers.last_refresh + zone->timers.soa_expire;
	}

	time_t flush = 0;
	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout > 0) {
		flush = zone->timers.last_flush + sync_timeout;
	}

	zone_events_schedule_at(zone, ZONE_EVENT_REFRESH, refresh,
	                              ZONE_EVENT_EXPIRE, expire,
	                              ZONE_EVENT_FLUSH, flush);
}

void zone_events_replan_updated(zone_t *zone, zone_t *old_zone)
{
	// other events will cascade from new zone load
	zone_events_enqueue(zone, ZONE_EVENT_LOAD);
	replan_ddns(zone, old_zone);
}

void zone_events_replan_current(conf_t *conf, zone_t *zone, zone_t *old_zone)
{
	replan_from_timers(conf, zone);
	replan_notify(zone, old_zone);
	replan_ddns(zone, old_zone);
	replan_dnssec(conf, zone);
}

void zone_events_replan_after_timers(conf_t *conf, zone_t *zone)
{
	replan_from_timers(conf, zone);
}
