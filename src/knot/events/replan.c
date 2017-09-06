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

#include <assert.h>

#include "knot/events/replan.h"

#define TIME_CANCEL 0
#define TIME_IGNORE (-1)

/*!
 * \brief Move DDNS queue from old zone to new zone and replan if necessary.
 *
 * New zone will contain references from the old zone. New zone will free
 * the data.
 */
static void replan_ddns(zone_t *zone, zone_t *old_zone)
{
	assert(zone);
	assert(old_zone);

	if (old_zone->ddns_queue_size == 0) {
		return;
	}

	ptrnode_t *node = NULL;
	WALK_LIST(node, old_zone->ddns_queue) {
		ptrlist_add(&zone->ddns_queue, node->d, NULL);
	}
	zone->ddns_queue_size = old_zone->ddns_queue_size;

	ptrlist_free(&old_zone->ddns_queue, NULL);

	zone_events_schedule_now(zone, ZONE_EVENT_UPDATE);
}

/*!
 * \brief Replan NOTIFY event if it was queued for the old zone.
 */
static void replan_notify(zone_t *zone, const zone_t *old_zone)
{
	assert(zone);
	assert(old_zone);

	time_t notify = zone_events_get_time(old_zone, ZONE_EVENT_NOTIFY);
	if (notify > 0) {
		zone_events_schedule_at(zone, notify);
	}
}

/*!
 * \brief Replan DNSSEC if automatic signing enabled.
 *
 * This is required as the configuration could have changed.
 */
static void replan_dnssec(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}
}

static bool can_expire(const zone_t *zone)
{
	return zone->timers.soa_expire > 0 && !zone_expired(zone);
}

/*!
 * \brief Replan events that depend on zone timers (REFRESH, EXPIRE, FLUSH, RESALT, PARENT DS QUERY).
 */
void replan_from_timers(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	time_t now = time(NULL);

	time_t refresh = TIME_CANCEL;
	if (zone_is_slave(conf, zone)) {
		refresh = zone->timers.next_refresh;
		assert(refresh > 0);
	}

	time_t expire_pre = TIME_IGNORE;
	time_t expire = TIME_IGNORE;
	if (zone_is_slave(conf, zone) && can_expire(zone)) {
		expire_pre = TIME_CANCEL;
		expire = zone->timers.last_refresh + zone->timers.soa_expire;
	}

	time_t flush = TIME_CANCEL;
	if (!zone_is_slave(conf, zone) || can_expire(zone)) {
		conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
		int64_t sync_timeout = conf_int(&val);
		if (sync_timeout > 0) {
			flush = zone->timers.last_flush + sync_timeout;
		}
	}

	time_t resalt = TIME_CANCEL;
	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		conf_val_t policy = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);
		conf_id_fix_default(&policy);
		val = conf_id_get(conf, C_POLICY, C_NSEC3, &policy);
		if (conf_bool(&val)) {
			if (zone->timers.last_resalt == 0) {
				resalt = now;
			} else {
				val = conf_id_get(conf, C_POLICY, C_NSEC3_SALT_LIFETIME, &policy);
				resalt = zone->timers.last_resalt + conf_int(&val);
			}
		}
	}

	time_t ds = zone->timers.next_parent_ds_q;
	if (ds == 0) {
		ds = TIME_IGNORE;
	}

	zone_events_schedule_at(zone,
	                        ZONE_EVENT_REFRESH, refresh,
	                        ZONE_EVENT_EXPIRE, expire_pre,
	                        ZONE_EVENT_EXPIRE, expire,
	                        ZONE_EVENT_FLUSH, flush,
	                        ZONE_EVENT_NSEC3RESALT, resalt,
	                        ZONE_EVENT_PARENT_DS_Q, ds);
}

void replan_load_new(zone_t *zone)
{
	// enqueue directly, make first load waitable
	// other events will cascade from load
	zone_events_enqueue(zone, ZONE_EVENT_LOAD);
}

void replan_load_bootstrap(conf_t *conf, zone_t *zone)
{
	replan_from_timers(conf, zone);
}

void replan_load_current(conf_t *conf, zone_t *zone, zone_t *old_zone)
{
	replan_ddns(zone, old_zone);
	replan_notify(zone, old_zone);

	replan_from_timers(conf, zone);
	replan_dnssec(conf, zone);
}

void replan_load_updated(zone_t *zone, zone_t *old_zone)
{
	replan_ddns(zone, old_zone);
	replan_notify(zone, old_zone);

	// other events will cascade from load
	zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
}
