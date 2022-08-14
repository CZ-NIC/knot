/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>

#include "knot/dnssec/kasp/kasp_db.h"
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
	if (old_zone->ddns_queue_size == 0) {
		return;
	}

	ptrnode_t *node;
	WALK_LIST(node, old_zone->ddns_queue) {
		ptrlist_add(&zone->ddns_queue, node->d, NULL);
	}
	zone->ddns_queue_size = old_zone->ddns_queue_size;

	ptrlist_free(&old_zone->ddns_queue, NULL);

	zone_events_schedule_now(zone, ZONE_EVENT_UPDATE);
}

/*!
 * \brief Replan events that are already planned for the old zone.
 *
 * \notice Preserves notifailed.
 */
static void replan_from_zone(zone_t *zone, zone_t *old_zone)
{
	assert(zone);
	assert(old_zone);

	replan_ddns(zone, old_zone);

	const zone_event_type_t types[] = {
		ZONE_EVENT_REFRESH,
		ZONE_EVENT_FLUSH,
		ZONE_EVENT_BACKUP,
		ZONE_EVENT_NOTIFY,
		ZONE_EVENT_UFREEZE,
		ZONE_EVENT_UTHAW,
		ZONE_EVENT_INVALID
	};

	for (const zone_event_type_t *type = types; *type != ZONE_EVENT_INVALID; type++) {
		time_t when = zone_events_get_time(old_zone, *type);
		if (when > 0) {
			zone_events_schedule_at(zone, *type, when);
		}
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
		if (zone->contents == NULL && zone->timers.last_refresh_ok) { // zone disappeared w/o expiry
			refresh = now;
		}
		assert(refresh > 0);
	}

	time_t expire_pre = TIME_IGNORE;
	time_t expire = TIME_IGNORE;
	if (zone_is_slave(conf, zone) && zone->contents != NULL) {
		expire_pre = TIME_CANCEL;
		expire = zone->timers.next_expire;
	}

	time_t flush = TIME_IGNORE;
	if (!zone_is_slave(conf, zone) || zone->contents != NULL) {
		conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
		int64_t sync_timeout = conf_int(&val);
		if (sync_timeout > 0) {
			flush = zone->timers.last_flush + sync_timeout;
		}
	}

	time_t resalt = TIME_IGNORE;
	time_t ds_check = TIME_CANCEL;
	time_t ds_push = TIME_CANCEL;
	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		conf_val_t policy = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);
		conf_id_fix_default(&policy);
		val = conf_id_get(conf, C_POLICY, C_NSEC3, &policy);
		if (conf_bool(&val)) {
			knot_time_t last_resalt = 0;
			if (knot_lmdb_open(zone_kaspdb(zone)) == KNOT_EOK) {
				(void)kasp_db_load_nsec3salt(zone_kaspdb(zone), zone->name, NULL, &last_resalt);
			}
			if (last_resalt == 0) {
				resalt = now;
			} else {
				val = conf_id_get(conf, C_POLICY, C_NSEC3_SALT_LIFETIME, &policy);
				if (conf_int(&val) > 0) {
					resalt = last_resalt + conf_int(&val);
				}
			}
		}

		ds_check = zone->timers.next_ds_check;
		if (ds_check == 0) {
			ds_check = TIME_IGNORE;
		}
		ds_push = zone->timers.next_ds_push;
		if (ds_push == 0) {
			ds_push = TIME_IGNORE;
		}
	}

	zone_events_schedule_at(zone,
	                        ZONE_EVENT_REFRESH, refresh,
	                        ZONE_EVENT_EXPIRE, expire_pre,
	                        ZONE_EVENT_EXPIRE, expire,
	                        ZONE_EVENT_FLUSH, flush,
	                        ZONE_EVENT_DNSSEC, resalt,
	                        ZONE_EVENT_DS_CHECK, ds_check,
	                        ZONE_EVENT_DS_PUSH, ds_push);
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
	replan_from_zone(zone, old_zone);

	if (zone->contents != NULL || zone_expired(zone)) {
		replan_from_timers(conf, zone);
		replan_dnssec(conf, zone);
	} else {
		zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
	}
}

void replan_load_updated(zone_t *zone, zone_t *old_zone)
{
	zone_notifailed_clear(zone);
	replan_from_zone(zone, old_zone);

	// other events will cascade from load
	zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
}
