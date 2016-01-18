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

#include "knot/zone/events/replan.h"
#include "knot/zone/events/handlers.h"
#include "libknot/rrtype/soa.h"
#include "contrib/macros.h"

/* -- Zone event replanning functions --------------------------------------- */

/*!< \brief Replans event for new zone according to old zone. */
static void replan_event(zone_t *zone, const zone_t *old_zone, zone_event_type_t e)
{
	const time_t event_time = zone_events_get_time(old_zone, e);
	if (event_time > ZONE_EVENT_NOW) {
		zone_events_schedule_at(zone, e, event_time);
	}
}

/*!< \brief Replans events that are dependent on the SOA record. */
static void replan_soa_events(zone_t *zone, const zone_t *old_zone)
{
	if (!zone_is_slave(zone)) {
		// Events only valid for slaves.
		return;
	}

	if (zone_is_slave(old_zone)) {
		// Replan SOA events.
		replan_event(zone, old_zone, ZONE_EVENT_REFRESH);
		replan_event(zone, old_zone, ZONE_EVENT_EXPIRE);
	} else {
		// Plan SOA events anew.
		if (!zone_contents_is_empty(zone->contents)) {
			const knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
			                                           KNOT_RRTYPE_SOA);
			assert(soa);
			zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
		}
	}
}

/*!< \brief Replans transfer event. */
static void replan_xfer(zone_t *zone, const zone_t *old_zone)
{
	if (!zone_is_slave(zone)) {
		// Only valid for slaves.
		return;
	}

	if (zone_is_slave(old_zone)) {
		// Replan the transfer from old zone.
		replan_event(zone, old_zone, ZONE_EVENT_XFER);
	} else if (zone_contents_is_empty(zone->contents)) {
		// Plan transfer anew.
		zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
		zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
	}
}

/*!< \brief Replans flush event. */
static void replan_flush(zone_t *zone, const zone_t *old_zone)
{
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout <= 0) {
		// Immediate sync scheduled after events.
		return;
	}

	const time_t flush_time = zone_events_get_time(old_zone, ZONE_EVENT_FLUSH);
	if (flush_time <= ZONE_EVENT_NOW) {
		// Not scheduled previously.
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, sync_timeout);
		return;
	}

	// Pick time to schedule: either reuse or schedule sooner than old event.
	const time_t schedule_at = MIN(time(NULL) + sync_timeout, flush_time);
	zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, schedule_at);
}

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

/*!< Replans DNSSEC event. Not whole resign needed, \todo #247 */
static void replan_dnssec(zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		/* Keys could have changed, force resign. */
		zone_events_schedule(zone, ZONE_EVENT_DNSSEC, ZONE_EVENT_NOW);
	}
}

/*!< Replans DDNS event. */
void replan_update(zone_t *zone, zone_t *old_zone)
{
	const bool have_updates = old_zone->ddns_queue_size > 0;
	if (have_updates) {
		duplicate_ddns_q(zone, old_zone);
	}

	if (have_updates) {
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}
}

void replan_events(zone_t *zone, zone_t *old_zone)
{
	replan_soa_events(zone, old_zone);
	replan_xfer(zone, old_zone);
	replan_flush(zone, old_zone);
	replan_event(zone, old_zone, ZONE_EVENT_NOTIFY);
	replan_update(zone, old_zone);
	replan_dnssec(zone);
}
