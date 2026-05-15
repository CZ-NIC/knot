/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/log.h"
#include "knot/dnssec/ds_query.h"
#include "knot/query/query.h"
#include "knot/zone/zone.h"

static void reschedule_next(zone_t *zone, uint32_t interval)
{
	if (interval > 0) {
		time_t next_check = time(NULL) + interval;
		zone->timers->next_ds_check = next_check;
		zone_events_schedule_at(zone, ZONE_EVENT_DS_CHECK, next_check);
	}
}

int event_ds_check(conf_t *conf, zone_t *zone)
{
	assert(zone);

	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &ctx, zone->name, zone_kaspdb(zone), NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (zone_contents_is_empty(zone->contents)) {
		log_zone_debug(zone->name, "%s, zone is not loaded, will retry", log_operation_name(LOG_OPERATION_DS_CHECK));
		reschedule_next(zone, ctx.policy->ksk_sbm_check_interval);
		kdnssec_ctx_deinit(&ctx);
		return KNOT_EOK;
	}

	ret = knot_parent_ds_query(conf, &ctx, zone->server,
	                           conf->cache.srv_tcp_remote_io_timeout);

	zone->timers->next_ds_check = 0;
	zone->timers->flags |= TIMERS_MODIFIED;

	switch (ret) {
	case KNOT_NO_READY_KEY:
		break;
	case KNOT_EOK:
		zone_schedule_update(conf, zone, ZONE_EVENT_DNSSEC);
		break;
	default:
		reschedule_next(zone, ctx.policy->ksk_sbm_check_interval);
	}

	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK; // allways ok, if failure it has been rescheduled
}
