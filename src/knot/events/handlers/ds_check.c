/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/dnssec/ds_query.h"
#include "knot/zone/zone.h"

int event_ds_check(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EEMPTYZONE;
	}

	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &ctx, zone->name, zone_kaspdb(zone), NULL);
	if (ret != KNOT_EOK) {
		return ret;
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
		if (ctx.policy->ksk_sbm_check_interval > 0) {
			time_t next_check = time(NULL) + ctx.policy->ksk_sbm_check_interval;
			zone->timers->next_ds_check = next_check;
			zone_events_schedule_at(zone, ZONE_EVENT_DS_CHECK, next_check);
		}
	}

	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK; // allways ok, if failure it has been rescheduled
}
