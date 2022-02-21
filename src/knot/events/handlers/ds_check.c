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

#include "knot/dnssec/ds_query.h"
#include "knot/zone/zone.h"

int event_ds_check(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &ctx, zone->name, zone_kaspdb(zone), NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_parent_ds_query(conf, &ctx, conf->cache.srv_tcp_remote_io_timeout);

	zone->timers.next_ds_check = 0;
	switch (ret) {
	case KNOT_NO_READY_KEY:
		break;
	case KNOT_EOK:
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
		break;
	default:
		if (ctx.policy->ksk_sbm_check_interval > 0) {
			time_t next_check = time(NULL) + ctx.policy->ksk_sbm_check_interval;
			zone->timers.next_ds_check = next_check;
			zone_events_schedule_at(zone, ZONE_EVENT_DS_CHECK, next_check);
		}
	}

	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK; // allways ok, if failure it has been rescheduled
}
