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

#include "knot/dnssec/context.h"
#include "knot/dnssec/zone-events.h"

int event_nsec3resalt(conf_t *conf, zone_t *zone)
{
	knot_time_t salt_changed = 0;
	knot_time_t next_resalt = 0;

	kdnssec_ctx_t kctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &kctx, zone->name, zone->kaspdb, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dnssec_nsec3resalt(&kctx, &salt_changed, &next_resalt);
	if (ret == KNOT_EOK && salt_changed != 0) {
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
		zone->timers.last_resalt = kctx.now;
	}

	kdnssec_ctx_deinit(&kctx);

	if (next_resalt) {
		zone_events_schedule_at(zone, ZONE_EVENT_NSEC3RESALT, next_resalt);
	}

	return ret;
}
