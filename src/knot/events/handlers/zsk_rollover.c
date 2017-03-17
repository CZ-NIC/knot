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
#include <time.h>

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"
#include "knot/dnssec/key-events.h"

int event_zsk_rollover(conf_t *conf, zone_t *zone)
{
	bool keys_updated = false;
	time_t next_rollover = 0;

	conf_val_t policy = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name);

	kdnssec_ctx_t kctx = { 0 };

	int ret = kdnssec_ctx_init(&kctx, zone->name, &policy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dnssec_zsk_rollover(&kctx, &keys_updated, &next_rollover);
	kdnssec_ctx_deinit(&kctx);

	if (next_rollover) {
		zone_events_schedule_at(zone, ZONE_EVENT_ZSK_ROLLOVER, next_rollover);
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	if (keys_updated) {
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}

	return KNOT_EOK;
}
