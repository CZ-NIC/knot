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

#include "knot/common/log.h"
#include "knot/dnssec/ds_query.h"
#include "knot/zone/zone.h"

int event_parent_ds_q(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t ctx = { 0 };

	int ret = kdnssec_ctx_init(conf, &ctx, zone->name, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_keyset_t keyset = { 0 };
	ret = load_zone_keys(&ctx, &keyset, false);
	if (ret != KNOT_EOK) {
		kdnssec_ctx_deinit(&ctx);
		return ret;
	}

	for (size_t i = 0; i < keyset.count; i++) {
		zone_key_t *key = &keyset.keys[i];
		if (key->is_ready) {
			assert(key->is_ksk);
			char param[32];
			(void)snprintf(param, sizeof(param), "KEY_SUBMISSION=%hu",
			               dnssec_key_get_keytag(key->key));

			log_fmt_zone(LOG_NOTICE, LOG_SOURCE_ZONE, zone->name, param,
			             "DNSSEC, KSK submission, waiting for confirmation");
		}
	}

	ret = knot_parent_ds_query(&ctx, &keyset, conf->cache.srv_tcp_reply_timeout * 1000);

	zone->timers.next_parent_ds_q = 0;
	if (ret != KNOT_EOK) {
		if (ctx.policy->ksk_sbm_check_interval > 0) {
			time_t next_check = time(NULL) + ctx.policy->ksk_sbm_check_interval;
			zone->timers.next_parent_ds_q = next_check;
			zone_events_schedule_at(zone, ZONE_EVENT_PARENT_DS_Q, next_check);
		}
	} else {
		zone_events_schedule_now(zone, ZONE_EVENT_DNSSEC);
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK; // allways ok, if failure it has been rescheduled
}
