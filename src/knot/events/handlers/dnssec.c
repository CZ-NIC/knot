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
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/zone-events.h"
#include "knot/events/log.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

void event_dnssec_reschedule(conf_t *conf, zone_t *zone,
			     const zone_sign_reschedule_t *refresh, bool zone_changed)
{
	time_t now = time(NULL);
	time_t ignore = -1;
	knot_time_t refresh_at = refresh->next_sign;

	if (knot_time_cmp(refresh->next_rollover, refresh_at) < 0) {
		refresh_at = refresh->next_rollover;
	}

	if (refresh_at <= 0) {
		return;
	}

	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);

	log_dnssec_next(zone->name, (time_t)refresh_at);

	if (refresh->plan_ds_query) {
		log_zone_notice(zone->name, "DNSSEC, published CDS, CDNSKEY for submission");
	}

	zone_events_schedule_at(zone,
		ZONE_EVENT_DNSSEC, (time_t)refresh_at,
		ZONE_EVENT_PARENT_DS_Q, refresh->plan_ds_query ? now : ignore,
		ZONE_EVENT_NOTIFY, zone_changed ? now : ignore,
		ZONE_EVENT_FLUSH,  zone_changed && conf_int(&val) == 0 ? now : ignore
	);
}

int event_dnssec(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_sign_reschedule_t resch = { 0 };
	resch.allow_rollover = true;
	int sign_flags = 0;

	if (zone_is_slave(conf, zone)) {
		log_zone_notice(zone->name, "DNSSEC, skipped re-signing on slave zone, "
				"will be resigned on next incoming transfer");
		return KNOT_EOK;
	}

	if (zone->flags & ZONE_FORCE_RESIGN) {
		log_zone_info(zone->name, "DNSSEC, dropping previous "
		              "signatures, resigning zone");
		zone->flags &= ~ZONE_FORCE_RESIGN;
		sign_flags = ZONE_SIGN_DROP_SIGNATURES;
	} else {
		log_zone_info(zone->name, "DNSSEC, signing zone");
		sign_flags = 0;
	}

	zone_update_t up;
	int ret = zone_update_init(&up, zone, UPDATE_INCREMENTAL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dnssec_zone_sign(&up, sign_flags, &resch);
	if (ret != KNOT_EOK) {
		goto done;
	}

	bool zone_changed = !zone_update_no_change(&up);
	if (zone_changed) {
		ret = zone_update_commit(conf, &up);
		if (ret != KNOT_EOK) {
			goto done;
		}
	}

	// Schedule dependent events
	event_dnssec_reschedule(conf, zone, &resch, zone_changed);

done:
	zone_update_clear(&up);
	return ret;
}
