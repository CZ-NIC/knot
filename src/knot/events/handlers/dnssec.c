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

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/apply.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

static void log_dnssec_next(const knot_dname_t *zone, knot_time_t refresh_at)
{
	char time_str[64] = { 0 };
	struct tm time_gm = { 0 };
	time_t refresh = refresh_at;
	localtime_r(&refresh, &time_gm);
	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);
	if (refresh_at == 0) {
		log_zone_warning(zone, "DNSSEC, next signing not scheduled");
	} else {
		log_zone_info(zone, "DNSSEC, next signing at %s", time_str);
	}
}

void event_dnssec_reschedule(conf_t *conf, zone_t *zone,
			     const zone_sign_reschedule_t *refresh, bool zone_changed)
{
	time_t now = time(NULL);
	time_t ignore = -1;
	knot_time_t refresh_at = refresh->next_sign;

	refresh_at = knot_time_min(refresh_at, refresh->next_rollover);
	refresh_at = knot_time_min(refresh_at, refresh->next_nsec3resalt);

	log_dnssec_next(zone->name, (time_t)refresh_at);

	if (refresh->plan_ds_check) {
		zone->timers.next_ds_check = now;
	}

	zone_events_schedule_at(zone,
		ZONE_EVENT_DNSSEC, refresh_at ? (time_t)refresh_at : ignore,
		ZONE_EVENT_DS_CHECK, refresh->plan_ds_check ? now : ignore
	);
	if (zone_changed) {
		zone_schedule_notify(zone, 0);
	}
}

int event_dnssec(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_sign_reschedule_t resch = { 0 };
	zone_sign_roll_flags_t r_flags = KEY_ROLL_ALLOW_ALL;
	int sign_flags = 0;
	bool zone_changed = false;

	if (zone_get_flag(zone, ZONE_FORCE_RESIGN, true)) {
		log_zone_info(zone->name, "DNSSEC, dropping previous "
		              "signatures, re-signing zone");
		sign_flags = ZONE_SIGN_DROP_SIGNATURES;
	} else {
		log_zone_info(zone->name, "DNSSEC, signing zone");
		sign_flags = 0;
	}

	if (zone_get_flag(zone, ZONE_FORCE_KSK_ROLL, true)) {
		r_flags |= KEY_ROLL_FORCE_KSK_ROLL;
	}
	if (zone_get_flag(zone, ZONE_FORCE_ZSK_ROLL, true)) {
		r_flags |= KEY_ROLL_FORCE_ZSK_ROLL;
	}

	zone_update_t up;
	int ret = zone_update_init(&up, zone, UPDATE_INCREMENTAL | UPDATE_NO_CHSET);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_dnssec_zone_sign(&up, conf, sign_flags, r_flags, 0, &resch);
	if (ret != KNOT_EOK) {
		goto done;
	}

	zone_changed = !zone_update_no_change(&up);

	ret = zone_update_commit(conf, &up);
	if (ret != KNOT_EOK) {
		goto done;
	}

done:
	// Schedule dependent events
	event_dnssec_reschedule(conf, zone, &resch, zone_changed);

	if (ret != KNOT_EOK) {
		zone_update_clear(&up);
	}
	return ret;
}
