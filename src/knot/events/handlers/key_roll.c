/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/policy.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

static void log_next(const knot_dname_t *zone_name, knot_time_t next_roll, knot_time_t next_sign)
{
	char nr[64] = { 0 }, ns[64] = { 0 };
	if (knot_time_print(TIME_PRINT_HUMAN_MIXED, next_roll, nr, sizeof(nr)) >= 0 &&
	    knot_time_print(TIME_PRINT_HUMAN_MIXED, next_sign, ns, sizeof(ns)) >= 0) {
		log_zone_info(zone_name, "DNSSEC, next key roll action %s, next sign %s", nr, ns);
	}
}

int event_key_roll(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t kctx = { 0 };
	zone_sign_reschedule_t resch = { 0 };
	zone_sign_roll_flags_t r_flags = KEY_ROLL_ALLOW_ALL;

	if (zone->flags & ZONE_FORCE_KSK_ROLL) {
		zone->flags &= ~ZONE_FORCE_KSK_ROLL;
		r_flags |= KEY_ROLL_FORCE_KSK_ROLL;
	}
	if (zone->flags & ZONE_FORCE_ZSK_ROLL) {
		zone->flags &= ~ZONE_FORCE_ZSK_ROLL;
		r_flags |= KEY_ROLL_FORCE_ZSK_ROLL;
	}

	int ret = kdnssec_ctx_init(conf, &kctx, zone->name, zone->kaspdb, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// TODO FIX SOMEHOW!!
	if (zone->contents != NULL) {
		update_policy_from_zone(kctx.policy, zone->contents);
	} else {
		kctx.policy->zone_maximal_ttl = 3600;
		(void)kctx.policy->dnskey_ttl;
	}

	ret = knot_dnssec_key_rollover(&kctx, r_flags, &resch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_time_t next_roll = resch.next_rollover;
	knot_time_t next_roll2 = kdnssec_next(&kctx, false, false);
	knot_time_t next_sign = resch.next_sign;
	knot_time_t next_sign2 = kdnssec_next(&kctx, true, true);
	log_next(zone->name, next_roll, next_sign);

	zone_events_schedule_at(zone,
		ZONE_EVENT_KEY_ROLL, knot_time_min(next_roll, next_roll2),
		ZONE_EVENT_DNSSEC, knot_time_min(next_sign, next_sign2),
		ZONE_EVENT_PARENT_DS_Q, resch.plan_ds_query ? kctx.now : -1
	);

	kdnssec_ctx_deinit(&kctx);
	return KNOT_EOK;
}
