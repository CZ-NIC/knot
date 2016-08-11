/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/updates/apply.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

/*!
 * \todo Separate signing from zone loading and drop this function.
 *
 * DNSSEC signing is planned from two places - after zone loading and after
 * successful resign. This function just logs the message and reschedules the
 * DNSSEC timer.
 *
 * I would rather see the invocation of the signing from event_dnssec()
 * function. This would require to split refresh event to zone load and zone
 * publishing.
 */
void schedule_dnssec(zone_t *zone, time_t refresh_at)
{
	// log a message

	char time_str[64] = { 0 };
	struct tm time_gm = { 0 };
	localtime_r(&refresh_at, &time_gm);
	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);
	log_zone_info(zone->name, "DNSSEC, next signing on %s", time_str);

	// schedule

	zone_events_schedule_at(zone, ZONE_EVENT_DNSSEC, refresh_at);
}

int event_dnssec(conf_t *conf, zone_t *zone)
{
	assert(zone);

	changeset_t ch;
	int ret = changeset_init(&ch, zone->name);
	if (ret != KNOT_EOK) {
		goto done;
	}

	uint32_t refresh_at = time(NULL);
	int sign_flags = 0;

	if (zone->flags & ZONE_FORCE_RESIGN) {
		log_zone_info(zone->name, "DNSSEC, dropping previous "
		              "signatures, resigning zone");
		zone->flags &= ~ZONE_FORCE_RESIGN;
		sign_flags = ZONE_SIGN_DROP_SIGNATURES;
	} else {
		log_zone_info(zone->name, "DNSSEC, signing zone");
		sign_flags = 0;
	}

	ret = knot_dnssec_zone_sign(zone->contents, &ch, sign_flags, &refresh_at);
	if (ret != KNOT_EOK) {
		goto done;
	}

	bool zone_changed = !changeset_empty(&ch);
	if (zone_changed) {
		/* Apply change. */
		apply_ctx_t a_ctx = { 0 };
		apply_init_ctx(&a_ctx, NULL, APPLY_STRICT);

		zone_contents_t *new_contents = NULL;
		int ret = apply_changeset(&a_ctx, zone, &ch, &new_contents);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			goto done;
		}

		/* Write change to journal. */
		ret = zone_change_store(conf, zone, &ch);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			update_rollback(&a_ctx);
			update_free_zone(&new_contents);
			goto done;
		}

		/* Switch zone contents. */
		zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
		zone->flags &= ~ZONE_EXPIRED;
		synchronize_rcu();
		update_free_zone(&old_contents);

		update_cleanup(&a_ctx);
	}

	// Schedule dependent events.

	schedule_dnssec(zone, refresh_at);
	if (zone_changed) {
		zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
		conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
		if (conf_int(&val) == 0) {
			zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
		}
	}

done:
	changeset_clear(&ch);
	return ret;
}
