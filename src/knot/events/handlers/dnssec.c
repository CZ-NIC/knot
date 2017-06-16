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

	changeset_t ch;
	int ret = changeset_init(&ch, zone->name);
	if (ret != KNOT_EOK) {
		goto done;
	}

	zone_sign_reschedule_t resch = { 0 };
	resch.allow_rollover = true;
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

	ret = knot_dnssec_zone_sign(zone->contents, &ch, sign_flags, &resch);
	if (ret != KNOT_EOK) {
		goto done;
	}

	bool zone_changed = !changeset_empty(&ch);
	if (zone_changed) {
		/* Apply change. */
		apply_ctx_t a_ctx = { 0 };
		apply_init_ctx(&a_ctx, NULL, APPLY_STRICT);

		zone_contents_t *new_contents = NULL;
		int ret = apply_changeset(&a_ctx, zone->contents, &ch, &new_contents);
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
		synchronize_rcu();
		update_free_zone(&old_contents);

		update_cleanup(&a_ctx);
	}

	// Schedule dependent events
	event_dnssec_reschedule(conf, zone, &resch, zone_changed);

done:
	changeset_clear(&ch);
	return ret;
}
