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
#include "knot/events/handlers.h"
#include "knot/events/log.h"
#include "knot/events/replan.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"

int event_load(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_contents_t *contents = NULL;
	bool load_from_journal = false;
	zone_sign_reschedule_t dnssec_refresh = { 0 };
	dnssec_refresh.allow_rollover = true;

	/* Take zone file mtime and load it. */
	time_t mtime;
	char *filename = conf_zonefile(conf, zone->name);
	int ret = zonefile_exists(filename, &mtime);
	free(filename);
	if (ret != KNOT_EOK) {
		load_from_journal = true;
		ret = zone_load_from_journal(conf, zone, &contents);
		if (ret != KNOT_EOK) {
			if (zone_load_can_bootstrap(conf, zone->name)) {
				log_zone_info(zone->name, "zone will be bootstrapped");
			} else {
				log_zone_info(zone->name, "zone not found");
			}
			goto fail;
		}
		goto load_post;
	}

	ret = zone_load_contents(conf, zone->name, &contents);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Store the zonefile SOA serial. */
	zone->zonefile.serial = zone_contents_serial(contents);

	/* Apply journal if first load or reload with original zonefile. */
	if (zone->contents == NULL ||
	    (zone->zonefile.exists && zone->zonefile.mtime == mtime)) {
		ret = zone_load_journal(conf, zone, contents);
		if (ret != KNOT_EOK) {
			goto fail;
		}
	}

	/* Store the zonefile mtime. */
	zone->zonefile.mtime = mtime;

load_post:
	/* Post load actions - calculate delta, sign with DNSSEC... */
	/*! \todo issue #242 dnssec signing should occur in the special event */
	ret = zone_load_post(conf, zone, &contents, &dnssec_refresh);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Everything went alright, switch the contents. */
	zone->zonefile.exists = !load_from_journal;
	zone_contents_t *old = zone_switch_contents(zone, contents);
	bool old_contents = (old != NULL);
	uint32_t old_serial = zone_contents_serial(old);
	if (old != NULL) {
		synchronize_rcu();
		zone_contents_deep_free(&old);
	}

	uint32_t current_serial = zone_contents_serial(zone->contents);
	if (old_contents) {
		log_zone_info(zone->name, "loaded, serial %u -> %u",
		              old_serial, current_serial);
	} else {
		log_zone_info(zone->name, "loaded, serial %u", current_serial);
	}

	if (zone->control_update != NULL) {
		log_zone_warning(zone->name, "control transaction aborted");
		zone_control_clear(zone);
	}

	/* Schedule depedent events. */

	const knot_rdataset_t *soa = zone_soa(zone);
	zone->timers.soa_expire = knot_soa_expire(soa);
	replan_from_timers(conf, zone);

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		zone_events_schedule_now(zone, ZONE_EVENT_NSEC3RESALT);
		// if nothing to be done NOW for any of those, they will replan themselves for later

		event_dnssec_reschedule(conf, zone, &dnssec_refresh, false); // false since we handle NOTIFY below
	}

	// TODO: track serial across restart and avoid unnecessary notify
	if (!load_from_journal && (!old_contents || old_serial != current_serial)) {
		zone_events_schedule_now(zone, ZONE_EVENT_NOTIFY);
	}

	return KNOT_EOK;

fail:
	zone->zonefile.exists = false;
	zone_contents_deep_free(&contents);

	/* Try to bootstrap the zone if local error. */
	replan_from_timers(conf, zone);

	if (load_from_journal && ret == KNOT_ENOENT) {
		// attempted zone-in-journal, not present = normal state
		ret = KNOT_EOK;
	}

	return ret;
}
