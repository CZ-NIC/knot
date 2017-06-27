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

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/zone-events.h"
#include "knot/events/handlers.h"
#include "knot/events/log.h"
#include "knot/events/replan.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"

static int post_load_dnssec_actions(conf_t *conf, zone_t *zone)
{
	kdnssec_ctx_t kctx = { 0 };
	int ret = kdnssec_ctx_init(conf, &kctx, zone->name, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	bool ignore1 = false; knot_time_t ignore2 = 0;
	ret = knot_dnssec_nsec3resalt(&kctx, &ignore1, &ignore2);
	if (ret != KNOT_EOK) {
		kdnssec_ctx_deinit(&kctx);
		return ret;
	}

	if (zone_has_key_sbm(&kctx)) {
		zone_events_schedule_now(zone, ZONE_EVENT_PARENT_DS_Q);
	}

	kdnssec_ctx_deinit(&kctx);
	return KNOT_EOK;
}

int event_load(conf_t *conf, zone_t *zone)
{
	assert(zone);

	conf_val_t val;
	zone_contents_t *contents = NULL;
	bool contents_in_update = true;
	zone_sign_reschedule_t dnssec_refresh = { 0 };
	dnssec_refresh.allow_rollover = true;

	time_t mtime;
	char *filename = conf_zonefile(conf, zone->name);
	int ret = zonefile_exists(filename, &mtime);
	bool load_from_journal = (ret != KNOT_EOK);
	free(filename);


	bool load_journal_first = false;
	bool loaded_from_journal = false;
	if (zone->contents == NULL) {
		conf_val_t val = conf_zone_get(conf, C_ZONE_IN_JOURNAL, zone->name);
		load_journal_first = conf_bool(&val);
	}

	if (load_from_journal) {
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
	} else if (load_journal_first) {
		ret = zone_load_from_journal(conf, zone, &contents);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			goto fail;
		}
		loaded_from_journal = (ret == KNOT_EOK);
		if (loaded_from_journal) {
			goto load_post;
		}
	}

	ret = zone_load_contents(conf, zone->name, &contents);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	if (load_journal_first && !loaded_from_journal) {
		ret = zone_in_journal_store(conf, zone, contents);
		if (ret != KNOT_EOK) {
			log_zone_warning(zone->name, "failed to write zone-in-journal (%s)",
					 knot_strerror(ret));
		}
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
	val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	val = conf_zone_get(conf, C_IXFR_DIFF, zone->name);
	bool build_diffs = conf_bool(&val);
	if (!build_diffs) {
		val = conf_zone_get(conf, C_ZONE_IN_JOURNAL, zone->name);
		build_diffs = conf_bool(&val);
	}

	bool old_contents = (zone->contents != NULL);
	const bool contents_changed = old_contents && (contents != zone->contents);

	/* Build the post-load update structure */
	zone_update_t post_load = { 0 };
	if (old_contents) {
		if (build_diffs && contents_changed) {
			ret = zone_update_from_differences(&post_load, zone, contents, UPDATE_INCREMENTAL);
			if (ret == KNOT_ERANGE || ret == KNOT_ESEMCHECK) {
				log_zone_warning(zone->name, (ret == KNOT_ESEMCHECK ?
					"failed to create journal entry, zone file changed without "
					"SOA serial update" : "IXFR history will be lost, "
					"zone file changed, but SOA serial decreased"));
				ret = zone_update_from_contents(&post_load, zone, contents, UPDATE_FULL);
			}
		} else {
			ret = zone_update_from_contents(&post_load, zone, contents, UPDATE_FULL);
		}
	} else {
		ret = zone_update_from_contents(&post_load, zone, contents, UPDATE_INCREMENTAL);
	}
	if (ret != KNOT_EOK) {
		contents_in_update = false;
		goto fail;
	}

	/* Sign zone using DNSSEC (if configured). */
	if (dnssec_enable) {
		ret = post_load_dnssec_actions(conf, zone);
		if (ret == KNOT_EOK) {
			ret = knot_dnssec_zone_sign(&post_load, 0, &dnssec_refresh);
		}
		if (ret != KNOT_EOK) {
			zone_update_clear(&post_load);
			goto fail;
		}
	}

	/* Everything went alright, switch the contents. */
	zone->zonefile.exists = !load_from_journal;
	uint32_t old_serial = zone_contents_serial(zone->contents);
	ret = zone_update_commit(conf, &post_load);
	zone_update_clear(&post_load);
	if (ret != KNOT_EOK) {
		goto fail;
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

	if (dnssec_enable) {
		zone_events_schedule_now(zone, ZONE_EVENT_NSEC3RESALT);
		// if nothing to be done NOW for any of those, they will replan themselves for later

		event_dnssec_reschedule(conf, zone, &dnssec_refresh, false); // false since we handle NOTIFY below
	}

	// TODO: track serial across restart and avoid unnecessary notify
	if (!load_from_journal && (!old_contents || old_serial != current_serial)) {
		zone_events_schedule_now(zone, ZONE_EVENT_NOTIFY);
	}

	if (loaded_from_journal) {
		// this enforces further load from zone file and applying ixfr from diff
		zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
	}

	return KNOT_EOK;

fail:
	zone->zonefile.exists = false;
	if (!contents_in_update) {
		zone_contents_deep_free(&contents);
	}

	/* Try to bootstrap the zone if local error. */
	replan_from_timers(conf, zone);

	if (load_from_journal && ret == KNOT_ENOENT) {
		// attempted zone-in-journal, not present = normal state
		ret = KNOT_EOK;
	}

	return ret;
}
