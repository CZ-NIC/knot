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

static bool dontcare_load_error(conf_t *conf, const zone_t *zone)
{
	return (zone->contents == NULL && zone_load_can_bootstrap(conf, zone->name));
}

int event_load(conf_t *conf, zone_t *zone)
{
	zone_contents_t *journal_conts = NULL, *zf_conts = NULL;
	bool old_contents_exist = (zone->contents != NULL);
	uint32_t old_serial = (old_contents_exist ? zone_contents_serial(zone->contents) : 0);

	conf_val_t val = conf_zone_get(conf, C_JOURNAL_CONTENT, zone->name);
	unsigned load_from = conf_opt(&val);

	unsigned zf_from = conf_zonefile_load(conf, zone->name);

	int ret = KNOT_EOK;

	// If configured, load journal contents.
	if (load_from == JOURNAL_CONTENT_ALL && !old_contents_exist && zf_from != ZONEFILE_LOAD_WHOLE) {
		ret = zone_load_from_journal(conf, zone, &journal_conts);
		if (ret != KNOT_EOK) {
			journal_conts = NULL;
		}
		old_serial = zone_contents_serial(journal_conts);
	}

	// If configured, attempt to load zonefile.
	if (zf_from != ZONEFILE_LOAD_NONE) {
		time_t mtime;
		char *filename = conf_zonefile(conf, zone->name);
		ret = zonefile_exists(filename, &mtime);
		bool zonefile_unchanged = (zone->zonefile.exists && zone->zonefile.mtime == mtime);
		free(filename);
		if (ret == KNOT_EOK) {
			ret = zone_load_contents(conf, zone->name, &zf_conts);
		}
		if (ret != KNOT_EOK) {
			zf_conts = NULL;
			if (dontcare_load_error(conf, zone)) {
				log_zone_info(zone->name, "failed to parse zonefile (%s)",
					      knot_strerror(ret));
			} else {
				log_zone_error(zone->name, "failed to parse zonefile (%s)",
					       knot_strerror(ret));
			}
			goto cleanup;
		}
		// If configured and appliable to zonefile, load journal changes.
		zone->zonefile.serial = zone_contents_serial(zf_conts);
		zone->zonefile.exists = (zf_conts != NULL);
		zone->zonefile.mtime = mtime;

		bool journal_load_configured1 = (load_from == JOURNAL_CONTENT_CHANGES);
		bool journal_load_configured2 = (load_from == JOURNAL_CONTENT_ALL);

		if ((journal_load_configured1 || journal_load_configured2) &&
		    (!old_contents_exist || zonefile_unchanged)) {
			ret = zone_load_journal(conf, zone, zf_conts);
			if (ret != KNOT_EOK) {
				zone_contents_deep_free(&zf_conts);
				log_zone_warning(zone->name, "failed to load journal (%s)",
				                 knot_strerror(ret));
			}
		}
	}

	// If configured contents=all, but not present, store zonefile.
	if (load_from == JOURNAL_CONTENT_ALL &&
	    journal_conts == NULL && zf_conts != NULL) {
		ret = zone_in_journal_store(conf, zone, zf_conts);
		if (ret != KNOT_EOK) {
			log_zone_warning(zone->name, "failed to write zone-in-journal (%s)",
			                 knot_strerror(ret));
		}
	}

	val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	zone_update_t up = { 0 };

	// Create zone_update structure according to current state.
	if (old_contents_exist) {
		if (zf_conts == NULL) {
			ret = KNOT_EOK;
			goto cleanup;
		} else if (zf_from == ZONEFILE_LOAD_WHOLE) {
			ret = zone_update_from_contents(&up, zone, zf_conts,
							(load_from == JOURNAL_CONTENT_NONE ? UPDATE_FULL : UPDATE_INCREMENTAL));
		} else {
			ret = zone_update_from_differences(&up, zone, zone->contents, zf_conts, UPDATE_INCREMENTAL);
		}
	} else {
		if (journal_conts != NULL && zf_from != ZONEFILE_LOAD_WHOLE) {
			if (zf_conts == NULL) {
				ret = zone_update_from_contents(&up, zone, journal_conts, UPDATE_INCREMENTAL);
			} else {
				ret = zone_update_from_differences(&up, zone, journal_conts, zf_conts, UPDATE_INCREMENTAL);
				if (ret == KNOT_ESEMCHECK || ret == KNOT_ERANGE) {
					log_zone_warning(zone->name, "zonefile changed with SOA serial %s, "
					                 "ignoring zonefile and loading from journal",
					                 (ret == KNOT_ESEMCHECK ? "unupdated" : "decreased"));
					zone_contents_deep_free(&zf_conts);
					ret = zone_update_from_contents(&up, zone, journal_conts, UPDATE_INCREMENTAL);
				} else {
					zone_contents_deep_free(&journal_conts);
				}
			}
		} else {
			if (zf_conts == NULL) {
				ret = KNOT_ENOENT;
			} else {
				ret = zone_update_from_contents(&up, zone, zf_conts,
				                                (load_from == JOURNAL_CONTENT_NONE ?
				                                 UPDATE_FULL : UPDATE_INCREMENTAL));
			}
		}
	}
	if (ret != KNOT_EOK) {
		switch (ret) {
		case KNOT_ENOENT:
			if (zone_load_can_bootstrap(conf, zone->name)) {
				log_zone_info(zone->name, "zone will be bootstrapped");
			} else {
				log_zone_info(zone->name, "zone not found");
			}
			break;
		case KNOT_ESEMCHECK:
			log_zone_warning(zone->name, "zone file changed without SOA serial update");
			break;
		case KNOT_ERANGE:
			log_zone_warning(zone->name, "zone file changed, but SOA serial decreased");
			break;
		}
		goto cleanup;
	}

	// The contents are already part of zone_update.
	zf_conts = NULL;
	journal_conts = NULL;

	// Sign zone using DNSSEC if configured.
	zone_sign_reschedule_t dnssec_refresh = { .allow_rollover = true, .allow_nsec3resalt = true, };
	if (dnssec_enable) {
		ret = knot_dnssec_zone_sign(&up, 0, &dnssec_refresh);
		if (ret != KNOT_EOK) {
			zone_update_clear(&up);
			goto cleanup;
		}
	}

	// Commit zone_update back to zone (including journal update, rcu,...).
	ret = zone_update_commit(conf, &up);
	zone_update_clear(&up);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}
	uint32_t new_serial = zone_contents_serial(zone->contents);

	if (old_contents_exist) {
		log_zone_info(zone->name, "loaded, serial %u -> %u",
		              old_serial, new_serial);
	} else {
		log_zone_info(zone->name, "loaded, serial %u", new_serial);
	}

	if (zone->control_update != NULL) {
		log_zone_warning(zone->name, "control transaction aborted");
		zone_control_clear(zone);
	}

	// Schedule depedent events.
	const knot_rdataset_t *soa = zone_soa(zone);
	zone->timers.soa_expire = knot_soa_expire(soa);

	if (dnssec_enable) {
		event_dnssec_reschedule(conf, zone, &dnssec_refresh, false); // false since we handle NOTIFY below
	}

	replan_from_timers(conf, zone);

	if (old_serial != new_serial) {
		zone_events_schedule_now(zone, ZONE_EVENT_NOTIFY);
	}

	return KNOT_EOK;

cleanup:
	// Try to bootstrap the zone if local error.
	replan_from_timers(conf, zone);

	zone_contents_deep_free(&zf_conts);
	zone_contents_deep_free(&journal_conts);

	return (dontcare_load_error(conf, zone) ? KNOT_EOK : ret);
}
