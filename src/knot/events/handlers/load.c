/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/catalog/generate.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/zone-events.h"
#include "knot/events/handlers.h"
#include "knot/events/replan.h"
#include "knot/zone/digest.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/updates/acl.h"

static bool dontcare_load_error(conf_t *conf, const zone_t *zone)
{
	return (zone->contents == NULL && zone_load_can_bootstrap(conf, zone->name));
}

static bool allowed_xfr(conf_t *conf, const zone_t *zone)
{
	conf_val_t acl = conf_zone_get(conf, C_ACL, zone->name);
	while (acl.code == KNOT_EOK) {
		conf_val_t action = conf_id_get(conf, C_ACL, C_ACTION, &acl);
		while (action.code == KNOT_EOK) {
			if (conf_opt(&action) == ACL_ACTION_TRANSFER) {
				return true;
			}
			conf_val_next(&action);
		}
		conf_val_next(&acl);
	}

	return false;
}

int event_load(conf_t *conf, zone_t *zone)
{
	zone_update_t up = { 0 };
	zone_contents_t *journal_conts = NULL, *zf_conts = NULL;
	bool old_contents_exist = (zone->contents != NULL), zone_in_journal_exists = false;

	conf_val_t val = conf_zone_get(conf, C_JOURNAL_CONTENT, zone->name);
	unsigned load_from = conf_opt(&val);

	val = conf_zone_get(conf, C_ZONEFILE_LOAD, zone->name);
	unsigned zf_from = conf_opt(&val);

	int ret = KNOT_EOK;

	// If configured, load journal contents.
	if (!old_contents_exist &&
	    ((load_from == JOURNAL_CONTENT_ALL && zf_from != ZONEFILE_LOAD_WHOLE) ||
	     zone->cat_members != NULL)) {
		ret = zone_load_from_journal(conf, zone, &journal_conts);
		switch (ret) {
		case KNOT_EOK:
			zone_in_journal_exists = true;
			break;
		case KNOT_ENOENT:
			zone_in_journal_exists = false;
			break;
		default:
			goto cleanup;
		}
	} else {
		zone_in_journal_exists = zone_journal_has_zij(zone);
	}

	// If configured, attempt to load zonefile.
	if (zf_from != ZONEFILE_LOAD_NONE && zone->cat_members == NULL) {
		struct timespec mtime;
		char *filename = conf_zonefile(conf, zone->name);
		ret = zonefile_exists(filename, &mtime);
		if (ret == KNOT_EOK) {
			ret = zone_load_contents(conf, zone->name, &zf_conts, false);
		}
		if (ret != KNOT_EOK) {
			zf_conts = NULL;
			if (dontcare_load_error(conf, zone)) {
				log_zone_info(zone->name, "failed to parse zone file '%s' (%s)",
				              filename, knot_strerror(ret));
			} else {
				log_zone_error(zone->name, "failed to parse zone file '%s' (%s)",
				               filename, knot_strerror(ret));
			}
			free(filename);
			goto load_end;
		}
		free(filename);

		// Save zonefile information.
		zone->zonefile.serial = zone_contents_serial(zf_conts);
		zone->zonefile.exists = (zf_conts != NULL);
		zone->zonefile.mtime = mtime;

		// If configured and possible, fix the SOA serial of zonefile.
		zone_contents_t *relevant = (zone->contents != NULL ? zone->contents : journal_conts);
		if (zf_conts != NULL && zf_from == ZONEFILE_LOAD_DIFSE && relevant != NULL) {
			uint32_t serial = zone_contents_serial(relevant);
			conf_val_t policy = conf_zone_get(conf, C_SERIAL_POLICY, zone->name);
			uint32_t set = serial_next(serial, conf_opt(&policy), 1);
			zone_contents_set_soa_serial(zf_conts, set);
			log_zone_info(zone->name, "zone file parsed, serial corrected %u -> %u",
			              zone->zonefile.serial, set);
			zone->zonefile.serial = set;
		} else {
			log_zone_info(zone->name, "zone file parsed, serial %u",
			              zone->zonefile.serial);
		}

		// If configured and appliable to zonefile, load journal changes.
		if (load_from != JOURNAL_CONTENT_NONE) {
			ret = zone_load_journal(conf, zone, zf_conts);
			if (ret != KNOT_EOK) {
				zone_contents_deep_free(zf_conts);
				zf_conts = NULL;
				log_zone_warning(zone->name, "failed to load journal (%s)",
				                 knot_strerror(ret));
			}
		}
	}
	if (zone->cat_members != NULL && !old_contents_exist) {
		uint32_t serial = journal_conts == NULL ? 1 : zone_contents_serial(journal_conts);
		serial = serial_next(serial, SERIAL_POLICY_UNIXTIME, 1); // unixtime hardcoded
		zf_conts = catalog_update_to_zone(zone->cat_members, zone->name, serial);
		if (zf_conts == NULL) {
			ret = zone->cat_members->error == KNOT_EOK ? KNOT_ENOMEM : zone->cat_members->error;
			goto cleanup;
		}
	}

	// If configured contents=all, but not present, store zonefile.
	if ((load_from == JOURNAL_CONTENT_ALL || zone->cat_members != NULL) &&
	    !zone_in_journal_exists && (zf_conts != NULL || old_contents_exist)) {
		zone_contents_t *store_c = old_contents_exist ? zone->contents : zf_conts;
		ret = zone_in_journal_store(conf, zone, store_c);
		if (ret != KNOT_EOK) {
			log_zone_warning(zone->name, "failed to write zone-in-journal (%s)",
			                 knot_strerror(ret));
		} else {
			zone_in_journal_exists = true;
		}
	}

	val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = (conf_bool(&val) && zone->cat_members == NULL), zu_from_zf_conts = false;
	bool do_diff = (zf_from == ZONEFILE_LOAD_DIFF || zf_from == ZONEFILE_LOAD_DIFSE || zone->cat_members != NULL);
	bool ignore_dnssec = (do_diff && dnssec_enable);

	// Create zone_update structure according to current state.
	if (old_contents_exist) {
		if (zone->cat_members != NULL) {
			ret = zone_update_init(&up, zone, UPDATE_INCREMENTAL);
			if (ret == KNOT_EOK) {
				ret = catalog_update_to_update(zone->cat_members, &up);
			}
			if (ret == KNOT_EOK) {
				ret = zone_update_increment_soa(&up, conf);
			}
		} else if (zf_conts == NULL) {
			// nothing to be re-loaded
			ret = KNOT_EOK;
			goto cleanup;
		} else if (zf_from == ZONEFILE_LOAD_WHOLE) {
			// throw old zone contents and load new from ZF
			ret = zone_update_from_contents(&up, zone, zf_conts,
			                                (load_from == JOURNAL_CONTENT_NONE ?
			                                 UPDATE_FULL : UPDATE_HYBRID));
			zu_from_zf_conts = true;
		} else {
			// compute ZF diff and if success, apply it
			ret = zone_update_from_differences(&up, zone, NULL, zf_conts, UPDATE_INCREMENTAL, ignore_dnssec);
		}
	} else {
		if (journal_conts != NULL && (zf_from != ZONEFILE_LOAD_WHOLE || zone->cat_members != NULL)) {
			if (zf_conts == NULL) {
				// load zone-in-journal
				ret = zone_update_from_contents(&up, zone, journal_conts, UPDATE_HYBRID);
			} else {
				// load zone-in-journal, compute ZF diff and if success, apply it
				ret = zone_update_from_differences(&up, zone, journal_conts, zf_conts,
				                                   UPDATE_HYBRID, ignore_dnssec);
				if (ret == KNOT_ESEMCHECK || ret == KNOT_ERANGE) {
					log_zone_warning(zone->name,
					                 "zone file changed with SOA serial %s, "
					                 "ignoring zone file and loading from journal",
					                 (ret == KNOT_ESEMCHECK ? "unupdated" : "decreased"));
					zone_contents_deep_free(zf_conts);
					zf_conts = NULL;
					ret = zone_update_from_contents(&up, zone, journal_conts, UPDATE_HYBRID);
				}
			}
		} else {
			if (zf_conts == NULL) {
				// nothing to be loaded
				ret = KNOT_ENOENT;
			} else {
				// load from ZF
				ret = zone_update_from_contents(&up, zone, zf_conts,
				                                (load_from == JOURNAL_CONTENT_NONE ?
				                                 UPDATE_FULL : UPDATE_HYBRID));
				if (zf_from == ZONEFILE_LOAD_WHOLE) {
					zu_from_zf_conts = true;
				}
			}
		}
	}

load_end:
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
			if (serial_compare(zone->zonefile.serial, zone_contents_serial(zone->contents)) == SERIAL_INCOMPARABLE) {
				log_zone_warning(zone->name, "zone file changed with incomparable SOA serial");
			} else {
				log_zone_warning(zone->name, "zone file changed with decreased SOA serial");
			}
			break;
		}
		goto cleanup;
	}

	bool zf_serial_updated = (zf_conts != NULL && zone_contents_serial(zf_conts) != zone_contents_serial(zone->contents));

	// The contents are already part of zone_update.
	zf_conts = NULL;
	journal_conts = NULL;

	ret = zone_update_verify_digest(conf, &up);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	uint32_t middle_serial = zone_contents_serial(up.new_cont);

	if (do_diff && old_contents_exist && dnssec_enable && zf_serial_updated &&
	    !zone_in_journal_exists) {
		ret = zone_update_start_extra(&up, conf);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
	}

	val = conf_zone_get(conf, C_ZONEMD_GENERATE, zone->name);
	unsigned digest_alg = conf_opt(&val);

	// Sign zone using DNSSEC if configured.
	zone_sign_reschedule_t dnssec_refresh = { 0 };
	if (dnssec_enable) {
		ret = knot_dnssec_zone_sign(&up, conf, 0, KEY_ROLL_ALLOW_ALL, 0, &dnssec_refresh);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
		if (zu_from_zf_conts && (up.flags & UPDATE_HYBRID) && allowed_xfr(conf, zone)) {
			log_zone_warning(zone->name,
			                 "with automatic DNSSEC signing and outgoing transfers enabled, "
			                 "'zonefile-load: difference' should be set to avoid malformed "
			                 "IXFR after manual zone file update");
		}
	} else if (digest_alg != ZONE_DIGEST_NONE) {
		if (zone_update_to(&up) == NULL || middle_serial == zone->zonefile.serial) {
			ret = zone_update_increment_soa(&up, conf);
		}
		if (ret == KNOT_EOK) {
			ret = zone_update_add_digest(&up, digest_alg, false);
		}
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
	}

	// If the change is only automatically incremented SOA serial, make it no change.
	if ((zf_from == ZONEFILE_LOAD_DIFSE || zone->cat_members != NULL) &&
	    (up.flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) &&
	    changeset_differs_just_serial(&up.change)) {
		changeset_t *cpy = changeset_clone(&up.change);
		if (cpy == NULL) {
			ret = KNOT_ENOMEM;
			goto cleanup;
		}
		ret = zone_update_apply_changeset_reverse(&up, cpy);
		changeset_free(cpy);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
	}

	uint32_t old_serial = 0, new_serial = zone_contents_serial(up.new_cont);
	char old_serial_str[11] = "none", new_serial_str[15] = "";
	if (old_contents_exist) {
		old_serial = zone_contents_serial(zone->contents);
		(void)snprintf(old_serial_str, sizeof(old_serial_str), "%u", old_serial);
	}
	if (new_serial != middle_serial) {
		(void)snprintf(new_serial_str, sizeof(new_serial_str), " -> %u", new_serial);
	}

	// Commit zone_update back to zone (including journal update, rcu,...).
	ret = zone_update_commit(conf, &up);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	log_zone_info(zone->name, "loaded, serial %s -> %u%s, %zu bytes",
	              old_serial_str, middle_serial, new_serial_str, zone->contents->size);

	if (zone->cat_members != NULL) {
		catalog_update_clear(zone->cat_members);
	}

	// Schedule dependent events.
	if (dnssec_enable) {
		event_dnssec_reschedule(conf, zone, &dnssec_refresh, false); // false since we handle NOTIFY below
	}

	replan_from_timers(conf, zone);

	if (!zone_timers_serial_notified(&zone->timers, new_serial)) {
		zone_schedule_notify(zone, 0);
	}

	return KNOT_EOK;

cleanup:
	// Try to bootstrap the zone if local error.
	replan_from_timers(conf, zone);

	zone_update_clear(&up);
	zone_contents_deep_free(zf_conts);
	zone_contents_deep_free(journal_conts);

	return (dontcare_load_error(conf, zone) ? KNOT_EOK : ret);
}
