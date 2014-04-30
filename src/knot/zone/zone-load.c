/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "common/log.h"
#include "knot/server/journal.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/xfr-in.h"
#include "libknot/rdata.h"

zone_contents_t *zone_load_contents(conf_zone_t *conf)
{
	assert(conf);

	zloader_t zl;
	int ret = zonefile_open(&zl, conf->file, conf->name, conf->enable_checks);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = !zone_load_can_bootstrap(conf);

	zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (zone_contents == NULL) {
		return NULL;
	}

	return zone_contents;
}

/*! \brief Check zone configuration constraints. */
int zone_load_check(zone_contents_t *contents, conf_zone_t *zone_config)
{
	/* Bootstrapped zone, no checks apply. */
	if (contents == NULL) {
		return KNOT_EOK;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (zone_contents_is_signed(contents)) {
		unsigned edns_dnssec_min = EDNS_MIN_DNSSEC_PAYLOAD;
		if (conf()->max_udp_payload < edns_dnssec_min) {
			log_zone_warning("EDNS payload lower than %uB for "
			                 "DNSSEC-enabled zone '%s'.\n",
			                 edns_dnssec_min, zone_config->name);
		}
	}

	/* Check NSEC3PARAM state if present. */
	int result = zone_contents_load_nsec3param(contents);
	if (result != KNOT_EOK) {
		log_zone_error("NSEC3 signed zone has invalid or no "
			       "NSEC3PARAM record.\n");
		return result;
	}

	return KNOT_EOK;
}

/*!
 * \brief Apply changesets to zone from journal.
 */
int zone_load_journal(zone_contents_t *contents, conf_zone_t *conf)
{
	/* Check if journal is used and zone is not empty. */
	if (!journal_exists(conf->ixfr_db) || zone_contents_is_empty(contents)) {
		return KNOT_EOK;
	}

	/* Fetch SOA serial. */
	uint32_t serial = zone_contents_serial(contents);

	/* Load all pending changesets. */
	knot_changesets_t* chsets = knot_changesets_create(0);
	if (chsets == NULL) {
		return KNOT_ERROR;
	}

	/*! \todo Check what should be the upper bound. */
	int ret = journal_load_changesets(conf->ixfr_db, chsets, serial, serial - 1);
	if ((ret != KNOT_EOK && ret != KNOT_ERANGE) || EMPTY_LIST(chsets->sets)) {
		knot_changesets_free(&chsets, NULL);
		/* Absence of records is not an error. */
		if (ret == KNOT_ENOENT) {
			return KNOT_EOK;
		} else {
			return ret;
		}
	}

	/* Apply changesets. */
	ret = xfrin_apply_changesets_directly(contents,  chsets);
	log_zone_info("Zone '%s' serial %u -> %u: %s\n",
	              conf->name,
	              serial, zone_contents_serial(contents),
	              knot_strerror(ret));

	knot_changesets_free(&chsets, NULL);
	return ret;
}

int zone_load_post(zone_contents_t *new_contents, zone_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	const conf_zone_t *conf = zone->conf;
	knot_changeset_t  *change = NULL;
	knot_changesets_t *chset = knot_changesets_create(0);
	if (chset == NULL) {
		return KNOT_ENOMEM;
	}

	/* Sign zone using DNSSEC (if configured). */
	if (conf->dnssec_enable) {
		change = zone_change_prepare(chset);
		if (change == NULL) {
			knot_changesets_free(&chset, NULL);
			return KNOT_ENOMEM;
		}

		ret = knot_dnssec_zone_sign(new_contents, conf, change,
		                            KNOT_SOA_SERIAL_UPDATE,
		                            &zone->dnssec.refresh_at);
	}

	/* Calculate IXFR from differences (if configured). */
	bool contents_changed = zone->contents && (new_contents != zone->contents);
	if (ret == KNOT_EOK && contents_changed && conf->build_diffs) {

		/* Commit existing zone change and prepare new. */
		int ret = zone_change_commit(new_contents, chset);
		if (ret != KNOT_EOK) {
			knot_changesets_free(&chset, NULL);
			return ret;
		} else {
			knot_changesets_clear(chset, NULL);
			change = zone_change_prepare(chset);
			if (change == NULL) {
				knot_changesets_free(&chset, NULL);
				return KNOT_ENOMEM;
			}
		}

		ret = zone_contents_create_diff(zone->contents, new_contents, change);
		if (ret == KNOT_ENODIFF) {
			log_zone_warning("Zone %s: Zone file changed, "
			                 "but serial didn't - won't "
			                 "create journal entry.\n",
			                 conf->name);
		} else if (ret != KNOT_EOK) {
			log_zone_error("Zone %s: Failed to calculate "
			               "differences from the zone "
			               "file update: %s\n",
			               conf->name, knot_strerror(ret));
		}
	}

	/* Now commit current change. */
	if (ret == KNOT_EOK) {
		ret = zone_change_commit(new_contents, chset);
		if (ret != KNOT_EOK) {
			knot_changesets_free(&chset, NULL);
			return ret;
		}

		/* Write changes to journal if all went well. */
		ret = zone_change_store(zone, chset);
	}

	/* Free changesets and return. */
	knot_changesets_free(&chset, NULL);
	return ret;
}

bool zone_load_can_bootstrap(const conf_zone_t *conf)
{
	return conf && !EMPTY_LIST(conf->acl.xfr_in);
}

