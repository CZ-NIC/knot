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

#include "knot/common/log.h"
#include "knot/server/journal.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/apply.h"
#include "libknot/libknot.h"

int zone_load_contents(conf_t *conf, const knot_dname_t *zone_name,
                       zone_contents_t **contents)
{
	if (conf == NULL || zone_name == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	zloader_t zl;
	char *zonefile = conf_zonefile(conf, zone_name);
	conf_val_t val = conf_zone_get(conf, C_SEM_CHECKS, zone_name);
	int ret = zonefile_open(&zl, zonefile, zone_name, conf_bool(&val));

	err_handler_logger_t handler;
	memset(&handler, 0, sizeof(handler));
	handler._cb.cb = err_handler_logger;

	zl.err_handler = (err_handler_t *) &handler;
	free(zonefile);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Set the zone type (master/slave). If zone has no master set, we
	 * are the primary master for this zone (i.e. zone type = master).
	 */
	zl.creator->master = !zone_load_can_bootstrap(conf, zone_name);

	*contents = zonefile_load(&zl);

	zonefile_close(&zl);
	if (*contents == NULL) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int zone_load_check(conf_t *conf, zone_contents_t *contents)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	/* Bootstrapped zone, no checks apply. */
	if (contents == NULL) {
		return KNOT_EOK;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (zone_contents_is_signed(contents)) {
		if (conf->cache.srv_max_ipv4_udp_payload < KNOT_EDNS_MIN_DNSSEC_PAYLOAD) {
			log_zone_error(contents->apex->owner, "EDNS payload size "
			               "for IPv4 is lower than %u bytes for DNSSEC zone",
			               KNOT_EDNS_MIN_DNSSEC_PAYLOAD);
			return KNOT_EPAYLOAD;
		}
		if (conf->cache.srv_max_ipv6_udp_payload < KNOT_EDNS_MIN_DNSSEC_PAYLOAD) {
			log_zone_error(contents->apex->owner, "EDNS payload size "
			               "for IPv6 is lower than %u bytes for DNSSEC zone",
			               KNOT_EDNS_MIN_DNSSEC_PAYLOAD);
			return KNOT_EPAYLOAD;
		}
	}

	return KNOT_EOK;
}

int zone_load_journal(conf_t *conf, zone_t *zone, zone_contents_t *contents)
{
	if (conf == NULL || zone == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	/* Check if journal is used and zone is not empty. */
	char *journal_name = conf_journalfile(conf, zone->name);
	if (!journal_exists(journal_name) ||
	    zone_contents_is_empty(contents)) {
		free(journal_name);
		return KNOT_EOK;
	}

	/* Fetch SOA serial. */
	uint32_t serial = zone_contents_serial(contents);

	/*! \todo Check what should be the upper bound. */
	list_t chgs;
	init_list(&chgs);

	pthread_mutex_lock(&zone->journal_lock);
	int ret = journal_load_changesets(journal_name, zone, &chgs, serial,
	                                  serial - 1);
	pthread_mutex_unlock(&zone->journal_lock);
	free(journal_name);

	if ((ret != KNOT_EOK && ret != KNOT_ERANGE) || EMPTY_LIST(chgs)) {
		changesets_free(&chgs);
		/* Absence of records is not an error. */
		if (ret == KNOT_ENOENT) {
			return KNOT_EOK;
		} else {
			return ret;
		}
	}

	/* Apply changesets. */
	apply_ctx_t a_ctx = { { 0 } };
	apply_init_ctx(&a_ctx, 0);

	ret = apply_changesets_directly(&a_ctx, contents, &chgs);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "changes from journal applied %u -> %u",
		              serial, zone_contents_serial(contents));
	} else {
		log_zone_error(zone->name, "changes from journal applied %u -> %u (%s)",
		               serial, zone_contents_serial(contents),
		               knot_strerror(ret));
	}

	update_cleanup(&a_ctx);
	changesets_free(&chgs);

	return ret;
}

int zone_load_post(conf_t *conf, zone_t *zone, zone_contents_t *contents,
                   uint32_t *dnssec_refresh)
{
	if (conf == NULL || zone == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	changeset_t change;
	int ret = changeset_init(&change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Sign zone using DNSSEC (if configured). */
	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, zone->name);
	bool dnssec_enable = conf_bool(&val);
	val = conf_zone_get(conf, C_IXFR_DIFF, zone->name);
	bool build_diffs = conf_bool(&val);
	if (dnssec_enable) {
		ret = knot_dnssec_zone_sign(contents, &change, 0, dnssec_refresh);
		if (ret != KNOT_EOK) {
			changeset_clear(&change);
			return ret;
		}

		/* Apply DNSSEC changes. */
		if (!changeset_empty(&change)) {
			apply_ctx_t a_ctx = { { 0 } };
			apply_init_ctx(&a_ctx, APPLY_STRICT);

			ret = apply_changeset_directly(&a_ctx, contents, &change);
			update_cleanup(&a_ctx);
			if (ret != KNOT_EOK) {
				changeset_clear(&change);
				return ret;
			}
		} else {
			changeset_clear(&change);
		}
	}

	/* Calculate IXFR from differences (if configured or auto DNSSEC). */
	const bool contents_changed = zone->contents && (contents != zone->contents);
	if (contents_changed && (build_diffs || dnssec_enable)) {
		/* Replace changes from zone signing, the resulting diff will cover
		 * those changes as well. */
		changeset_clear(&change);
		ret = changeset_init(&change, zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = zone_contents_diff(zone->contents, contents, &change);
		if (ret == KNOT_ENODIFF) {
			log_zone_warning(zone->name, "failed to create journal "
			                 "entry, zone file changed without "
			                 "SOA serial update");
			ret = KNOT_EOK;
		} else if (ret == KNOT_ERANGE) {
			log_zone_warning(zone->name, "IXFR history will be lost, "
			                 "zone file changed, but SOA serial decreased");
			ret = KNOT_EOK;
		} else if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "failed to calculate "
			               "differences from the zone file update (%s)",
			               knot_strerror(ret));
			return ret;
		}
	}

	/* Write changes (DNSSEC, diff, or both) to journal if all went well. */
	if (!changeset_empty(&change)) {
		ret = zone_change_store(conf, zone, &change);
		if (ret == KNOT_ESPACE) {
			log_zone_error(zone->name, "journal size is too small "
			               "to fit the changes");
		} else {
			log_zone_error(zone->name, "failed to store changes into "
			               "journal (%s)", knot_strerror(ret));
		}
	}

	changeset_clear(&change);
	return ret;
}

bool zone_load_can_bootstrap(conf_t *conf, const knot_dname_t *zone_name)
{
	if (conf == NULL || zone_name == NULL) {
		return false;
	}

	conf_val_t val = conf_zone_get(conf, C_MASTER, zone_name);
	size_t count = conf_val_count(&val);

	return count > 0;
}
