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

#include "knot/common/log.h"
#include "knot/journal/journal.h"
#include "knot/journal/old_journal.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/key-events.h"
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

/*!
 * \brief If old journal exists, warn the user and append the changes to chgs
 *
 * \todo Remove in the future together with journal/old_journal.[ch] and conf_old_journalfile()
 */
static void try_old_journal(conf_t *conf, zone_t *zone, uint32_t zone_c_serial, list_t *chgs)
{
	list_t old_chgs;
	init_list(&old_chgs);

	// fetch old journal name
	char *jfile = conf_old_journalfile(conf, zone->name);
	if (jfile == NULL) {
		return;
	}

	if (!old_journal_exists(jfile)) {
		goto toj_end;
	}
	log_zone_notice(zone->name, "journal, obsolete exists, file '%s'", jfile);

	// determine serial to load from
	if (!EMPTY_LIST(*chgs)) {
		changeset_t *lastch = TAIL(*chgs);
		zone_c_serial = knot_soa_serial(&lastch->soa_to->rrs);
	}

	// load changesets from old journal
	int ret = old_journal_load_changesets(jfile, zone->name, &old_chgs,
	                                      zone_c_serial, zone_c_serial - 1);
	if (ret != KNOT_ERANGE && ret != KNOT_ENOENT && ret != KNOT_EOK) {
		log_zone_warning(zone->name, "journal, failed to load obsolete history (%s)",
		                 knot_strerror(ret));
		goto toj_end;
	}

	if (EMPTY_LIST(old_chgs)) {
		goto toj_end;
	}
	log_zone_notice(zone->name, "journal, loaded obsolete history since serial '%u'",
	                zone_c_serial);

	// store them to new journal
	ret = zone_changes_store(conf, zone, &old_chgs);
	if (ret != KNOT_EOK) {
		log_zone_warning(zone->name, "journal, failed to store obsolete history (%s)",
		                 knot_strerror(ret));
		goto toj_end;
	}

	// append them to chgs
	changeset_t *ch, *nxt;
	WALK_LIST_DELSAFE(ch, nxt, old_chgs) {
		rem_node(&ch->n);
		add_tail(chgs, &ch->n);
	}

toj_end:
	changesets_free(&old_chgs);
	free(jfile);
}

int zone_load_journal(conf_t *conf, zone_t *zone, zone_contents_t *contents)
{
	if (conf == NULL || zone == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	/* Check if journal is used (later in zone_changes_load() and zone is not empty. */
	if (zone_contents_is_empty(contents)) {
		return KNOT_EOK;
	}

	/* Fetch SOA serial. */
	uint32_t serial = zone_contents_serial(contents);

	/* Load journal */
	list_t chgs;
	init_list(&chgs);
	int ret = zone_changes_load(conf, zone, &chgs, serial);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		changesets_free(&chgs);
		return ret;
	}

	/* Load old journal (to be obsoleted) */
	try_old_journal(conf, zone, serial, &chgs);

	if (EMPTY_LIST(chgs)) {
		return KNOT_EOK;
	}

	/* Apply changesets. */
	apply_ctx_t a_ctx = { 0 };
	apply_init_ctx(&a_ctx, contents, 0);

	ret = apply_changesets_directly(&a_ctx, &chgs);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "changes from journal applied %u -> %u",
		              serial, zone_contents_serial(contents));
	} else {
		log_zone_error(zone->name, "failed to apply journal changes %u -> %u (%s)",
		               serial, zone_contents_serial(contents),
		               knot_strerror(ret));
	}

	update_cleanup(&a_ctx);
	changesets_free(&chgs);

	return ret;
}

int zone_load_from_journal(conf_t *conf, zone_t *zone, zone_contents_t **contents)
{
	if (conf == NULL || zone == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	list_t chgs;
	init_list(&chgs);
	int ret = zone_in_journal_load(conf, zone, &chgs);
	if (ret != KNOT_EOK) {
		changesets_free(&chgs);
		return ret; // include ENOENT, which is normal operation
	}

	changeset_t *boo_ch = (changeset_t *)HEAD(chgs);
	rem_node(&boo_ch->n);
	*contents = changeset_to_contents(boo_ch);

	apply_ctx_t a_ctx = { 0 };
	apply_init_ctx(&a_ctx, *contents, 0);
	ret = apply_changesets_directly(&a_ctx, &chgs);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone loaded from journal, serial %u",
		              zone_contents_serial(*contents));
	} else {
		log_zone_error(zone->name, "failed to load zone from journal (%s)",
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
		/* Perform NSEC3 resalt and ZSK rollover if needed. */
		kdnssec_ctx_t kctx = { 0 };
		ret = kdnssec_ctx_init(conf, &kctx, zone->name, NULL);
		if (ret != KNOT_EOK) {
			changeset_clear(&change);
			return ret;
		}
		// TODO consider if we shall handle return value or ignore2
		bool ignore1 = false; time_t ignore2 = 0;
		(void)knot_dnssec_nsec3resalt(&kctx, &ignore1, &ignore2);
		ignore1 = false; ignore2 = 0;
		ret = knot_dnssec_key_rollover(&kctx, zone, &ignore1, &ignore2);

		if (zone_has_key_submittion(&kctx)) {
			zone_events_schedule_now(zone, ZONE_EVENT_PARENT_DS_Q);
		}

		kdnssec_ctx_deinit(&kctx);
		if (ret != KNOT_EOK) {
			changeset_clear(&change);
			return ret;
		}

		ret = knot_dnssec_zone_sign(contents, &change, 0, dnssec_refresh);
		if (ret != KNOT_EOK) {
			changeset_clear(&change);
			return ret;
		}

		/* Apply DNSSEC changes. */
		if (!changeset_empty(&change)) {
			apply_ctx_t a_ctx = { 0 };
			apply_init_ctx(&a_ctx, contents, APPLY_STRICT);

			ret = apply_changeset_directly(&a_ctx, &change);
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
		} else if (ret != KNOT_EOK) {
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
