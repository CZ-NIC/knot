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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "knot/common/log.h"
#include "knot/journal/journal.h"
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

	char *zonefile = conf_zonefile(conf, zone_name);
	conf_val_t val = conf_zone_get(conf, C_SEM_CHECKS, zone_name);

	zloader_t zl;
	int ret = zonefile_open(&zl, zonefile, zone_name, conf_bool(&val), time(NULL));
	free(zonefile);
	if (ret != KNOT_EOK) {
		return ret;
	}

	sem_handler_t handler = {
		.cb = err_handler_logger
	};

	zl.err_handler = &handler;
	zl.creator->master = !zone_load_can_bootstrap(conf, zone_name);

	*contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (*contents == NULL) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
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
	if (EMPTY_LIST(chgs)) {
		return KNOT_EOK;
	}

	/* Apply changesets. */
	apply_ctx_t a_ctx = { 0 };
	ret = apply_init_ctx(&a_ctx, contents, 0);
	if (ret != KNOT_EOK) {
		changesets_free(&chgs);
		return ret;
	}

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
	ret = changeset_to_contents(boo_ch, contents);
	if (ret != KNOT_EOK) {
		changesets_free(&chgs);
		return ret;
	}

	apply_ctx_t a_ctx = { 0 };
	ret = apply_init_ctx(&a_ctx, *contents, 0);
	if (ret != KNOT_EOK) {
		changesets_free(&chgs);
		return ret;
	}

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

bool zone_load_can_bootstrap(conf_t *conf, const knot_dname_t *zone_name)
{
	if (conf == NULL || zone_name == NULL) {
		return false;
	}

	conf_val_t val = conf_zone_get(conf, C_MASTER, zone_name);
	size_t count = conf_val_count(&val);

	return count > 0;
}
