/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/journal/journal_metadata.h"
#include "knot/journal/journal_read.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/zone-events.h"
#include "libknot/libknot.h"

int zone_load_contents(conf_t *conf, const knot_dname_t *zone_name,
                       zone_contents_t **contents, semcheck_optional_t semcheck_mode,
                       bool fail_on_warning)
{
	if (conf == NULL || zone_name == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	char *zonefile = conf_zonefile(conf, zone_name);

	zloader_t zl;
	int ret = zonefile_open(&zl, zonefile, zone_name, semcheck_mode, time(NULL));
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
	if (handler.warning && fail_on_warning) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}

static int apply_one_cb(bool remove, const knot_rrset_t *rr, void *ctx)
{
	zone_node_t *unused = NULL;
	zone_contents_t *contents = ctx;
	int ret = remove ? zone_contents_remove_rr(contents, rr, &unused)
	                 : zone_contents_add_rr(contents, rr, &unused);
	if (ret == KNOT_ENOENT && remove && knot_rrtype_is_dnssec(rr->type)) {
		// Compatibility with imperfect journal contents (versions < 2.9) if
		// 'zonefile-load: difference' and 'dnssec-signing: on`.
		// Journal history can contain a changeset with removed DNSSEC records
		// which are not present in the zonefile.
		return KNOT_EOK;
	} else {
		return ret;
	}
}

int zone_load_journal(conf_t *conf, zone_t *zone, zone_contents_t *contents)
{
	if (conf == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	// Check if journal is used (later in zone_changes_load() and zone is not empty.
	if (zone_contents_is_empty(contents)) {
		return KNOT_EOK;
	}
	uint32_t serial = zone_contents_serial(contents);

	journal_read_t *read = NULL;
	int ret = journal_read_begin(zone_journal(zone), false, serial, &read);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		return KNOT_EOK;
	default:
		return ret;
	}

	ret = journal_read_rrsets(read, apply_one_cb, contents);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "changes from journal applied, serial %u -> %u",
		              serial, zone_contents_serial(contents));
	} else {
		log_zone_error(zone->name, "failed to apply journal changes, serial %u -> %u (%s)",
		               serial, zone_contents_serial(contents),
		               knot_strerror(ret));
	}

	return ret;
}

int zone_load_from_journal(conf_t *conf, zone_t *zone, zone_contents_t **contents)
{
	if (conf == NULL || zone == NULL || contents == NULL) {
		return KNOT_EINVAL;
	}

	*contents = zone_contents_new(zone->name, true);
	if (*contents == NULL) {
		return KNOT_ENOMEM;
	}

	journal_read_t *read = NULL;
	int ret = journal_read_begin(zone_journal(zone), true, 0, &read);
	if (ret == KNOT_ENOENT) {
		zone_contents_deep_free(*contents);
		*contents = NULL;
		return ret;
	}

	knot_rrset_t rr = { 0 };
	while (ret == KNOT_EOK && journal_read_rrset(read, &rr, false)) {
		zone_node_t *unused = NULL;
		ret = zone_contents_add_rr(*contents, &rr, &unused);
		journal_read_clear_rrset(&rr);
	}

	if (ret == KNOT_EOK) {
		ret = journal_read_rrsets(read, apply_one_cb, *contents);
	} else {
		journal_read_end(read);
	}

	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone loaded from journal, serial %u",
		              zone_contents_serial(*contents));
	} else {
		log_zone_error(zone->name, "failed to load zone from journal, serial %u (%s)",
		               zone_contents_serial(*contents), knot_strerror(ret));
		zone_contents_deep_free(*contents);
		*contents = NULL;
	}

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
