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
#include "knot/zone/contents.h"
#include "knot/zone/load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
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

	zone_contents_t *zone_contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (zone_contents == NULL) {
		return NULL;
	}

	return zone_contents;
}

/*!
 * \brief Apply changesets to zone from journal.
 */
int apply_journal(zone_contents_t *contents, conf_zone_t *conf)
{
	/* Check if journal is used and zone is not empty. */
	if (!journal_exists(conf->ixfr_db) || zone_contents_is_empty(contents)) {
		return KNOT_EOK;
	}

	/* Fetch SOA serial. */
	const knot_rrset_t *soa = knot_node_rrset(contents->apex, KNOT_RRTYPE_SOA);
	uint32_t serial = knot_rdata_soa_serial(soa);

	/* Load all pending changesets. */
	knot_changesets_t* chsets = knot_changesets_create();
	if (chsets == NULL) {
		return KNOT_ERROR;
	}

	/*! \todo Check what should be the upper bound. */
	int ret = journal_load_changesets(conf->ixfr_db, chsets, serial, serial - 1);
	if ((ret != KNOT_EOK && ret != KNOT_ERANGE) || EMPTY_LIST(chsets->sets)) {
		knot_changesets_free(&chsets);
		/* Absence of records is not an error. */
		if (ret == KNOT_ENOENT) {
			return KNOT_EOK;
		} else {
			return ret;
		}
	}

	/* Apply changesets. */
	log_zone_info("Applying '%zu' changesets from journal to zone '%s'.\n",
	              chsets->count, conf->name);
	ret = xfrin_apply_changesets_directly(contents, chsets->changes, chsets);
	if (ret != KNOT_EOK) {
		log_zone_error("Failed to apply changesets to '%s' - %s\n",
		               conf->name, knot_strerror(ret));
		knot_changesets_free(&chsets);
		return ret;
	}
	/* Switch zone immediately. */
	log_zone_info("Zone '%s' serial %u -> %u.\n",
	              conf->name,
	              serial, zone_contents_serial(contents));

	/* Free changesets and return. */
	xfrin_cleanup_successful_update(chsets->changes);
	knot_changesets_free(&chsets);
	return ret;
}
