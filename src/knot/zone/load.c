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
int apply_journal(zone_contents_t *contents, journal_t *journal)
{
#warning "Not implemented but returns KNOT_EOK."
	return KNOT_EOK;
}
