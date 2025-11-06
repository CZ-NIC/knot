/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <time.h>

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"

int event_flush(conf_t *conf, zone_t *zone)
{
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EEMPTYZONE;
	}

	return zone_flush_journal(conf, zone, true);
}
