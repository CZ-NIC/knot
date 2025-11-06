/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/zone/zone.h"

int event_purge(conf_t *conf, zone_t *zone)
{
	purge_flag_t what = (purge_flag_t)zone_get_flag(zone, (zone_flag_t)PURGE_ZONE_FLAGS, true);

	if (what & PURGE_ZONE_EXPIRE) {
		zone_perform_expire(conf, zone);
	}

	return selective_zone_purge(conf, zone, what);
}
