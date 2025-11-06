/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/zone/zone.h"

int event_expire(conf_t *conf, zone_t *zone)
{
	zone_perform_expire(conf, zone);

	return KNOT_EOK;
}
