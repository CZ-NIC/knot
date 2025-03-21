/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/zone-events.h"
#include "knot/zone/zone.h"

int event_validate(conf_t *conf, zone_t *zone)
{
	knot_time_t now = knot_time();
	zone_update_t fake_upd = {
		.zone = zone,
		.new_cont = zone->contents,
		// .validation_hint is zeroed
	};

	log_zone_info(zone->name, "DNSSEC, re-validating zone fully");

	return knot_dnssec_validate_zone(&fake_upd, conf, now, false, true);
}
