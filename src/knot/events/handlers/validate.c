/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
