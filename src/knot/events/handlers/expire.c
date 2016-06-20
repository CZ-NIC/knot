/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <urcu.h>

#include "contrib/trim.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/handlers.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"

int event_expire(conf_t *conf, zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	synchronize_rcu();

	/* Expire zonefile information. */
	zone->zonefile.exists = false;
	zone->flags |= ZONE_EXPIRED;
	zone_contents_deep_free(&expired);

	log_zone_info(zone->name, "zone expired");

	mem_trim();

	return KNOT_EOK;
}
