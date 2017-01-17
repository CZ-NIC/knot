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
#include <time.h>

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"

int event_flush(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	int ret = zone_flush_journal(conf, zone);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone->timers.last_flush = time(NULL);

	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout > 0) {
		time_t next_flush = zone->timers.last_flush + sync_timeout;
		zone_events_schedule_at(zone, ZONE_EVENT_FLUSH, next_flush);
	}

	return KNOT_EOK;
}
