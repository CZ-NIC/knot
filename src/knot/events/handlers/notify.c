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

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/query.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

#define NOTIFY_LOG(priority, zone, remote, msg...) \
	ZONE_QUERY_LOG(priority, zone, remote, "NOTIFY, outgoing", msg);

int event_notify(conf_t *conf, zone_t *zone)
{
	assert(zone);

	/* Check zone contents. */
	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	/* Walk through configured remotes and send messages. */
	conf_val_t notify = conf_zone_get(conf, C_NOTIFY, zone->name);
	while (notify.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf, C_RMT, C_ADDR, &notify);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t slave = conf_remote(conf, &notify, i);
			int ret = zone_query_execute(conf, zone, KNOT_QUERY_NOTIFY, &slave);
			if (ret == KNOT_EOK) {
				NOTIFY_LOG(LOG_INFO, zone, &slave, "serial %u", zone_contents_serial(zone->contents));
				break;
			} else {
				NOTIFY_LOG(LOG_WARNING, zone, &slave, "failed (%s)", knot_strerror(ret));
			}
		}

		conf_val_next(&notify);
	}

	return KNOT_EOK;
}
