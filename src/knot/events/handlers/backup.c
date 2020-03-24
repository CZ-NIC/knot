/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/events/handlers.h"
#include "knot/zone/backup.h"

int event_backup(conf_t *conf, zone_t *zone)
{
	char *bckdir = strdup(zone->backup_ctx->backup_dir);
	if (bckdir == NULL) {
		 return KNOT_ENOMEM;
	}

	zone_backup_ctx_t *ctx = zone->backup_ctx;
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}
	bool restore = ctx->restore_mode;

	if (restore) {
		(void)event_expire(conf, zone); // always returns EOK
	}

	int ret = zone_backup(conf, zone);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone %s %s", restore ? "restored from" : "backed up to", bckdir);
	} // else logged by event system

	if (restore) {
		zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
	}

	free(bckdir);
	return ret;
}
