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
#include "knot/zone/backup.h"

int event_backup(conf_t *conf, zone_t *zone)
{
	char *bckdir = strdup(zone->backup_ctx->backup_dir);

	int ret = zone_backup(conf, zone);
	if (ret == KNOT_EOK) {
		log_zone_info(zone->name, "zone backed up to %s", bckdir);
	} // else logged by event system

	free(bckdir);
	return ret;
}

