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

#include <stdlib.h>

#include "knot/common/systemd.h"
#include "contrib/strtonum.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>

#define ZONE_LOAD_TIMEOUT_EMPTY   -1
#define ZONE_LOAD_TIMEOUT_DEFAULT 60

static int zone_load_timeout_s = ZONE_LOAD_TIMEOUT_EMPTY;

static int systemd_zone_load_timeout(void)
{
	const char *timeout = getenv("KNOT_ZONE_LOAD_TIMEOUT_SEC");

	int out = ZONE_LOAD_TIMEOUT_DEFAULT;
	if (timeout != NULL && timeout[0] != '\0' &&
	    str_to_int(timeout, &out, 0, 24 * 3600) == KNOT_EOK) {
		return out;
	} else {
		return ZONE_LOAD_TIMEOUT_DEFAULT;
	}
}
#endif

void systemd_zone_load_timeout_notify(void)
{
#ifdef ENABLE_SYSTEMD
	if (zone_load_timeout_s == ZONE_LOAD_TIMEOUT_EMPTY) {
		zone_load_timeout_s = systemd_zone_load_timeout();
	}
	if (zone_load_timeout_s > 0) {
		sd_notifyf(0, "EXTEND_TIMEOUT_USEC=%d000000", zone_load_timeout_s);
	}
#endif
}

void systemd_tasks_status_notify(int tasks)
{
#ifdef ENABLE_SYSTEMD
	if (tasks > 0) {
		sd_notifyf(0, "STATUS=Waiting for %d tasks to finish...", tasks);
	} else {
		sd_notify(0, "STATUS=");
	}
#endif
}

void systemd_ready_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "READY=1\nSTATUS=");
#endif
}

void systemd_reloading_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "RELOADING=1\nSTATUS=");
#endif
}

void systemd_stopping_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "STOPPING=1\nSTATUS=");
#endif
}
