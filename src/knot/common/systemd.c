/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <stdlib.h>

#include "knot/common/systemd.h"
#include "contrib/ctype.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>

#define ZONE_LOAD_TIMEOUT_DEFAULT "60"

static char zone_load_timeout[40];

static const char *systemd_zone_load_timeout(void)
{
	const char *timeout = getenv("ZONE_LOAD_TIMEOUT_SEC");
	if (timeout == NULL || timeout[0] == '\0') {
		goto error;
	}
	for (const char *it = timeout; *it != '\0'; ++it) {
		if (!is_digit(*it)) {
			goto error;
		}
	}
	return timeout;
error:
	return ZONE_LOAD_TIMEOUT_DEFAULT;
}
#endif

void systemd_zone_load_timeout_notify(void)
{
#ifdef ENABLE_SYSTEMD
	if (zone_load_timeout[0] == '\0') {
		int ret = snprintf(zone_load_timeout,
		                   sizeof(zone_load_timeout),
		                   "EXTEND_TIMEOUT_USEC=%s000000",
		                   systemd_zone_load_timeout());
		if (ret < 0 || ret >= sizeof(zone_load_timeout)) {
			zone_load_timeout[0] = '\0';
		}
	}
	sd_notify(0, zone_load_timeout);
#endif
}

void systemd_tasks_status_notify(int tasks)
{
#ifdef ENABLE_SYSTEMD
	if (tasks > 0) {
		char state[64];
		int ret = snprintf(state, sizeof(state),
		                   "STATUS=Waiting for %d tasks to finish...", tasks);
		if (ret < 0 || ret >= sizeof(state)) {
			state[0] = '\0';
		}
		sd_notify(0, state);
	} else {
		sd_notify(0, "STATUS=");
	}
#endif
}

void systemd_ready_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "READY=1");
	sd_notify(0, "STATUS=");
#endif
}

void systemd_reloading_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "RELOADING=1");
	sd_notify(0, "STATUS=");
#endif
}

void systemd_stopping_notify(void)
{
#ifdef ENABLE_SYSTEMD
	sd_notify(0, "STOPPING=1");
	sd_notify(0, "STATUS=");
#endif
}
