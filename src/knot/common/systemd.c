/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
