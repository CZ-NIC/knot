/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "knot/common/systemd.h"
#include "contrib/strtonum.h"

#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>

#define ZONE_LOAD_TIMEOUT_DEFAULT 60

static int zone_load_timeout_s;

static int systemd_zone_load_timeout(void)
{
	const char *timeout = getenv("KNOT_ZONE_LOAD_TIMEOUT_SEC");

	int out;
	if (timeout != NULL && timeout[0] != '\0' &&
	    str_to_int(timeout, &out, 0, 24 * 3600) == KNOT_EOK) {
		return out;
	} else {
		return ZONE_LOAD_TIMEOUT_DEFAULT;
	}
}
#endif

#ifdef ENABLE_DBUS
#include <systemd/sd-bus.h>

static sd_bus *_dbus = NULL;
#endif

void systemd_zone_load_timeout_notify(void)
{
#ifdef ENABLE_SYSTEMD
	if (zone_load_timeout_s == 0) {
		zone_load_timeout_s = systemd_zone_load_timeout();
	}
	sd_notifyf(0, "EXTEND_TIMEOUT_USEC=%d000000", zone_load_timeout_s);
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

int systemd_dbus_open(void)
{
#ifdef ENABLE_DBUS
	if (_dbus != NULL) {
		return KNOT_EOK;
	}

	int ret = sd_bus_open_system(&_dbus);
	if (ret < 0) {
		return ret;
	}

	/* Take a well-known service name so that clients can find us. */
	ret = sd_bus_request_name(_dbus, KNOT_DBUS_NAME, 0);
	if (ret < 0) {
		systemd_dbus_close();
		return ret;
	}

	return KNOT_EOK;
#else
	return KNOT_ENOTSUP;
#endif
}

void systemd_dbus_close(void)
{
#ifdef ENABLE_DBUS
	_dbus = sd_bus_unref(_dbus);
#endif
}

#define emit_event(event, ...) \
	sd_bus_emit_signal(_dbus, KNOT_DBUS_PATH, KNOT_DBUS_NAME".events", \
	                   event, __VA_ARGS__)

void systemd_emit_running(bool up)
{
#ifdef ENABLE_DBUS
	emit_event(up ? KNOT_BUS_EVENT_STARTED : KNOT_BUS_EVENT_STOPPED, "");
#endif
}

void systemd_emit_zone_updated(const knot_dname_t *zone_name, uint32_t serial)
{
#ifdef ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_UPD, "su", zone_str, serial);
	}
#endif
}

void systemd_emit_zone_submission(const knot_dname_t *zone_name, uint16_t keytag,
                                  const char *keyid)
{
#ifdef ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_KSK_SUBM, "sqs", zone_str, keytag, keyid);
	}
#endif
}

void systemd_emit_zone_invalid(const knot_dname_t *zone_name)
{
#ifdef ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_INVALID, "s", zone_str);
	}
#endif
}
