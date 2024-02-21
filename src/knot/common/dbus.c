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

#include <stdarg.h>

#include "knot/common/dbus.h"
#include "knot/common/log.h"

#define ENABLE_DBUS (ENABLE_DBUS_SYSTEMD | ENABLE_DBUS_LIBDBUS)

#if defined(ENABLE_DBUS_SYSTEMD)

#include <systemd/sd-bus.h>
#define VALUE_OF(x) (x)
typedef sd_bus * dbus_ctx_t;

#elif defined(ENABLE_DBUS_LIBDBUS)

#include <assert.h>
#include <dbus/dbus.h>
#define VALUE_OF(x) (&(x))
typedef DBusConnection * dbus_ctx_t;

#else

typedef struct {} * dbus_ctx_t; // Dummy

#endif // ENABLE_DBUS_LIBDBUS

static dbus_ctx_t _dbus = NULL;

int dbus_open(void)
{
	if (_dbus != NULL) {
		return KNOT_EOK;
	}
#if defined(ENABLE_DBUS_SYSTEMD)
	int ret = sd_bus_open_system(&_dbus);
	if (ret < 0) {
		goto error_systemd;
	}

	/* Take a well-known service name so that clients can find us. */
	ret = sd_bus_request_name(_dbus, KNOT_DBUS_NAME, 0);
	if (ret < 0) {
		goto error_systemd;
	}

	log_info("d-bus: connected to system bus");
	return KNOT_EOK;
error_systemd:
	log_error("d-bus: failed to open system bus (%s)", knot_strerror(ret));
	dbus_close();
	return ret;
#elif defined(ENABLE_DBUS_LIBDBUS)
	DBusError err;
	dbus_error_init(&err);

	_dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err) == TRUE) {
		goto error_libdbus;
	}

	/* Take a well-known service name so that clients can find us. */
	dbus_bus_request_name(_dbus, KNOT_DBUS_NAME, 0, &err);
	if (dbus_error_is_set(&err) == TRUE) {
		goto error_libdbus;
	}

	dbus_error_free(&err);
	log_info("d-bus: connected to system bus");
	return KNOT_EOK;
error_libdbus:
	log_error("d-bus: failed to open system bus (%s)", err.message);
	dbus_error_free(&err);
	dbus_close();
	return KNOT_ERROR;
#endif
	log_error("d-bus: not supported");
	return KNOT_ENOTSUP;
}

void dbus_close(void)
{
	if (_dbus == NULL) {
		return;
	}
#if defined(ENABLE_DBUS_SYSTEMD)
	_dbus = sd_bus_unref(_dbus);
#elif defined(ENABLE_DBUS_LIBDBUS)
	dbus_connection_unref(_dbus);
	_dbus = NULL;
#endif // ENABLE_DBUS_LIBDBUS
}

#if ENABLE_DBUS
static void emit_event(const char *event, char *first_arg_type, ...)
{
	int ret = KNOT_ENOENT;
	if (_dbus == NULL) {
		goto failed;
	}

#if defined(ENABLE_DBUS_SYSTEMD)
	sd_bus_message *msg = NULL;
	ret = sd_bus_message_new_signal(_dbus, &msg, KNOT_DBUS_PATH,
	                                KNOT_DBUS_NAME".events", event);
	if (ret < 0) {
		goto failed;
	}

	va_list args;
	va_start(args, first_arg_type);
	ret = sd_bus_message_appendv(msg, first_arg_type, args);
	if (ret < 0) {
		sd_bus_message_unref(msg);
		va_end(args);
		goto failed;
	}
	/*
	 * \note sd_bus_message_send(msg) or even sd_bus_emit_signalv() can
	 *       be used with a newer systemd.
	 */
	ret = sd_bus_send(sd_bus_message_get_bus(msg), msg, NULL);
	if (ret < 0) {
		sd_bus_message_unref(msg);
		va_end(args);
		goto failed;
	}
	va_end(args);
#elif defined(ENABLE_DBUS_LIBDBUS)
	DBusMessage *msg = NULL;
	msg = dbus_message_new_signal(KNOT_DBUS_PATH, KNOT_DBUS_NAME".events",
	                              event);
	if (msg == NULL) {
		ret = KNOT_ENOMEM;
		goto failed;
	}

	/*
	 * \note This loop considers only basic data types; composite ones,
	 *       such as arrays, result in undefined behavior.
	 */
	va_list args;
	va_start(args, first_arg_type);
	for (const char *type = first_arg_type; *type; ++type) {
		dbus_bool_t bret = dbus_message_append_args(msg, *type,
		                                            va_arg(args, void *),
		                                            DBUS_TYPE_INVALID);
		if (bret == FALSE) {
			dbus_message_unref(msg);
			va_end(args);
			assert(0); // Read note
			ret = KNOT_EINVAL;
			goto failed;
		}
	}

	if (dbus_connection_send(_dbus, msg, NULL) == 0) {
		dbus_message_unref(msg);
		va_end(args);
		ret = KNOT_NET_ESEND;
		goto failed;
	}
	dbus_message_unref(msg);
	va_end(args);
#endif // ENABLE_DBUS_LIBDBUS
	return;
failed:
	log_error("d-bus: failed to emit signal '%s' (%s)", event, knot_strerror(ret));
}
#endif // ENABLE_DBUS

void dbus_emit_running(bool up)
{
#if ENABLE_DBUS
	emit_event(up ? KNOT_BUS_EVENT_STARTED : KNOT_BUS_EVENT_STOPPED, "");
#endif // ENABLE_DBUS
}

void dbus_emit_zone_updated(const knot_dname_t *zone_name, uint32_t serial)
{
#if ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_UPD, "su", VALUE_OF(zone_str),
		           VALUE_OF(serial));
	}
#endif // ENABLE_DBUS
}

void dbus_emit_keys_updated(const knot_dname_t *zone_name)
{
#if ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_KEYS_UPD, "s",
		           VALUE_OF(zone_str));
	}
#endif // ENABLE_DBUS
}

void dbus_emit_zone_submission(const knot_dname_t *zone_name, uint16_t keytag,
                               const char *keyid)
{
#if ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_KSK_SUBM, "sqs",
		           VALUE_OF(zone_str), VALUE_OF(keytag),
		           VALUE_OF(keyid));
	}
#endif // ENABLE_DBUS
}

void dbus_emit_zone_invalid(const knot_dname_t *zone_name, uint32_t remaining_secs)
{
#if ENABLE_DBUS
	knot_dname_txt_storage_t buff;
	char *zone_str = knot_dname_to_str(buff, zone_name, sizeof(buff));
	if (zone_str != NULL) {
		emit_event(KNOT_BUS_EVENT_ZONE_INVALID, "su",
		           VALUE_OF(zone_str),
		           VALUE_OF(remaining_secs));
	}
#endif // ENABLE_DBUS
}
