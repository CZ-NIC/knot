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

#pragma once

#include "contrib/sockaddr.h"
#include "knot/common/log.h"
#include "libknot/dname.h"

typedef enum {
	LOG_OPERATION_AXFR,
	LOG_OPERATION_IXFR,
	LOG_OPERATION_NOTIFY,
	LOG_OPERATION_REFRESH,
	LOG_OPERATION_UPDATE,
	LOG_OPERATION_DS_CHECK,
	LOG_OPERATION_DS_PUSH,
} log_operation_t;

typedef enum {
	LOG_DIRECTION_NONE,
	LOG_DIRECTION_IN,
	LOG_DIRECTION_OUT,
} log_direction_t;

static inline const char *log_operation_name(log_operation_t operation)
{
	switch (operation) {
	case LOG_OPERATION_AXFR:
		return "AXFR";
	case LOG_OPERATION_IXFR:
		return "IXFR";
	case LOG_OPERATION_NOTIFY:
		return "notify";
	case LOG_OPERATION_REFRESH:
		return "refresh";
	case LOG_OPERATION_UPDATE:
		return "DDNS";
	case LOG_OPERATION_DS_CHECK:
		return "DS check";
	case LOG_OPERATION_DS_PUSH:
		return "DS push";
	default:
		return "?";
	}
}

static inline const char *log_direction_name(log_direction_t direction)
{
	switch (direction) {
	case LOG_DIRECTION_IN:
		return ", incoming";
	case LOG_DIRECTION_OUT:
		return ", outgoing";
	case LOG_DIRECTION_NONE:
	default:
		return "";
	}
}

/*!
 * \brief Generate log message for server communication.
 *
 * Example output:
 *
 * [example.com] NOTIFY, outgoing, remote 2001:db8::1@53, serial 123
 */
#define ns_log(priority, zone, op, dir, remote, pool, fmt, ...) \
	do { \
		char address[SOCKADDR_STRLEN] = ""; \
		sockaddr_tostr(address, sizeof(address), (const struct sockaddr_storage *)remote); \
		log_fmt_zone(priority, LOG_SOURCE_ZONE, zone, NULL, "%s%s, remote %s%s, " fmt, \
		             log_operation_name(op), log_direction_name(dir), address, \
		             (pool) ? " pool" : "", ## __VA_ARGS__); \
	} while (0)
