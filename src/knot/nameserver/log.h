/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "contrib/sockaddr.h"
#include "knot/common/log.h"
#include "libknot/dname.h"

enum log_operation {
	LOG_OPERATION_AXFR,
	LOG_OPERATION_IXFR,
	LOG_OPERATION_NOTIFY,
	LOG_OPERATION_REFRESH,
	LOG_OPERATION_UPDATE,
	LOG_OPERATION_PARENT,
};

enum log_direction {
	LOG_DIRECTION_IN,
	LOG_DIRECTION_OUT,
};

static inline const char *log_operation_name(enum log_operation operation)
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
	case LOG_OPERATION_PARENT:
		return "parent DS check";
	default:
		return "?";
	}
}

static inline const char *log_direction_name(enum log_direction direction)
{
	switch (direction) {
	case LOG_DIRECTION_IN:
		return "incoming";
	case LOG_DIRECTION_OUT:
		return "outgoing";
	default:
		return "?";
	}
}

/*!
 * \brief Generate log message for server communication.
 *
 * If this macro was a function:
 *
 * void ns_log(int priority, const knot_dname_t *zone, enum log_operation op,
 *             enum log_direction dir, const struct sockaddr *remote,
 *             const char *fmt, ...);
 *
 * Example output:
 *
 * [example.com] NOTIFY, outgoing, 2001:db8::1@53: serial 123
 *
 */
#define ns_log(priority, zone, op, dir, remote, fmt, ...) \
	do { \
		char address[SOCKADDR_STRLEN] = ""; \
		sockaddr_tostr(address, sizeof(address), remote); \
		log_fmt_zone(priority, LOG_SOURCE_ZONE, zone, "%s, %s, %s: " fmt, \
		             log_operation_name(op), log_direction_name(dir), address, \
		             ## __VA_ARGS__); \
	} while (0)
