/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
	LOG_OPERATION_DNSKEY_SYNC,
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
	case LOG_OPERATION_DNSKEY_SYNC:
		return "DNSKEY sync";
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

static inline const char *log_conn_info(knotd_query_proto_t proto, bool pool)
{
	switch (proto) {
	case KNOTD_QUERY_PROTO_TCP:
		return pool ? " TCP/pool" : " TCP";
	case KNOTD_QUERY_PROTO_QUIC:
		return pool ? " QUIC/0-RTT" : " QUIC";
	case KNOTD_QUERY_PROTO_TLS:
		return pool ? " TLS/0-RTT" : " TLS";
	default:
		return "";
	}
}

/*!
 * \brief Generate log message for server communication.
 */
#define ns_log(priority, zone, op, dir, remote, proto, pool, key, fmt, ...) \
	do { \
		knot_dname_txt_storage_t key_str; \
		char address[SOCKADDR_STRLEN] = ""; \
		sockaddr_tostr(address, sizeof(address), remote); \
		(void)knot_dname_to_str(key_str, key, sizeof(key_str)); \
		log_fmt_zone(priority, LOG_SOURCE_ZONE, zone, NULL, "%s%s, remote %s%s, %s%s%s" fmt, \
		             log_operation_name(op), log_direction_name(dir), address, \
		             log_conn_info(proto, pool), (key != NULL ? "key " : ""), \
		             (key != NULL ? key_str : ""), (key != NULL ? ", " : ""), \
		             ## __VA_ARGS__); \
	} while (0)
