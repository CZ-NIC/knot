/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <inttypes.h>

#define RDB_PARAM_DFLT_TTL	"default-ttl"
#define RDB_PARAM_EVENT_AGE	"max-event-age"

#define RDB_VERSION		"\x01"
#define RDB_PREFIX		"k" RDB_VERSION
#define RDB_PREFIX_LEN		(sizeof(RDB_PREFIX) - 1)

#define RDB_CMD_ZONE_EXISTS	"KNOT_BIN.ZONE.EXISTS"
#define RDB_CMD_ZONE_BEGIN	"KNOT_BIN.ZONE.BEGIN"
#define RDB_CMD_ZONE_STORE	"KNOT_BIN.ZONE.STORE"
#define RDB_CMD_ZONE_COMMIT	"KNOT_BIN.ZONE.COMMIT"
#define RDB_CMD_ZONE_ABORT	"KNOT_BIN.ZONE.ABORT"
#define RDB_CMD_ZONE_LOAD	"KNOT_BIN.ZONE.LOAD"
#define RDB_CMD_ZONE_PURGE	"KNOT_BIN.ZONE.PURGE"
#define RDB_CMD_ZONE_LIST	"KNOT_BIN.ZONE.LIST"
#define RDB_CMD_UPD_BEGIN	"KNOT_BIN.UPD.BEGIN"
#define RDB_CMD_UPD_ADD		"KNOT_BIN.UPD.ADD"
#define RDB_CMD_UPD_REMOVE	"KNOT_BIN.UPD.REM"
#define RDB_CMD_UPD_COMMIT	"KNOT_BIN.UPD.COMMIT"
#define RDB_CMD_UPD_ABORT	"KNOT_BIN.UPD.ABORT"
#define RDB_CMD_UPD_DIFF	"KNOT_BIN.UPD.DIFF"
#define RDB_CMD_UPD_LOAD	"KNOT_BIN.UPD.LOAD"

#define RDB_RETURN_OK		"OK"

#define RDB_EVENT_KEY		(RDB_PREFIX "\x01")
#define RDB_EVENT_ARG_EVENT	"e"
#define RDB_EVENT_ARG_ORIGIN	"o"
#define RDB_EVENT_ARG_INSTANCE	"i"
#define RDB_EVENT_ARG_SERIAL	"s"

typedef struct {
	uint8_t instance;
	uint8_t id;
} rdb_txn_t;

typedef enum {
	RDB_EVENT_ZONE  = 1,
	RDB_EVENT_UPD   = 2,
	RDB_EVENT_PURGE = 3,
} rdb_event_t;
