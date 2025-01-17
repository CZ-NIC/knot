/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <inttypes.h>

#define RDB_VERSION		"\x01"
#define RDB_PREFIX		"k" RDB_VERSION
#define RDB_PREFIX_LEN		(sizeof(RDB_PREFIX) - 1)

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
	RDB_EVENT_ZONE = 1,
	RDB_EVENT_UPD  = 2,
} rdb_event_t;
