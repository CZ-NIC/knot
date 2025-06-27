/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <inttypes.h>

#define RDB_OK	"OK"

typedef struct {
	uint8_t instance;
	uint8_t id;
} rdb_txn_t;

enum redis_event {
        ZONE_CREATED,
        ZONE_UPDATED,
        ZONE_PURGED,
        RRSET_UPDATED
};
