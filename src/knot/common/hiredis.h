/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Extension of Hiredis to support GnuTLS backend.
 */

#pragma once

#include <hiredis/hiredis.h>

#include "knot/conf/conf.h"

int rdb_addr_to_str(struct sockaddr_storage *addr, char *out, size_t out_len, int *port);

redisContext *rdb_connect(conf_t *conf, bool require_master);

void rdb_disconnect(redisContext *rdb, bool pool_save);

bool rdb_compatible(redisContext *rdb);
