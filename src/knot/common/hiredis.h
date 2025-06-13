/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Extension of hiredis to support GnuTLS backend.
 */

#pragma once

#include <hiredis/hiredis.h>

#include "knot/conf/conf.h"

redisContext *rdb_connect(conf_t *conf);
