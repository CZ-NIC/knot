/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Extension of hiredis to support GnuTLS backend.
 */

#pragma once

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>
#else
typedef void * redisContext;
#endif

#include "knot/conf/conf.h"
#include "libknot/quic/tls_common.h"

redisContext *rdb_connect(conf_t *conf);