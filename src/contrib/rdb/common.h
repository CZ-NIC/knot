/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>
#else // ENABLE_REDIS
struct redisContext;
typedef struct redisContext redisContext;
#endif // ENABLE_REDIS

/*!
 * \brief Check if the conected DB has compatible endianness.
 */
bool rdb_compatible(redisContext *rdb);

/*!
 * \brief Check if the conection to the DB is still alive.
 */
bool rdb_ping(redisContext *rdb);

/*!
 * \brief Check the connected DB role.
 *
 * \retval -1	Error
 * \retval  0	Master
 * \retval  1	Replica
 * \retval  2	Sentinel
 */
int rdb_role(redisContext *rdb);
