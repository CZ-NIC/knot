/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/zone/node.h"
#include "redis/knot.h"

#ifdef ENABLE_REDIS
#include <hiredis/hiredis.h>
#else // ENABLE_REDIS
struct redisContext;
#endif // ENABLE_REDIS

typedef char zone_redis_err_t[128];

typedef struct {
	struct redisContext *rdb;
	rdb_txn_t rdb_txn;
	uint8_t instance;

	const knot_dname_t *origin;
	uint8_t origin_len;

	bool incremental;
	bool removals;

	zone_redis_err_t err;
} zone_redis_txn_t;

/*!
 * \brief Wrappers to rdb_connect and rdb_disconnect not needing #ifdef ENABLE_REDIS around.
 */
struct redisContext *zone_redis_connect(conf_t *conf);
void zone_redis_disconnect(struct redisContext *ctx);

/*!
 * \brief Start a writing stransaction into Redis zone database.
 *
 * \param txn           Transaction context structure to be filled;
 * \param rdb           Redis context (just pass zone_redis_connect()).
 * \param instance      Zone instance number (from configuration).
 * \param zone_name     Zone name.
 * \param incremental   Store incremental update (otherwise full zone rewrite).
 *
 * \return KNOT_E*
 */
int zone_redis_txn_begin(zone_redis_txn_t *txn, struct redisContext *rdb,
                         uint8_t instance, const knot_dname_t *zone_name,
                         bool incremental);

/*!
 * \brief Write single RRset to zone DB.
 *
 * \param txn    Transaction to write into.
 * \param rr     RRset to write.
 *
 * \note In case of incremental transaction, txn->removals signals if the RRset should be added to removals or additions.
 *
 * \return KNOT_E*
 */
int zone_redis_write_rrset(zone_redis_txn_t *txn, const knot_rrset_t *rr);

/*!
 * \brief Calls zone_redis_write_rrset() for all RRsets in a node.
 */
int zone_redis_write_node(zone_redis_txn_t *txn, const zone_node_t *node);

/*!
 * \brief Commit a zone DB transaction.
 */
int zone_redis_txn_commit(zone_redis_txn_t *txn);

/*!
 * \brief Abort a zone DB transaction.
 *
 * \note You might want to ignore the return code.
 */
int zone_redis_txn_abort(zone_redis_txn_t *txn);
