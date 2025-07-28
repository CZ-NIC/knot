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
struct zone_contents;

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

/*!
 * \brief Check if the zone exists in the database+instance and read out SOA serial.
 *
 * \param rdb         Redis context (just pass zone_redis_connect()).
 * \param instance    Zone instance number (from configuration).
 * \param zone        Zone name.
 * \param serial      Output: SOA serial of stored zone.
 * \param err         Output: error message in case of Redis error.
 *
 * \retval KNOT_ERDB  Redis-related error with err set.
 * \return KNOT_E*
 */
int zone_redis_serial(struct redisContext *rdb, uint8_t instance,
                      const knot_dname_t *zone, uint32_t *serial,
                      zone_redis_err_t err);

/*!
 * \brief Load whole zone contents from Redis.
 *
 * \param rdb         Redis context (just pass zone_redis_connect()).
 * \param instance    Zone instance number (from configuration).
 * \param zone_name   Zone name.
 * \param out         Output: zone contents.
 * \param err         Output: error message in case of Redis error.
 *
 * \retval KNOT_ERDB  Redis-related error with err set.
 * \return KNOT_E*
 */
int zone_redis_load(struct redisContext *rdb, uint8_t instance,
                    const knot_dname_t *zone_name, struct zone_contents **out,
                    zone_redis_err_t err);

/*!
 * \brief Callback type for handling data read by zone_redis_load_upd().
 *
 * \param rr       Loaded RRset.
 * \param add      The RRset is an addition in the changeset (removal otherwise).
 * \param ctx      Transparent context passed to zone_redis_load_upd().
 *
 * \return KNOT_E*
 */
typedef int (*zone_redis_load_upd_cb_t)(const knot_rrset_t *rr, bool add, void *ctx);

/*!
 * \brief Load one or more changesets from Redis.
 *
 * \param rdb         Redis context (just pass zone_redis_connect()).
 * \param instance    Zone instance number (from configuration).
 * \param zone_name   Zone name.
 * \param soa_from    SOA serial to start at.
 * \param cb          Callback to be called for each removed/added RRset.
 * \param ctx         Transparent context for the callback.
 * \param err         Output: error message in case of Redis error.
 *
 * \note In case of error, the callback might have been called several times,
 *       so that the real target structure (zone_update or whatever) might
 *       contain partial invalid data.
 *
 * \retval KNOT_ERDB  Redis-related error with err set.
 * \return KNOT_E*
 */
int zone_redis_load_upd(struct redisContext *rdb, uint8_t instance,
                        const knot_dname_t *zone_name, uint32_t soa_from,
                        zone_redis_load_upd_cb_t cb, void *ctx,
                        zone_redis_err_t err);
