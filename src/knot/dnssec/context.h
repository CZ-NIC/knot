/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libdnssec/keystore.h"
#include "contrib/spinlock.h"
#include "contrib/time.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/policy.h"

typedef struct {
	size_t rrsig_count;
	knot_time_t expire;

	knot_spin_t lock;
} zone_sign_stats_t;

/*!
 * \brief DNSSEC signing context.
 */
typedef struct {
	knot_time_t now;

	knot_lmdb_db_t *kasp_db;
	knot_kasp_zone_t *zone;
	knot_kasp_policy_t *policy;
	knot_kasp_keystore_t *keystores;

	char *kasp_zone_path;

	zone_sign_stats_t *stats;

	bool rrsig_drop_existing;
	bool keep_deleted_keys;
	bool keytag_conflict;
	bool validation_mode;

	unsigned dbus_event;

	key_records_t offline_records;
	knot_time_t offline_next_time;
} kdnssec_ctx_t;

/*!
 * \brief Initialize DNSSEC signing context.
 *
 * \param conf         Configuration.
 * \param ctx          Signing context to be initialized.
 * \param zone_name    Name of the zone.
 * \param kaspdb       Key and signature policy database.
 * \param from_module  Module identifier if initialized from a module.
 */
int kdnssec_ctx_init(conf_t *conf, kdnssec_ctx_t *ctx, const knot_dname_t *zone_name,
                     knot_lmdb_db_t *kaspdb, const conf_mod_id_t *from_module);

/*!
 * \brief Initialize DNSSEC validating context.
 *
 * \param conf    Configuration.
 * \param ctx     Signing context to be initialized.
 * \param zone    Zone contents to be validated.
 * \param threads The number of threads when conf is not available (0 for default).
 *
 * \return KNOT_E*
 */
int kdnssec_validation_ctx(conf_t *conf, kdnssec_ctx_t *ctx, const zone_contents_t *zone,
                           uint16_t threads);

/*!
 * \brief Save the changes in ctx (in kasp zone).
 */
int kdnssec_ctx_commit(kdnssec_ctx_t *ctx);

/*!
 * \brief Cleanup DNSSEC signing context.
 */
void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx);
