/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <time.h>

#include <dnssec/kasp.h>
#include <dnssec/keystore.h>

#include "knot/conf/conf.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "libknot/dname.h"

/*!
 * \brief DNSSEC signing context.
 */
struct kdnssec_ctx {
	time_t now;

	kasp_db_t **kasp_db;
	knot_kasp_zone_t *zone;
	dnssec_kasp_policy_t *policy;
	dnssec_keystore_t *keystore;

	char *kasp_zone_path;

	uint32_t old_serial;
	uint32_t new_serial;
	bool rrsig_drop_existing;
};

typedef struct kdnssec_ctx kdnssec_ctx_t;

/*!
 * \brief Initialize DNSSEC parameters of the DNSSEC context.
 *
 * No cleanup is performed on failure.
 */
int kdnssec_kasp_init(kdnssec_ctx_t *ctx, const char *kasp_path, size_t kasp_mapsize,
		      const knot_dname_t *zone_name, const char *policy_name);

/*!
 * \brief Initialize DNSSEC signing context.
 *
 * \param ctx             Signing context to be initialized.
 * \param zone_name       Name of the zone.
 * \param policy          DNSSEC policy configuration reference.
 * \param disable_legacy  Disable legacy detection indication.
 */
int kdnssec_ctx_init(kdnssec_ctx_t *ctx, const knot_dname_t *zone_name,
                     conf_val_t *policy);

/*!
 * \brief Save the changes in ctx (in kasp zone).
 */
int kdnssec_ctx_commit(kdnssec_ctx_t *ctx);

/*!
 * \brief Cleanup DNSSEC signing context.
 */
void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx);
