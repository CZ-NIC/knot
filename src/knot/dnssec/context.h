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

#include <dnssec/keystore.h>

#include "knot/conf/conf.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/policy.h"

/*!
 * \brief DNSSEC signing context.
 */
typedef struct {
	knot_time_t now;

	kasp_db_t **kasp_db;
	knot_kasp_zone_t *zone;
	knot_kasp_policy_t *policy;
	dnssec_keystore_t *keystore;

	char *kasp_zone_path;

	uint32_t old_serial;
	uint32_t new_serial;
	bool rrsig_drop_existing;
} kdnssec_ctx_t;

/*!
 * \brief Initialize DNSSEC signing context.
 *
 * \param conf         Configuration.
 * \param ctx          Signing context to be initialized.
 * \param zone_name    Name of the zone.
 * \param from_module  Module identifier if initialized from a module.
 */
int kdnssec_ctx_init(conf_t *conf, kdnssec_ctx_t *ctx, const knot_dname_t *zone_name,
                     const conf_mod_id_t *from_module);

/*!
 * \brief Save the changes in ctx (in kasp zone).
 */
int kdnssec_ctx_commit(kdnssec_ctx_t *ctx);

/*!
 * \brief Cleanup DNSSEC signing context.
 */
void kdnssec_ctx_deinit(kdnssec_ctx_t *ctx);
