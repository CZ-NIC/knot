/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "knot/dnssec/kasp/kasp_db.h"
#include "knot/zone/contents.h"
#include "libdnssec/keystore.h"

typedef struct {
	knot_dname_t *dname;

	knot_kasp_key_t *keys;
	size_t num_keys;

	dnssec_binary_t nsec3_salt;
	knot_time_t nsec3_salt_created;
} knot_kasp_zone_t;

int kasp_zone_load(knot_kasp_zone_t *zone,
                   const knot_dname_t *zone_name,
                   knot_lmdb_db_t *kdb,
                   bool *kt_cfl);

int kasp_zone_save(const knot_kasp_zone_t *zone,
		   const knot_dname_t *zone_name,
		   knot_lmdb_db_t *kdb);

int kasp_zone_append(knot_kasp_zone_t *zone,
		     const knot_kasp_key_t *appkey);

void kasp_zone_clear(knot_kasp_zone_t *zone);
void kasp_zone_free(knot_kasp_zone_t **zone);

void free_key_params(key_params_t *parm);

int zone_init_keystore(conf_t *conf, conf_val_t *policy_id,
                       dnssec_keystore_t **keystore, unsigned *backend, bool *key_label);

int kasp_zone_keys_from_rr(knot_kasp_zone_t *zone,
                           const knot_rdataset_t *zone_dnskey,
                           bool policy_single_type_signing,
                           bool *keytag_conflict);

int kasp_zone_from_contents(knot_kasp_zone_t *zone,
                            const zone_contents_t *contents,
                            bool policy_single_type_signing,
                            bool policy_nsec3,
                            uint16_t *policy_nsec3_iters,
                            bool *keytag_conflict);
