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

#include <stdio.h>

#include "knot/dnssec/context.h"

typedef struct {
	knot_time_print_t format;
	bool extended;
	bool color;
	bool json;
} keymgr_list_params_t;

int parse_timestamp(char *arg, knot_time_t *stamp);

int keymgr_generate_key(kdnssec_ctx_t *ctx, int argc, char *argv[]);

int keymgr_import_bind(kdnssec_ctx_t *ctx, const char *import_file, bool pub_only);

int keymgr_import_pem(kdnssec_ctx_t *ctx, const char *import_file, int argc, char *argv[]);

int keymgr_import_pkcs11(kdnssec_ctx_t *ctx, char *key_id, int argc, char *argv[]);

int keymgr_nsec3_salt_print(kdnssec_ctx_t *ctx);

int keymgr_nsec3_salt_set(kdnssec_ctx_t *ctx, const char *new_salt);

int keymgr_serial_print(kdnssec_ctx_t *ctx, kaspdb_serial_t type);

int keymgr_serial_set(kdnssec_ctx_t *ctx, kaspdb_serial_t type, uint32_t new_serial);

int keymgr_generate_tsig(const char *tsig_name, const char *alg_name, int bits);

int keymgr_get_key(kdnssec_ctx_t *ctx, const char *key_spec, knot_kasp_key_t **key);

int keymgr_foreign_key_id(char *argv[], knot_lmdb_db_t *kaspdb, knot_dname_t **key_zone, char **key_id);

int keymgr_set_timing(knot_kasp_key_t *key, int argc, char *argv[]);

int keymgr_list_keys(kdnssec_ctx_t *ctx, keymgr_list_params_t *params);

int keymgr_generate_ds(const knot_dname_t *dname, const knot_kasp_key_t *key);

int keymgr_generate_dnskey(const knot_dname_t *dname, const knot_kasp_key_t *key);

int keymgr_list_zones(knot_lmdb_db_t *kaspdb, bool json);
