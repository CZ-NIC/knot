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

#include "knot/dnssec/context.h"

int keymgr_generate_key(kdnssec_ctx_t *ctx, int argc, char *argv[]);

int keymgr_import_bind(kdnssec_ctx_t *ctx, const char *import_file);

int keymgr_generate_tsig(const char *tsig_name, const char *alg_name, int bits);

int keymgr_get_key(kdnssec_ctx_t *ctx, const char *key_spec, knot_kasp_key_t **key);

int keymgr_foreign_key_id(int argc, char *argv[], const char *req_action,
			  knot_dname_t **key_zone, char **key_id);

int keymgr_set_timing(knot_kasp_key_t *key, int argc, char *argv[]);

int keymgr_list_keys(kdnssec_ctx_t *ctx);

int keymgr_generate_ds(const knot_dname_t *dname, const knot_kasp_key_t *key);
