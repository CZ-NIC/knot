/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/context.h"

int keymgr_pregenerate_zsks(kdnssec_ctx_t *ctx, char *arg);

int keymgr_print_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_delete_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_del_all_old(kdnssec_ctx_t *ctx);

int keymgr_print_ksr(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_sign_ksr(kdnssec_ctx_t *ctx, const char *ksr_file);

int keymgr_import_skr(kdnssec_ctx_t *ctx, const char *skr_file);

int keymgr_validate_skr(kdnssec_ctx_t *ctx, const char *skr_file);
