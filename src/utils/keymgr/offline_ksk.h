/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/dnssec/context.h"

int keymgr_pregenerate_zsks(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_print_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_delete_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_del_all_old(kdnssec_ctx_t *ctx);

int keymgr_print_ksr(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to);

int keymgr_sign_ksr(kdnssec_ctx_t *ctx, const char *ksr_file);

int keymgr_import_skr(kdnssec_ctx_t *ctx, const char *skr_file);

int keymgr_validate_skr(kdnssec_ctx_t *ctx, const char *skr_file);
