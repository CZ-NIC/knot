/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef LIBNGHTTP2

#include <stdbool.h>

#include <nghttp2/nghttp2.h>

#include "contrib/base64.h"
#include "libknot/errcode.h"
#include "utils/common/tls.h"

#define MAKE_STATIC_NV(K, V) \
    { (uint8_t *)K, (uint8_t *)V, sizeof(K) - 1, sizeof(V) - 1, NGHTTP2_NV_FLAG_NONE }

#define MAKE_NV(K, KS, V, VS) \
    { (uint8_t *)K, (uint8_t *)V, KS, VS, NGHTTP2_NV_FLAG_NONE }

typedef struct  {
    bool enable;
} https_params_t;


typedef struct {
    nghttp2_session *session;
    tls_ctx_t *tls;
    const https_params_t *params;
} https_ctx_t;

int https_ctx_init(https_ctx_t *ctx, tls_ctx_t *tls_ctx, const https_params_t *params);
int https_ctx_connect(https_ctx_t *ctx);
int https_send_dns_query(https_ctx_t *ctx, const uint8_t *buf, const size_t buf_len);
int https_recv_dns_response(https_ctx_t *ctx);
void https_ctx_deinit(https_ctx_t *ctx);

#endif //LIBNGHTTP2