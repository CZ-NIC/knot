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

#include <wget.h>
#include <string.h>

#include "config.h"

#include "contrib/base64.h"

#include "libknot/errcode.h"

typedef struct {
    bool use;
    wget_iri_t server;
} https_ctx_t;

int https_ctx_init(https_ctx_t *ctx);

int https_send_doh_request(const uint8_t *buf, const size_t buf_len);