/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/context.h"

struct server;

int knot_parent_ds_query(conf_t *conf, kdnssec_ctx_t *kctx, struct server *server,
                         size_t timeout);
