/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "utils/kdig/kdig_params.h"

int kdig_exec(const kdig_params_t *params);
int process_query(const query_t *query, net_t *net);
knot_pkt_t *create_query_packet(const query_t *query);
knot_pkt_t *create_query_packet_with_msgid(const query_t *query);
