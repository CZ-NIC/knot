/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"

int proxyv2_header_strip(knot_pkt_t **query,
                         const struct sockaddr_storage *remote,
                         struct sockaddr_storage *new_remote);
