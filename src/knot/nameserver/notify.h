/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "knot/nameserver/process_query.h"

/*!
 * \brief Answer IN class zone NOTIFY message (RFC1996).
 */
knot_layer_state_t notify_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata);
