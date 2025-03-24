/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/nameserver/process_query.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief Process an AXFR query message.
 */
knot_layer_state_t axfr_process_query(knot_pkt_t *pkt, knotd_qdata_t *qdata);
