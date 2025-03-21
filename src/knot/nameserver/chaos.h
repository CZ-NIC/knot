/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int knot_chaos_answer(knot_pkt_t *pkt);
