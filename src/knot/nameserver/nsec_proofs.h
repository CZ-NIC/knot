/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "knot/nameserver/process_query.h"

/*! \brief Prove wildcards visited during answer resolution. */
int nsec_prove_wildcards(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/*! \brief Prove answer leading to non-existent name. */
int nsec_prove_nxdomain(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/*! \brief Prove empty answer. */
int nsec_prove_nodata(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/*! \brief Prove delegation point security. */
int nsec_prove_dp_security(knot_pkt_t *pkt, knotd_qdata_t *qdata);

/*! \brief Append missing RRSIGs for current processing section. */
int nsec_append_rrsigs(knot_pkt_t *pkt, knotd_qdata_t *qdata, bool optional);

/*! \brief Clear RRSIG list. */
void nsec_clear_rrsigs(knotd_qdata_t *qdata);
