/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
