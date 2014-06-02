/*!
 * \file nsec_proofs.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief NSEC/NSEC3 proofs for various states.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "libknot/packet/pkt.h"

/* Query data (from query processing). */
struct query_data;

/*! \brief Prove wildcards visited during answer resolution. */
int nsec_prove_wildcards(knot_pkt_t *pkt, struct query_data *qdata);

/*! \brief Prove answer leading to non-existent name. */
int nsec_prove_nxdomain(knot_pkt_t *pkt, struct query_data *qdata);

/*! \brief Prove empty answer. */
int nsec_prove_nodata(knot_pkt_t *pkt, struct query_data *qdata);

/*! \brief Prove delegation point security. */
int nsec_prove_dp_security(knot_pkt_t *pkt, struct query_data *qdata);

/*! \brief Append missing RRSIGs for current processing section. */
int nsec_append_rrsigs(knot_pkt_t *pkt, struct query_data *qdata, bool optional);

/*! \brief Clear RRSIG list. */
void nsec_clear_rrsigs(struct query_data *qdata);

/*! @} */
