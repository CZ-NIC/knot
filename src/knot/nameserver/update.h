/*!
 * \file update.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief DDNS UPDATE processing.
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
#include "knot/zone/zonedb.h"

struct query_data;

/*!
 * \brief UPDATE query processing module.
 *
 * \retval FAIL if it encountered an error.
 * \retval DONE if finished.
 */
int update_answer(knot_pkt_t *pkt, struct query_data *qdata);


/*!
 * \brief Processes serialized packet with DDNS. Function expects that the
 *        query is already authenticated and TSIG signature is verified.
 *
 * \param pkt    Prepared response packet.
 * \param qdata  Minimal query data context.
 *
 * \return KNOT_E*
 */
int update_process_query(knot_pkt_t *pkt, struct query_data *qdata);

/*! @} */
