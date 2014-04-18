/*!
 * \file ixfr.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief IXFR processing.
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

#ifndef _KNOT_IXFR_H_
#define _KNOT_IXFR_H_

#include "libknot/packet/pkt.h"
#include "knot/zone/zonedb.h"

struct query_data;
struct answer_data;

/*!
 * \brief IXFR query processing module.
 *
 * \retval FULL if it has an answer, but not yet finished.
 * \retval FAIL if it encountered an error.
 * \retval DONE if finished.
 */
int ixfr_answer(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Process an IXFR query response.
 *
 * \param pkt Processed packet.
 * \param xfr Persistent transfer-specific data.
 *
 * \retval KNOT_EOK If this packet was processed successfuly and another packet
 *                  is expected. (RFC1995bis, case c)
 * \retval KNOT_ENOXFR If the transfer is not taking place because server's
 *                     SERIAL is the same as this client's SERIAL. The client
 *                     should close the connection and do no further processing.
 *                     (RFC1995bis case a).
 * \retval KNOT_EAGAIN If the server could not fit the transfer into the packet.
 *                     This should happen only if UDP was used. In this case
 *                     the client should retry the request via TCP. If UDP was
 *                     not used, it should be considered that the transfer was
 *                     malformed and the connection should be closed.
 *                     (RFC1995bis case b).
 * \retval >0 Transfer successully finished. Changesets are created and furter
 *            processing is needed.
 * \retval Other If any other error occured. The connection should be closed.
 *
 */
int ixfr_process_answer(knot_pkt_t *pkt, struct answer_data *data);

#endif /* _KNOT_IXFR_H_ */

/*! @} */
