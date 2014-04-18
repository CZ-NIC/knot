/*!
 * \file axfr.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief AXFR processing.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_AXFR_H_
#define _KNOT_AXFR_H_

#include "libknot/packet/pkt.h"
#include "knot/zone/zonedb.h"

struct query_data;
struct answer_data;

/*! \brief Generic transfer processing state. */
struct xfr_proc {
	list_t nodes;    /* Items to process (ptrnode_t). */
	unsigned npkts;  /* Packets processed. */
	unsigned nbytes; /* Bytes processed. */
	struct timeval tstamp; /* Start time. */
};

/*! \brief Generic transfer processing (reused for IXFR).
 */
typedef int (*xfr_put_cb)(knot_pkt_t *pkt, const void *item, struct xfr_proc *xfer);

/*! \brief Put all items from xfr_proc.nodes to packet using a callback function.
 *  \note qdata->ext points to struct xfr_proc* (this is xfer-specific context)
 */
int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb put, struct query_data *qdata);

/*!
 * \brief AXFR query processing module.
 *
 * \retval FULL if it has an answer, but not yet finished.
 * \retval FAIL if it encountered an error.
 * \retval DONE if finished.
 */
int axfr_answer(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Processes an AXFR query response.
 *
 * \param pkt Processed packet.
 * \param xfr Persistent transfer-specific data.
 *
 */
int axfr_process_answer(knot_pkt_t *pkt, struct answer_data *xfr);

#endif /* _KNOT_AXFR_H_ */

/*! @} */
