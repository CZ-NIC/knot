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

#pragma once

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
	zone_contents_t *contents; /* Processed zone. */
	conf_t *conf;
};

/*! \brief Generic transfer processing (reused for IXFR).
 *  \return KNOT_EOK or an error
 */
typedef int (*xfr_put_cb)(knot_pkt_t *pkt, const void *item, struct xfr_proc *xfer);

/*! \brief Put all items from xfr_proc.nodes to packet using a callback function.
 *  \note qdata->ext points to struct xfr_proc* (this is xfer-specific context)
 */
int xfr_process_list(knot_pkt_t *pkt, xfr_put_cb put, struct query_data *qdata);

/*!
 * \brief Process an AXFR query message.
 *
 * \return NS_PROC_* processing states
 */
int axfr_query_process(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Processes an AXFR response message.
 *
 * \return NS_PROC_* processing states
 */
int axfr_answer_process(knot_pkt_t *pkt, struct answer_data *adata);

/*! @} */
