/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief AXFR processing.
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "knot/nameserver/log.h"
#include "knot/query/query.h"
#include "knot/nameserver/process_query.h"
#include "knot/zone/contents.h"
#include "contrib/ucw/lists.h"

/*!
 * \brief Transfer-specific logging (internal, expects 'qdata' variable set).
 *
 * Emits a message in the following format:
 * > [zone] type, outgoing, address: custom formatted message
 */
#define TRANSFER_OUT_LOG(type, priority, msg, ...) \
	NS_PROC_LOG(priority, (qdata)->zone->name, (qdata)->param->remote, \
	            type ", outgoing", msg, ##__VA_ARGS__)
#define AXFROUT_LOG(args...) TRANSFER_OUT_LOG("AXFR", args)
#define IXFROUT_LOG(args...) TRANSFER_OUT_LOG("IXFR", args)

/*!
 * \brief Transfer-specific logging (internal, expects 'adata' variable set).
 */
#define TRANSFER_IN_LOG(type, priority, msg, ...) \
	NS_PROC_LOG(priority, (adata)->param->zone->name, (adata)->param->remote, \
	            type ", incoming", msg, ##__VA_ARGS__)
#define AXFRIN_LOG(args...) TRANSFER_IN_LOG("AXFR", args)
#define IXFRIN_LOG(args...) TRANSFER_IN_LOG("IXFR", args)


/*! \brief Generic transfer processing state. */
struct xfr_proc {
	list_t nodes;    /* Items to process (ptrnode_t). */
	unsigned npkts;  /* Packets processed. */
	unsigned nbytes; /* Bytes processed. */
	struct timeval tstamp; /* Start time. */
	zone_contents_t *contents; /* Processed zone. */
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
 * \return KNOT_STATE_* processing states
 */
int axfr_process_query(knot_pkt_t *pkt, struct query_data *qdata);

/*!
 * \brief Processes an AXFR response message.
 *
 * \return KNOT_STATE_* processing states
 */
int axfr_process_answer(knot_pkt_t *pkt, struct answer_data *adata);

/*! @} */
