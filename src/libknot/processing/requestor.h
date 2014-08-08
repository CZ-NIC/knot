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

#include "common/lists.h"
#include "common/sockaddr.h"
#include "libknot/processing/process.h"

struct knot_request;

/* Requestor flags. */
enum {
	KNOT_RQ_UDP = 1 << 0  /* Use UDP for requests. */

};

/*! \brief Requestor structure.
 *
 *  Requestor holds a FIFO of pending queries.
 */
struct knot_requestor {
	const knot_process_module_t *module; /*!< Response processing module. */
	list_t pending;                      /*!< Pending requests (FIFO). */
	mm_ctx_t *mm;                        /*!< Memory context. */
};

/*! \brief Request data (socket, payload and endpoints). */
struct knot_request_data {
	node_t node;
	int fd;
	unsigned flags;
	struct sockaddr_storage remote, origin;
	knot_pkt_t *query;
};

/*!
 * \brief Initialize requestor structure.
 *
 * \param requestor Requestor instance.
 * \param module    Response processing module.
 * \param mm        Memory context.
 */
void knot_requestor_init(struct knot_requestor *requestor, const knot_process_module_t *module, mm_ctx_t *mm);

/*!
 * \brief Clear the requestor structure and close pending queries.
 *
 * \param requestor Requestor instance.
 */
void knot_requestor_clear(struct knot_requestor *requestor);

/*!
 * \brief Return true if there are no pending queries.
 *
 * \param requestor Requestor instance.
 */
bool knot_requestor_finished(struct knot_requestor *requestor);


/*!
 * \brief Make request out of endpoints and query.
 *
 * \param requestor Requestor instance.
 * \param dst       Remote endpoint address.
 * \param src       Source address (or NULL).
 * \param query     Query message.
 * \param flags     Request flags.
 *
 * \return Prepared request or NULL in case of error.
 */
struct knot_request *knot_requestor_make(struct knot_requestor *requestor,
                                         const struct sockaddr *addr,
                                         const struct sockaddr *src,
                                         knot_pkt_t *query,
                                         unsigned flags);

/*!
 * \brief Enqueue a query for processing.
 *
 * \note This function asynchronously creates a new connection to remote, but
 *       it does not send any data until requestor_exec().
 *
 * \param requestor Requestor instance.
 * \param request   Prepared request.
 * \param param     Request processing module parameter.
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_enqueue(struct knot_requestor *requestor, struct knot_request *request, void *param);

/*!
 * \brief Close first pending request.
 *
 * \param requestor Requestor instance.
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_dequeue(struct knot_requestor *requestor);

/*!
 * \brief Execute next pending query (FIFO).
 *
 * \param requestor Requestor instance.
 * \param timeout   Processing timeout.
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_exec(struct knot_requestor *requestor, struct timeval *timeout);
