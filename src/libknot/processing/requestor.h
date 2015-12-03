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

#include <sys/socket.h>
#include <sys/time.h>

#include "libknot/processing/overlay.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/internal/lists.h"
#include "libknot/internal/mempattern.h"

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
	mm_ctx_t *mm;                 /*!< Memory context. */
	list_t pending;               /*!< Pending requests (FIFO). */
	struct knot_overlay overlay;  /*!< Response processing overlay. */
};

/*! \brief Request data (socket, payload, response, TSIG and endpoints). */
struct knot_request {
	node_t node;
	int fd;
	unsigned flags;
	struct sockaddr_storage remote, origin;
	knot_sign_context_t sign;
	knot_pkt_t *query;
	knot_pkt_t *resp;
};

/*!
 * \brief Make request out of endpoints and query.
 *
 * \param mm     Memory context.
 * \param dst    Remote endpoint address.
 * \param src    Source address (or NULL).
 * \param query  Query message.
 * \param flags  Request flags.
 *
 * \return Prepared request or NULL in case of error.
 */
struct knot_request *knot_request_make(mm_ctx_t *mm,
                                       const struct sockaddr *dst,
                                       const struct sockaddr *src,
                                       knot_pkt_t *query,
                                       unsigned flags);

/*!
 * \brief Free request and associated data.
 *
 * \param mm      Memory context.
 * \param request Freed request.
 *
 * \return Prepared request or NULL in case of error.
 */
int knot_request_free(mm_ctx_t *mm, struct knot_request *request);

/*!
 * \brief Initialize requestor structure.
 *
 * \param requestor Requestor instance.
 * \param mm        Memory context.
 */
void knot_requestor_init(struct knot_requestor *requestor, mm_ctx_t *mm);

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
 * \brief Add a processing layer.
 *
 * \param requestor Requestor instance.
 * \param proc      Response processing module.
 * \param param     Processing module parameters.
 */
int knot_requestor_overlay(struct knot_requestor *requestor,
                           const knot_layer_api_t *proc, void *param);

/*!
 * \brief Enqueue a query for processing.
 *
 * \note This function asynchronously creates a new connection to remote, but
 *       it does not send any data until requestor_exec().
 *
 * \param requestor Requestor instance.
 * \param request   Prepared request.
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_enqueue(struct knot_requestor *requestor,
                           struct knot_request *request);

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
int knot_requestor_exec(struct knot_requestor *requestor,
                        struct timeval *timeout);
