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

#include "knot/nameserver/process_query.h"
#include "knot/nameserver/process_answer.h"
#include "common/lists.h"

struct request;

/*! \brief Requestor structure.
 *
 *  Requestor holds a FIFO of pending queries with given remote.
 */
struct requestor {
	/* Requestor target and source address. */
	const knot_process_module_t *module;

	//knot_sign_context_t tsig; /* @note not implemented */

	list_t pending;
	mm_ctx_t *mm;                      /*!< Memory context. */
};

/*! \brief Request data (payload and endpoints). */
struct request_data {
	node_t node;
	int fd;
	struct sockaddr_storage remote, origin;
	knot_pkt_t *query;
};

/*!
 * \brief Initialize requestor structure.
 */
void requestor_init(struct requestor *requestor, const knot_process_module_t *module, mm_ctx_t *mm);

/*!
 * \brief Clear the requestor structure and close pending queries.
 */
void requestor_clear(struct requestor *requestor);

/*! \brief Return true if there are no pending queries. */
bool requestor_finished(struct requestor *requestor);


/*! \brief Make request out of endpoints and query. */
struct request *requestor_make(struct requestor *requestor,
                               const conf_iface_t *remote,
                               knot_pkt_t *query);

/*!
 * \brief Enqueue a query for processing.
 *
 * \note This function asynchronously creates a new connection to remote, but
 *       it does not send any data until requestor_exec().
 *
 * \param requestor Requestor instance.
 * \param query     Query (requestor takes ownership if this function succeeds).
 * \param module    Processing module.
 * \param param     Processing module parameter.
 *
 * \return KNOT_EOK or error
 */
int requestor_enqueue(struct requestor *requestor, struct request *request, void *param);

/*!
 * \brief Close first pending request.
 *
 * \param requestor Requestor instance.
 *
 * \return KNOT_EOK or error
 */
int requestor_dequeue(struct requestor *requestor);

/*!
 * \brief Execute next pending query (FIFO).
 *
 * \param requestor Requestor instance.
 * \param timeout   Processing timeout.
 *
 * \return KNOT_EOK or error
 */
int requestor_exec(struct requestor *requestor, struct timeval *timeout);
