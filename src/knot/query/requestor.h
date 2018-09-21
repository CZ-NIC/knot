/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/socket.h>
#include <sys/time.h>

#include "knot/nameserver/tsig_ctx.h"
#include "knot/query/layer.h"
#include "libknot/mm_ctx.h"
#include "libknot/rrtype/tsig.h"

typedef enum {
	KNOT_REQUEST_UDP = 1 << 0  /*!< Use UDP for requests. */
} knot_request_flag_t;

typedef enum {
	KNOT_REQUESTOR_CLOSE = 1 << 0
} knot_requestor_flag_t;

/*! \brief Requestor structure.
 *
 *  Requestor holds a FIFO of pending queries.
 */
typedef struct {
	knot_mm_t *mm;       /*!< Memory context. */
	knot_layer_t layer;  /*!< Response processing layer. */
} knot_requestor_t;

/*! \brief Request data (socket, payload, response, TSIG and endpoints). */
typedef struct {
	int fd;
	knot_request_flag_t flags;
	struct sockaddr_storage remote, source;
	knot_pkt_t *query;
	knot_pkt_t *resp;
	tsig_ctx_t tsig;

	knot_sign_context_t sign; /*!< Required for async. DDNS processing. */
} knot_request_t;

/*!
 * \brief Make request out of endpoints and query.
 *
 * \param mm     Memory context.
 * \param dst    Remote endpoint address.
 * \param src    Source address (or NULL).
 * \param query  Query message.
 * \param key    TSIG key for authentication.
 * \param flags  Request flags.
 *
 * \return Prepared request or NULL in case of error.
 */
knot_request_t *knot_request_make(knot_mm_t *mm,
                                  const struct sockaddr *dst,
                                  const struct sockaddr *src,
                                  knot_pkt_t *query,
                                  const knot_tsig_key_t *key,
                                  knot_request_flag_t flags);

/*!
 * \brief Free request and associated data.
 *
 * \param request Freed request.
 * \param mm      Memory context.
 */
void knot_request_free(knot_request_t *request, knot_mm_t *mm);

/*!
 * \brief Initialize requestor structure.
 *
 * \param requestor   Requestor instance.
 * \param proc        Response processing module.
 * \param proc_param  Processing module context.
 * \param mm          Memory context.
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_init(knot_requestor_t *requestor,
                        const knot_layer_api_t *proc, void *proc_param,
                        knot_mm_t *mm);

/*!
 * \brief Clear the requestor structure and close pending queries.
 *
 * \param requestor Requestor instance.
 */
void knot_requestor_clear(knot_requestor_t *requestor);

/*!
 * \brief Execute a request.
 *
 * \param requestor  Requestor instance.
 * \param request    Request instance.
 * \param timeout_ms Timeout of each operation in miliseconds (-1 for infinity).
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_exec(knot_requestor_t *requestor,
                        knot_request_t *request,
                        int timeout_ms);
