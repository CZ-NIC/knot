/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <sys/socket.h>
#include <sys/time.h>

#include "knot/conf/conf.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/query/layer.h"
#include "knot/query/query.h"
#include "knot/query/tls-requestor.h"
#include "libknot/mm_ctx.h"
#include "libknot/rrtype/tsig.h"

typedef enum {
	KNOT_REQUEST_NONE = 0,       /*!< Empty flag. */
	KNOT_REQUEST_UDP  = 1 << 0,  /*!< Use UDP for requests. */
	KNOT_REQUEST_TFO  = 1 << 1,  /*!< Enable TCP Fast Open for requests. */
	KNOT_REQUEST_KEEP = 1 << 2,  /*!< Keep upstream TCP connection in pool for later reuse. */
	KNOT_REQUEST_QUIC = 1 << 3,  /*!< Use QUIC/UDP for requests. */
	KNOT_REQUEST_TLS  = 1 << 4,  /*!< Use DoT for requests. */
	KNOT_REQUEST_FWD  = 1 << 5,  /*!< Forwarded message, don't modify (TSIG, PADDING). */
} knot_request_flag_t;

typedef enum {
	KNOT_REQUESTOR_CLOSE  = 1 << 0, /*!< Close the connection indication. */
	KNOT_REQUESTOR_REUSED = 1 << 1, /*!< Reused FD indication (RO). */
	KNOT_REQUESTOR_QUIC   = 1 << 2, /*!< QUIC used indication (RO). */
	KNOT_REQUESTOR_TLS    = 1 << 3, /*!< DoT used indication (RO). */
	KNOT_REQUESTOR_IOFAIL = 1 << 4, /*!< Encountered error sending/recving data. */
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
typedef struct knot_request {
	int fd;
	union {
		struct {
			struct knot_quic_reply *quic_ctx;
			struct knot_quic_conn *quic_conn;
			int64_t quic_stream;
		};
		knot_tls_req_ctx_t tls_req_ctx;
	};
	knot_request_flag_t flags;
	struct sockaddr_storage remote, source;
	knot_pkt_t *query;
	knot_pkt_t *resp;
	const query_edns_data_t *edns;
	tsig_ctx_t tsig;

	knot_sign_context_t sign; /*!< Required for async. DDNS processing. */

	const struct knot_creds *creds;
	const char *hostname;
	size_t pin_len;
	uint8_t pin[];
} knot_request_t;

static inline knotd_query_proto_t flags2proto(unsigned layer_flags)
{
	knotd_query_proto_t proto = KNOTD_QUERY_PROTO_TCP;
	if ((layer_flags & KNOT_REQUESTOR_QUIC)) {
		proto = KNOTD_QUERY_PROTO_QUIC;
	} else if ((layer_flags & KNOT_REQUESTOR_TLS)) {
		proto = KNOTD_QUERY_PROTO_TLS;
	}
	return proto;
}

/*!
 * \brief Make request out of endpoints and query.
 *
 * \param mm        Memory context.
 * \param remote    Remote endpoint address.
 * \param source    Source address (or NULL).
 * \param query     Query message.
 * \param creds     Local (server) credentials.
 * \param edns      EDNS parameters.
 * \param tsig_key  TSIG key for authentication.
 * \param pin       Possible remote certificate PIN.
 * \param pin_len   Length of the remote certificate PIN.
 * \param flags     Request flags.
 *
 * \return Prepared request or NULL in case of error.
 */
knot_request_t *knot_request_make_generic(knot_mm_t *mm,
                                          const struct sockaddr_storage *remote,
                                          const struct sockaddr_storage *source,
                                          knot_pkt_t *query,
                                          const struct knot_creds *creds,
                                          const query_edns_data_t *edns,
                                          const knot_tsig_key_t *tsig_key,
                                          const char *hostname,
                                          const uint8_t *pin,
                                          size_t pin_len,
                                          knot_request_flag_t flags);

/*!
 * \brief Make request out of endpoints and query.
 *
 * Similar to knot_request_make_generic() but takes a remote configuration
 * instead of individual remote and key parameters specified.
 */
knot_request_t *knot_request_make(knot_mm_t *mm,
                                  const conf_remote_t *remote,
                                  knot_pkt_t *query,
                                  const struct knot_creds *creds,
                                  const query_edns_data_t *edns,
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
 * \param timeout_ms Timeout of each operation in milliseconds (-1 for infinity).
 *
 * \return KNOT_EOK or error
 */
int knot_requestor_exec(knot_requestor_t *requestor,
                        knot_request_t *request,
                        int timeout_ms);
