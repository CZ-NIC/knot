/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <sys/socket.h>

#include "libknot/attribute.h"
#include "libknot/errcode.h"
#include "libknot/quic/tls.h"
#include "knot/common/unreachable.h"
#include "knot/query/requestor.h"
#ifdef ENABLE_QUIC
#include "knot/query/quic-requestor.h"
#endif // ENABLE_QUIC
#include "contrib/conn_pool.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"

static bool use_tcp(knot_request_t *request)
{
	return (request->flags & (KNOT_REQUEST_UDP | KNOT_REQUEST_QUIC)) == 0;
}

static bool use_quic(knot_request_t *request)
{
	return (request->flags & KNOT_REQUEST_QUIC) != 0;
}

static bool use_tls(knot_request_t *request)
{
	return (request->flags & KNOT_REQUEST_TLS) != 0;
}

static bool is_answer_to_query(const knot_pkt_t *query, const knot_pkt_t *answer)
{
	return knot_wire_get_id(query->wire) == knot_wire_get_id(answer->wire);
}

/*! \brief Ensure a socket is connected. */
static int request_ensure_connected(knot_request_t *request, bool *reused_fd, int timeout_ms)
{
	if (request->fd >= 0) {
		return KNOT_EOK;
	}

	int sock_type = use_tcp(request) ? SOCK_STREAM : SOCK_DGRAM;

	if (sock_type == SOCK_STREAM) {
		request->fd = (int)conn_pool_get(global_conn_pool,
		                                 &request->source,
		                                 &request->remote);
		if (request->fd >= 0) {
			if (reused_fd != NULL) {
				*reused_fd = true;
			}
			return KNOT_EOK;
		}

		if (knot_unreachable_is(global_unreachables, &request->remote,
		                        &request->source)) {
			return KNOT_EUNREACH;
		}
	}

	request->fd = net_connected_socket(sock_type,
	                                   &request->remote,
	                                   &request->source,
	                                   request->flags & KNOT_REQUEST_TFO);
	if (request->fd < 0) {
		if (request->fd == KNOT_ETIMEOUT) {
			knot_unreachable_add(global_unreachables, &request->remote,
			                     &request->source);
		}
		return request->fd;
	}

	if (use_quic(request)) {
		if (request->source.ss_family == AF_UNSPEC) {
			socklen_t local_len = sizeof(request->source);
			(void)getsockname(request->fd, (struct sockaddr *)&request->source,
			                  &local_len);
		}
#ifdef ENABLE_QUIC
		int ret = knot_qreq_connect(&request->quic_ctx, request->fd, &request->remote,
					    &request->source, request->creds, request->hostname,
					    request->pin, request->pin_len, reused_fd, timeout_ms);
		if (ret != KNOT_EOK) {
			close(request->fd);
			request->fd = -1;
			return ret;
		}
#else
		assert(0);
#endif // ENABLE_QUIC
	}

	if (use_tls(request)) {
		assert(!use_quic(request));

		int ret = knot_tls_req_ctx_init(&request->tls_req_ctx, request->fd,
						&request->remote, &request->source, request->creds,
						request->hostname, request->pin, request->pin_len,
						reused_fd, timeout_ms);
		if (ret != KNOT_EOK) {
			close(request->fd);
			request->fd = -1;
			return ret;
		}
	}

	return KNOT_EOK;
}

static int request_send(knot_request_t *request, int timeout_ms, bool *reused_fd)
{
	/* Initiate non-blocking connect if not connected. */
	*reused_fd = false;
	int ret = request_ensure_connected(request, reused_fd, timeout_ms);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Send query, construct if not exists. */
	knot_pkt_t *query = request->query;
	uint8_t *wire = query->wire;
	size_t wire_len = query->size;
	struct sockaddr_storage *tfo_addr = (request->flags & KNOT_REQUEST_TFO) ?
	                                    &request->remote : NULL;

	/* Send query. */
	if (use_tls(request)) {
		ret = knot_tls_send(request->tls_req_ctx.conn, wire, wire_len);
		knot_tls_req_ctx_maint(&request->tls_req_ctx, request);
	} else if (use_quic(request)) {
#ifdef ENABLE_QUIC
		struct iovec tosend = { wire, wire_len };
		return knot_qreq_send(request->quic_ctx, &tosend);
#else
		assert(0);
#endif // ENABLE_QUIC
	} else if (use_tcp(request)) {
		ret = net_dns_tcp_send(request->fd, wire, wire_len, timeout_ms,
		                       tfo_addr);
		if (ret == KNOT_ETIMEOUT) { // Includes establishing conn which times out.
			knot_unreachable_add(global_unreachables, &request->remote,
			                     &request->source);
		}
	} else {
		ret = net_dgram_send(request->fd, wire, wire_len, NULL);
	}
	if (ret < 0) {
		return ret;
	} else if (ret != wire_len) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_recv(knot_request_t *request, int timeout_ms)
{
	knot_pkt_t *resp = request->resp;
	knot_pkt_clear(resp);

	/* Wait for readability */
	int ret = request_ensure_connected(request, NULL, timeout_ms);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Receive it */
	if (use_tls(request)) {
		ret = knot_tls_recv(request->tls_req_ctx.conn, resp->wire, resp->max_size);
		knot_tls_req_ctx_maint(&request->tls_req_ctx, request);
	} else if (use_quic(request)) {
#ifdef ENABLE_QUIC
		struct iovec recvd = { resp->wire, resp->max_size };
		ret = knot_qreq_recv(request->quic_ctx, &recvd, timeout_ms);
		resp->size = recvd.iov_len;
		return ret;
#else
		assert(0);
#endif // ENABLE_QUIC
	} else if (use_tcp(request)) {
		ret = net_dns_tcp_recv(request->fd, resp->wire, resp->max_size, timeout_ms);
	} else {
		ret = net_dgram_recv(request->fd, resp->wire, resp->max_size, timeout_ms);
	}
	if (ret <= 0) {
		resp->size = 0;
		if (ret == 0) {
			return KNOT_ECONN;
		}
		return ret;
	}

	resp->size = ret;
	return ret;
}

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
                                          knot_request_flag_t flags)
{
	if (remote == NULL || query == NULL) {
		return NULL;
	}

	knot_request_t *request = mm_calloc(mm, 1, sizeof(*request) + pin_len);
	if (request == NULL) {
		return NULL;
	}

	request->resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, mm);
	if (request->resp == NULL) {
		mm_free(mm, request);
		return NULL;
	}

	request->query = query;
	request->fd = -1;
	request->flags = flags;
	memcpy(&request->remote, remote, sockaddr_len(remote));
	if (source) {
		memcpy(&request->source, source, sockaddr_len(source));
	} else {
		request->source.ss_family = AF_UNSPEC;
	}

	if (tsig_key && (tsig_key->algorithm == DNSSEC_TSIG_UNKNOWN ||
	                 (flags & KNOT_REQUEST_FWD))) {
		tsig_key = NULL;
	}
	tsig_init(&request->tsig, tsig_key);

	request->edns = edns;
	request->creds = creds;
	if ((flags & (KNOT_REQUEST_QUIC | KNOT_REQUEST_TLS)) && pin_len > 0) {
		request->pin_len = pin_len;
		memcpy(request->pin, pin, pin_len);
	}

	request->hostname = hostname;

	return request;
}

knot_request_t *knot_request_make(knot_mm_t *mm,
                                  const conf_remote_t *remote,
                                  knot_pkt_t *query,
                                  const struct knot_creds *creds,
                                  const query_edns_data_t *edns,
                                  knot_request_flag_t flags)
{
	if (remote->quic) {
		assert(!remote->tls);
		flags |= KNOT_REQUEST_QUIC;
	} else if (remote->tls) {
		flags |= KNOT_REQUEST_TLS;
	}

	// NULL hostname in request signifies no certificate verification (except possibly by PIN)
	const char *hostname = remote->cert_verify ? remote->hostname : NULL;

	return knot_request_make_generic(mm, &remote->addr, &remote->via, query, creds, edns,
					 &remote->key, hostname, remote->pin, remote->pin_len,
					 flags);
}

void knot_request_free(knot_request_t *request, knot_mm_t *mm)
{
	if (request == NULL) {
		return;
	}

	if (use_quic(request)) {
#ifdef ENABLE_QUIC
		if (request->quic_ctx != NULL) {
			knot_qreq_close(request->quic_ctx, true);
		}
		// NOTE synthetic DDNSoQ request is NOOP here
#else
		assert(0);
#endif // ENABLE_QUIC
	} else if (use_tls(request) && request->tls_req_ctx.conn != NULL) {
		knot_tls_req_ctx_deinit(&request->tls_req_ctx);
	} else {
		assert(request->quic_ctx == NULL);
		assert(request->quic_conn == NULL);
		assert(request->tls_req_ctx.ctx == NULL);
		assert(request->tls_req_ctx.conn == NULL);
	}

	if (request->fd >= 0 && use_tcp(request) && !use_tls(request) &&
	    (request->flags & KNOT_REQUEST_KEEP)) {
		request->fd = (int)conn_pool_put(global_conn_pool,
		                                 &request->source,
		                                 &request->remote,
		                                 (conn_pool_fd_t)request->fd);
	}
	if (request->fd >= 0) {
		close(request->fd);
	}
	knot_pkt_free(request->query);
	knot_pkt_free(request->resp);
	dnssec_binary_free(&request->sign.tsig_key.secret);
	tsig_cleanup(&request->tsig);

	mm_free(mm, request);
}

int knot_requestor_init(knot_requestor_t *requestor,
                        const knot_layer_api_t *proc, void *proc_param,
                        knot_mm_t *mm)
{
	if (requestor == NULL || proc == NULL) {
		return KNOT_EINVAL;
	}

	memset(requestor, 0, sizeof(*requestor));

	requestor->mm = mm;
	knot_layer_init(&requestor->layer, mm, proc);
	knot_layer_begin(&requestor->layer, proc_param);

	return KNOT_EOK;
}

void knot_requestor_clear(knot_requestor_t *requestor)
{
	if (requestor == NULL) {
		return;
	}

	knot_layer_finish(&requestor->layer);

	memset(requestor, 0, sizeof(*requestor));
}

static int request_reset(knot_requestor_t *req, knot_request_t *last)
{
	knot_layer_reset(&req->layer);
	tsig_reset(&last->tsig);

	req->layer.flags &= ~KNOT_REQUESTOR_IOFAIL;

	if (req->layer.flags & KNOT_REQUESTOR_CLOSE) {
		req->layer.flags &= ~KNOT_REQUESTOR_CLOSE;
		if (last->fd >= 0) {
			close(last->fd);
			last->fd = -1;
		}
	}

	if (req->layer.state == KNOT_STATE_RESET) {
		return KNOT_EPROCESSING;
	}

	return KNOT_EOK;
}

static int request_produce(knot_requestor_t *req, knot_request_t *last,
                           int timeout_ms)
{
	knot_layer_produce(&req->layer, last->query);

	/* NOTE: it would make more sense to reserve space for TSIG _before_ producing query packet,
	         but layer_produce usually resets the packet including reserved space. */
	int ret = knot_pkt_reserve(last->query, knot_tsig_wire_size(last->tsig.key));
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (last->edns != NULL && !last->edns->no_edns) {
		ret = query_put_edns(last->query, last->edns,
		                     (last->flags & (KNOT_REQUEST_QUIC | KNOT_REQUEST_TLS)));
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	/* NOTE: it's not necessary to reclaim pkt->reserved space for TSIG, as the following function
	         does not use knot_pkt_put to insert it, it just writes at the end of wire. */
	ret = tsig_sign_packet(&last->tsig, last->query);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (req->layer.state == KNOT_STATE_CONSUME) {
		bool reused_fd = false;
		ret = request_send(last, timeout_ms, &reused_fd);
		if (ret != KNOT_EOK) {
			req->layer.flags |= KNOT_REQUESTOR_IOFAIL;
		}
		if (reused_fd) {
			req->layer.flags |= KNOT_REQUESTOR_REUSED;
		}
		if (last->flags & KNOT_REQUEST_QUIC) {
			req->layer.flags |= KNOT_REQUESTOR_QUIC;
		}
		if (last->flags & KNOT_REQUEST_TLS) {
			req->layer.flags |= KNOT_REQUESTOR_TLS;
		}
	}

	return ret;
}

static int request_consume(knot_requestor_t *req, knot_request_t *last,
                           int timeout_ms)
{
	int ret = request_recv(last, timeout_ms);
	if (ret < 0) {
		req->layer.flags |= KNOT_REQUESTOR_IOFAIL;
		return ret;
	}

	ret = knot_pkt_parse(last->resp, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!is_answer_to_query(last->query, last->resp)) {
		return KNOT_EMALF;
	}

	if (knot_wire_get_tc(last->resp->wire)) {
		return KNOT_EFEWDATA;
	}

	ret = tsig_verify_packet(&last->tsig, last->resp);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (tsig_unsigned_count(&last->tsig) >= 100) {
		return KNOT_TSIG_EBADSIG;
	}

	knot_layer_consume(&req->layer, last->resp);

	return KNOT_EOK;
}

static bool layer_active(knot_layer_state_t state)
{
	switch (state) {
	case KNOT_STATE_CONSUME:
	case KNOT_STATE_PRODUCE:
	case KNOT_STATE_RESET:
		return true;
	default:
		return false;
	}
}

static int request_io(knot_requestor_t *req, knot_request_t *last,
                      int timeout_ms)
{
	switch (req->layer.state) {
	case KNOT_STATE_CONSUME:
		return request_consume(req, last, timeout_ms);
	case KNOT_STATE_PRODUCE:
		return request_produce(req, last, timeout_ms);
	case KNOT_STATE_RESET:
		return request_reset(req, last);
	default:
		return KNOT_EINVAL;
	}
}

int knot_requestor_exec(knot_requestor_t *requestor, knot_request_t *request,
                        int timeout_ms)
{
	if (requestor == NULL || request == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	requestor->layer.tsig = &request->tsig;

	/* Do I/O until the processing is satisfied or fails. */
	while (layer_active(requestor->layer.state)) {
		ret = request_io(requestor, request, timeout_ms);
		if (ret != KNOT_EOK) {
			knot_layer_finish(&requestor->layer);
			return ret;
		}
	}

	/* Expect complete request. */
	switch (requestor->layer.state) {
	case KNOT_STATE_DONE:
		request->flags |= KNOT_REQUEST_KEEP;
		break;
	case KNOT_STATE_IGNORE:
		ret = KNOT_ERROR;
		break;
	default:
		ret = KNOT_EPROCESSING;
	}

	/* Verify last TSIG */
	if (tsig_unsigned_count(&request->tsig) != 0) {
		ret = KNOT_TSIG_EBADSIG;
	}

	/* Finish current query processing. */
	knot_layer_finish(&requestor->layer);

	return ret;
}
