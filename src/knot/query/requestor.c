/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>

#include "libknot/attribute.h"
#include "knot/query/requestor.h"
#include "libknot/errcode.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"

static bool use_tcp(struct knot_request *request)
{
	return (request->flags & KNOT_RQ_UDP) == 0;
}

static bool is_answer_to_query(const knot_pkt_t *query, const knot_pkt_t *answer)
{
	return knot_wire_get_id(query->wire) == knot_wire_get_id(answer->wire);
}

/*! \brief Ensure a socket is connected. */
static int request_ensure_connected(struct knot_request *request)
{
	if (request->fd >= 0) {
		return KNOT_EOK;
	}

	int sock_type = use_tcp(request) ? SOCK_STREAM : SOCK_DGRAM;
	request->fd = net_connected_socket(sock_type,
	                                  (struct sockaddr *)&request->remote,
	                                  (struct sockaddr *)&request->source);
	if (request->fd < 0) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_send(struct knot_request *request, int timeout_ms)
{
	/* Initiate non-blocking connect if not connected. */
	int ret = request_ensure_connected(request);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Send query, construct if not exists. */
	knot_pkt_t *query = request->query;
	uint8_t *wire = query->wire;
	size_t wire_len = query->size;

	/* Send query. */
	if (use_tcp(request)) {
		ret = net_dns_tcp_send(request->fd, wire, wire_len, timeout_ms);
	} else {
		ret = net_dgram_send(request->fd, wire, wire_len, NULL);
	}
	if (ret != wire_len) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_recv(struct knot_request *request, int timeout_ms)
{
	knot_pkt_t *resp = request->resp;
	knot_pkt_clear(resp);

	/* Wait for readability */
	int ret = request_ensure_connected(request);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Receive it */
	if (use_tcp(request)) {
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

struct knot_request *knot_request_make(knot_mm_t *mm,
                                       const struct sockaddr *remote,
                                       const struct sockaddr *source,
                                       knot_pkt_t *query,
                                       const knot_tsig_key_t *tsig_key,
                                       unsigned flags)
{
	if (remote == NULL || query == NULL) {
		return NULL;
	}

	struct knot_request *request = mm_alloc(mm, sizeof(*request));
	if (request == NULL) {
		return NULL;
	}
	memset(request, 0, sizeof(*request));

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

	if (tsig_key && tsig_key->algorithm == DNSSEC_TSIG_UNKNOWN) {
		tsig_key = NULL;
	}
	tsig_init(&request->tsig, tsig_key);

	return request;
}

void knot_request_free(struct knot_request *request, knot_mm_t *mm)
{
	if (request == NULL) {
		return;
	}

	if (request->fd >= 0) {
		close(request->fd);
	}
	knot_pkt_free(&request->query);
	knot_pkt_free(&request->resp);
	tsig_cleanup(&request->tsig);

	mm_free(mm, request);
}

int knot_requestor_init(struct knot_requestor *requestor,
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

void knot_requestor_clear(struct knot_requestor *requestor)
{
	if (requestor == NULL) {
		return;
	}

	knot_layer_finish(&requestor->layer);

	memset(requestor, 0, sizeof(*requestor));
}

static int request_reset(struct knot_requestor *req,
                         struct knot_request *last)
{
	knot_layer_reset(&req->layer);
	tsig_reset(&last->tsig);

	if (req->layer.flags & KNOT_RQ_LAYER_CLOSE) {
		req->layer.flags &= ~KNOT_RQ_LAYER_CLOSE;
		if (last->fd >= 0) {
			close(last->fd);
			last->fd = -1;
		}
	}

	if (req->layer.state == KNOT_STATE_RESET) {
		return KNOT_LAYER_ERROR;
	}

	return KNOT_EOK;
}

static int request_produce(struct knot_requestor *req,
                           struct knot_request *last,
                           int timeout_ms)
{
	knot_layer_produce(&req->layer, last->query);

	int ret = tsig_sign_packet(&last->tsig, last->query);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// TODO: verify condition
	if (req->layer.state == KNOT_STATE_CONSUME) {
		ret = request_send(last, timeout_ms);
	}

	return ret;
}

static int request_consume(struct knot_requestor *req,
                           struct knot_request *last,
                           int timeout_ms)
{
	int ret = request_recv(last, timeout_ms);
	if (ret < 0) {
		return ret;
	}

	ret = knot_pkt_parse(last->resp, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!is_answer_to_query(last->query, last->resp)) {
		return KNOT_EMALF;
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

static int request_io(struct knot_requestor *req, struct knot_request *last,
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

int knot_requestor_exec(struct knot_requestor *requestor,
                        struct knot_request *request,
                        int timeout_ms)
{
	if (!requestor || !request) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	requestor->layer.tsig = &request->tsig;

	/* Do I/O until the processing is satisifed or fails. */
	while (layer_active(requestor->layer.state)) {
		ret = request_io(requestor, request, timeout_ms);
		if (ret != KNOT_EOK) {
			knot_layer_finish(&requestor->layer);
			return ret;
		}
	}

	/* Expect complete request. */
	if (requestor->layer.state != KNOT_STATE_DONE) {
		ret = KNOT_LAYER_ERROR;
	}

	/* Verify last TSIG */
	if (tsig_unsigned_count(&request->tsig) != 0) {
		ret = KNOT_TSIG_EBADSIG;
	}

	/* Finish current query processing. */
	knot_layer_finish(&requestor->layer);

	return ret;
}
