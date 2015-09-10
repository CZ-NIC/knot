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

#include <assert.h>

#include "libknot/processing/requestor.h"
#include "libknot/errcode.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/net.h"

static bool use_tcp(struct knot_request *request)
{
	return (request->flags & KNOT_RQ_UDP) == 0;
}

static struct knot_request *request_make(mm_ctx_t *mm)
{
	struct knot_request *request = mm_alloc(mm, sizeof(*request));
	if (request == NULL) {
		return NULL;
	}

	memset(request, 0, sizeof(*request));

	return request;
}

/*! \brief Ensure a socket is connected. */
static int request_ensure_connected(struct knot_request *request)
{
	/* Connect the socket if not already connected. */
	if (request->fd < 0) {
		int sock_type = use_tcp(request) ? SOCK_STREAM : SOCK_DGRAM;
		request->fd = net_connected_socket(sock_type, &request->remote,
		                                   &request->origin);
		if (request->fd < 0) {
			return KNOT_ECONN;
		}
	}

	return KNOT_EOK;
}

static int request_send(struct knot_request *request,
                        const struct timeval *timeout)
{
	/* Each request has unique timeout. */
	struct timeval tv = *timeout;

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
		ret = tcp_send_msg(request->fd, wire, wire_len, &tv);
	} else {
		ret = udp_send_msg(request->fd, wire, wire_len, NULL);
	}
	if (ret != wire_len) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_recv(struct knot_request *request,
                        const struct timeval *timeout)
{
	knot_pkt_t *resp = request->resp;
	knot_pkt_clear(resp);

	/* Wait for readability */
	int ret = request_ensure_connected(request);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Each request has unique timeout. */
	struct timeval tv = *timeout;

	/* Receive it */
	if (use_tcp(request)) {
		ret = tcp_recv_msg(request->fd, resp->wire, resp->max_size, &tv);
	} else {
		ret = udp_recv_msg(request->fd, resp->wire, resp->max_size, &tv);
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

_public_
struct knot_request *knot_request_make(mm_ctx_t *mm,
                                       const struct sockaddr *dst,
                                       const struct sockaddr *src,
                                       knot_pkt_t *query,
                                       unsigned flags)
{
	if (dst == NULL || query == NULL) {
		return NULL;
	}

	/* Form a pending request. */
	struct knot_request *request = request_make(mm);
	if (request == NULL) {
		return NULL;
	}

	memcpy(&request->remote, dst, sockaddr_len(dst));
	if (src) {
		memcpy(&request->origin, src, sockaddr_len(src));
	} else {
		request->origin.ss_family = AF_UNSPEC;
	}

	request->fd = -1;
	request->query = query;
	request->resp  = NULL;
	request->flags = flags;
	return request;
}

_public_
int knot_request_free(mm_ctx_t *mm, struct knot_request *request)
{
	if (request == NULL) {
		return KNOT_EINVAL;
	}

	if (request->fd >= 0) {
		close(request->fd);
	}
	knot_pkt_free(&request->query);
	knot_pkt_free(&request->resp);

	rem_node(&request->node);
	mm_free(mm, request);

	return KNOT_EOK;
}

_public_
void knot_requestor_init(struct knot_requestor *requestor, mm_ctx_t *mm)
{
	if (requestor == NULL) {
		return;
	}

	memset(requestor, 0, sizeof(*requestor));
	requestor->mm = mm;
	init_list(&requestor->pending);
	knot_overlay_init(&requestor->overlay, mm);
}

_public_
void knot_requestor_clear(struct knot_requestor *requestor)
{
	if (requestor == NULL) {
		return;
	}

	while (knot_requestor_dequeue(requestor) == KNOT_EOK)
		;

	knot_overlay_finish(&requestor->overlay);
	knot_overlay_deinit(&requestor->overlay);
}

_public_
bool knot_requestor_finished(struct knot_requestor *requestor)
{
	return requestor == NULL || EMPTY_LIST(requestor->pending);
}

_public_
int knot_requestor_overlay(struct knot_requestor *requestor,
                           const knot_layer_api_t *proc, void *param)
{
	if (requestor == NULL) {
		return KNOT_EINVAL;
	}

	return knot_overlay_add(&requestor->overlay, proc, param);
}

_public_
int knot_requestor_enqueue(struct knot_requestor *requestor,
                           struct knot_request *request)
{
	if (requestor == NULL || request == NULL) {
		return KNOT_EINVAL;
	}

	/* Socket must be uninitialized. */
	assert(request->fd == -1);

	/* Prepare response buffers. */
	request->resp = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, requestor->mm);
	if (request->resp == NULL) {
		mm_free(requestor->mm, request);
		return KNOT_ENOMEM;
	}

	add_tail(&requestor->pending, &request->node);

	return KNOT_EOK;
}

_public_
int knot_requestor_dequeue(struct knot_requestor *requestor)
{
	if (requestor == NULL) {
		return KNOT_EINVAL;
	}

	if (knot_requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	struct knot_request *last = HEAD(requestor->pending);
	return knot_request_free(requestor->mm, last);
}

static int request_io(struct knot_requestor *req, struct knot_request *last,
                      struct timeval *timeout)
{
	int ret = KNOT_EOK;
	knot_pkt_t *query = last->query;
	knot_pkt_t *resp = last->resp;

	/* Data to be sent. */
	if (req->overlay.state == KNOT_STATE_PRODUCE) {

		/* Process query and send it out. */
		knot_overlay_produce(&req->overlay, query);

		if (req->overlay.state == KNOT_STATE_CONSUME) {
			ret = request_send(last, timeout);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	/* Data to be read. */
	if (req->overlay.state == KNOT_STATE_CONSUME) {
		/* Read answer and process it. */
		ret = request_recv(last, timeout);
		if (ret < 0) {
			return ret;
		}

		(void) knot_pkt_parse(resp, 0);
		knot_overlay_consume(&req->overlay, resp);
	}

	return KNOT_EOK;
}

static int exec_request(struct knot_requestor *req, struct knot_request *last,
                        struct timeval *timeout)
{
	int ret = KNOT_EOK;

	/* Do I/O until the processing is satisifed or fails. */
	while (req->overlay.state & (KNOT_STATE_PRODUCE|KNOT_STATE_CONSUME)) {
		ret = request_io(req, last, timeout);
		if (ret != KNOT_EOK) {
			knot_overlay_reset(&req->overlay);
			return ret;
		}
	}

	/* Expect complete request. */
	if (req->overlay.state != KNOT_STATE_DONE) {
		ret = KNOT_LAYER_ERROR;
	}

	/* Finish current query processing. */
	knot_overlay_reset(&req->overlay);

	return ret;
}

_public_
int knot_requestor_exec(struct knot_requestor *requestor,
                        struct timeval *timeout)
{
	if (knot_requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	/* Execute next request. */
	int ret = exec_request(requestor, HEAD(requestor->pending), timeout);

	/* Remove it from processing. */
	knot_requestor_dequeue(requestor);

	return ret;
}
