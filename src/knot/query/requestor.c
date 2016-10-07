/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <poll.h>

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

/*
 * Returns KNOT_EOK, a negative error code or a positive poll() event mask.
 */
static int request_tcp_send_nonblocking(struct knot_request *request)
{
	struct msghdr *msg = &request->msg;

	if (msg->msg_iov == NULL) {
		request->pktsize = htons(request->query->size);
		request->iov[0].iov_base = &request->pktsize;
		request->iov[0].iov_len = sizeof(request->pktsize);
		request->iov[1].iov_base = request->query->wire;
		request->iov[1].iov_len = request->query->size;
		msg->msg_iov = request->iov;
		msg->msg_iovlen = 2;
	}

	int len = net_send_nonblocking(request->fd, msg);
	if (len < 0) return len;

	if (msg->msg_iovlen != 0) {
		/* Request re-invocation. */
		return POLLOUT;
	}

	/* Mark the msg as unused. */
	msg->msg_iov = NULL;

	return KNOT_EOK;
}

/*
 * Returns KNOT_EOK, a negative error code or a positive poll() event mask.
 */
static int request_send_nonblocking(struct knot_request *request)
{
	/* Initiate non-blocking connect if not connected. */
	int ret = request_ensure_connected(request);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Send query. */
	if (use_tcp(request)) {
		ret = request_tcp_send_nonblocking(request);
		if (ret < 0) {
			return KNOT_ECONN;
		}
	} else {
		ret = net_dgram_send(request->fd, request->query->wire,
		                     request->query->size, NULL);
		if (ret != request->query->size) {
			return KNOT_ECONN;
		}
		return KNOT_EOK;
	}

	return ret;
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

/*
 * Returns KNOT_EOK, a negative error or a poll() event mask.
 */
static int request_tcp_recv_nonblocking(struct knot_request *request)
{
	struct msghdr *msg = &request->msg;

	if (msg->msg_iov == NULL) {
		knot_pkt_clear(request->resp);
		request->iov[0].iov_base = &request->pktsize;
		request->iov[0].iov_len = sizeof(request->pktsize);
		msg->msg_iov = request->iov;
		msg->msg_iovlen = 1;
		return POLLIN;
	}

	if (request->iov[0].iov_base == &request->pktsize) {
		/* Read the packet size. */
		ssize_t len = net_recv_nonblocking(request->fd, msg);
		if (len < 0) return len;

		if (msg->msg_iovlen == 0) {
			uint16_t pktsize = ntohs(request->pktsize);
			if (request->resp->max_size < pktsize) {
				return KNOT_ESPACE;
			}

			/* Begin reading the packet data. */
			request->iov[0].iov_base = request->resp->wire;
			request->iov[0].iov_len = pktsize;
			msg->msg_iovlen = 1;
		}

		/* Request re-invocation. */
		return POLLIN;
	} else {
		// Read the packet data
		ssize_t len = net_recv_nonblocking(request->fd, msg);
		if (len < 0) return len;

		request->resp->size += len;

		if (msg->msg_iovlen > 0) {
			/* Request re-invocation. */
			return POLLIN;
		}
	}

	return KNOT_EOK;
}

/*
 * Returns KNOT_EOK, a negative error or a poll() event mask.
 */
static int request_recv_nonblocking(struct knot_request *request)
{
	/* Wait for readability */
	int ret = request_ensure_connected(request);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Receive it */
	if (use_tcp(request)) {
		ret = request_tcp_recv_nonblocking(request);
		if (ret < 0) {
			return KNOT_ECONN;
		}
		return ret;
	}

	/* Receive a UDP datagram */
	knot_pkt_t *resp = request->resp;
	knot_pkt_clear(resp);
	ret = recv(request->fd, resp->wire, resp->max_size, 0);
	if (ret < 0) {
		return KNOT_ECONN;
	}

	resp->size = ret;
	return KNOT_EOK;
}

struct knot_request *knot_request_make(knot_mm_t *mm,
                                       const struct sockaddr *remote,
                                       const struct sockaddr *source,
                                       knot_pkt_t *query,
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
	requestor->layer.state = knot_layer_begin(&requestor->layer, proc_param);

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

static int request_io(struct knot_requestor *req, struct knot_request *last,
                      int timeout_ms)
{
	int ret = KNOT_EOK;
	knot_pkt_t *query = last->query;
	knot_pkt_t *resp = last->resp;

	/* Data to be sent. */
	if (req->layer.state == KNOT_STATE_PRODUCE) {

		/* Process query and send it out. */
		knot_layer_produce(&req->layer, query);

		if (req->layer.state == KNOT_STATE_CONSUME) {
			ret = request_send(last, timeout_ms);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	/* Data to be read. */
	if (req->layer.state == KNOT_STATE_CONSUME) {
		/* Read answer and process it. */
		ret = request_recv(last, timeout_ms);
		if (ret < 0) {
			return ret;
		}

		(void) knot_pkt_parse(resp, 0);
		knot_layer_consume(&req->layer, resp);
	}

	return KNOT_EOK;
}

/*
 * Returns KNOT_EOK or a negative error.
 */
static int request_io_nonblocking(struct knot_requestor *req,
                                  struct knot_request *last)
{
	knot_pkt_t *query = last->query;
	knot_pkt_t *resp = last->resp;

	/* Data to be sent. */
	if (req->layer.state == KNOT_STATE_PRODUCE) {

		/* Process query and send it out. */
		knot_layer_produce_nonblocking(&req->layer, query);
		if (req->layer.defer_fd.fd) return KNOT_EOK;

		if (req->layer.state == KNOT_STATE_CONSUME) {
			int ret = request_send_nonblocking(last);
			if (ret < 0) {
				return ret;
			}

			if (ret > 0) {
				// Instruct the caller to wait on the fd
				req->layer.defer_fd.fd = last->fd;
				req->layer.defer_fd.events = ret;
				return KNOT_EOK;
			}

			// Instruct the caller to wait for the response
			req->layer.defer_fd.fd = last->fd;
			req->layer.defer_fd.events = POLLIN;
			return KNOT_EOK;
		}
	}

	/* Data to be read. */
	if (req->layer.state == KNOT_STATE_CONSUME) {
		/* Read answer and process it. */
		int ret = request_recv_nonblocking(last);
		if (ret < 0) {
			return ret;
		}
		if (ret > 0) {
			req->layer.defer_fd.fd = last->fd;
			req->layer.defer_fd.events = ret;
			return KNOT_EOK;
		}

		(void) knot_pkt_parse(resp, 0);
		knot_layer_consume(&req->layer, resp);
		req->layer.defer_fd.fd = 0;
	}

	return KNOT_EOK;
}

int knot_requestor_exec(struct knot_requestor *requestor,
                        struct knot_request *request,
                        int timeout_ms)
{
	if (!requestor || !request) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Do I/O until the processing is satisifed or fails. */
	while (requestor->layer.state & (KNOT_STATE_PRODUCE|KNOT_STATE_CONSUME)) {
		ret = request_io(requestor, request, timeout_ms);
		if (ret != KNOT_EOK) {
			knot_layer_reset(&requestor->layer);
			return ret;
		}
	}

	/* Expect complete request. */
	if (requestor->layer.state != KNOT_STATE_DONE) {
		ret = KNOT_LAYER_ERROR;
	}

	/* Finish current query processing. */
	knot_layer_reset(&requestor->layer);

	return ret;
}

/*
 * Returns KNOT_EOK or a negative error code.
 */
int knot_requestor_exec_nonblocking(struct knot_requestor *requestor,
                                    struct knot_request *request)
{
	if (!requestor || !request) {
		return KNOT_EINVAL;
	}

	/* Do I/O until the processing is satisfied or fails. */
	while (requestor->layer.state & (KNOT_STATE_PRODUCE|KNOT_STATE_CONSUME)) {
		int ret = request_io_nonblocking(requestor, request);
		if (ret < 0) {
			knot_layer_reset(&requestor->layer);
			return ret;
		}
		if (requestor->layer.defer_fd.fd) {
			/* Request re-invocation. */
			return KNOT_EOK;
		}
	}

	int ret = KNOT_EOK;

	/* Expect complete request. */
	if (requestor->layer.state != KNOT_STATE_DONE) {
		ret = KNOT_LAYER_ERROR;
	}

	/* Finish current query processing. */
	knot_layer_reset(&requestor->layer);

	return ret;
}
