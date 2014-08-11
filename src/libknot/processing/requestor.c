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
#include <sys/fcntl.h>

#include "libknot/common.h"
#include "libknot/processing/requestor.h"
#include "libknot/packet/net.h"

/*! \brief Single pending request. */
struct knot_request {
	struct knot_request_data data; /*!< Request data. */
	int state;                /*!< Processing state. */
	knot_process_t process;   /*!< Response processor. */
	uint8_t *pkt_buf;         /*!< Buffers. */
};

static bool use_tcp(struct knot_request *request)
{
	return !(request->data.flags & KNOT_RQ_UDP);
}

static struct knot_request *request_make(mm_ctx_t *mm)
{
	struct knot_request *request = mm_alloc(mm, sizeof(struct knot_request));
	if (request == NULL) {
		return NULL;
	}

	memset(request, 0, sizeof(struct knot_request));

	request->pkt_buf = mm_alloc(mm, KNOT_WIRE_MAX_PKTSIZE);
	if (request->pkt_buf == NULL) {
		mm_free(mm, request);
		request = NULL;
	}

	return request;
}

static int request_close(mm_ctx_t *mm, struct knot_request *request)
{
	/* Reset processing if didn't complete. */
	if (request->state != NS_PROC_DONE) {
		knot_process_reset(&request->process);
	}

	knot_process_finish(&request->process);

	rem_node(&request->data.node);
	close(request->data.fd);
	knot_pkt_free(&request->data.query);
	mm_free(mm, request->pkt_buf);
	mm_free(mm, request);

	return KNOT_EOK;
}

/*! \brief Wait for socket readiness. */
static int request_wait(int fd, int state, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);

	switch(state) {
	case NS_PROC_FULL: /* Wait for writeability. */
		return select(fd + 1, NULL, &set, NULL, timeout);
	case NS_PROC_MORE: /* Wait for data. */
		return select(fd + 1, &set, NULL, NULL, timeout);
	default:
		return -1;
	}
}

static int request_send(struct knot_request *request, const struct timeval *timeout)
{
	/* Each request has unique timeout. */
	struct timeval tv = { timeout->tv_sec, timeout->tv_usec };

	/* Wait for writeability or error. */
	int ret = request_wait(request->data.fd, NS_PROC_FULL, &tv);
	if (ret == 0) {
		return KNOT_ETIMEOUT;
	}

	/* Check socket error. */
	int err = 0;
	socklen_t len = sizeof(int);
	getsockopt(request->data.fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err != 0) {
		return KNOT_ECONNREFUSED;
	}

	/* Send query, construct if not exists. */
	knot_pkt_t *query = request->data.query;
	uint8_t *wire = request->pkt_buf;
	uint16_t wire_len = KNOT_WIRE_MAX_PKTSIZE;
	if (query) {
		wire = query->wire;
		wire_len = query->size;
	} else {
		request->state = knot_process_out(&request->process, wire, &wire_len);
	}

	/* Send query. */
	if (use_tcp(request)) {
		ret = tcp_send_msg(request->data.fd, wire, wire_len);
	} else {
		ret = udp_send_msg(request->data.fd, wire, wire_len,
		                   (const struct sockaddr *)&request->data.remote);
	}
	if (ret != wire_len) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_recv(struct knot_request *request, const struct timeval *timeout)
{
	/* Each request has unique timeout. */
	struct timeval tv = { timeout->tv_sec, timeout->tv_usec };

	/* Receive it */
	int ret = 0;
	if (use_tcp(request)) {
		ret = tcp_recv_msg(request->data.fd, request->pkt_buf,
		                   KNOT_WIRE_MAX_PKTSIZE, &tv);
	} else {
		ret = udp_recv_msg(request->data.fd, request->pkt_buf,
		                   KNOT_WIRE_MAX_PKTSIZE,
		                   (struct sockaddr *)&request->data.remote);

	}
	if (ret < 0) {
		return ret;
	}

	return ret;
}

void knot_requestor_init(struct knot_requestor *requestor, const knot_process_module_t *module,
                         mm_ctx_t *mm)
{
	memset(requestor, 0, sizeof(struct knot_requestor));
	requestor->module = module;
	requestor->mm = mm;
	init_list(&requestor->pending);
}

void knot_requestor_clear(struct knot_requestor *requestor)
{
	while (knot_requestor_dequeue(requestor) == KNOT_EOK)
		;
}

bool knot_requestor_finished(struct knot_requestor *requestor)
{
	return requestor == NULL || EMPTY_LIST(requestor->pending);
}

struct knot_request *knot_requestor_make(struct knot_requestor *requestor,
                               const struct sockaddr *dst,
                               const struct sockaddr *src,
                               knot_pkt_t *query,
                               unsigned flags)
{
	if (requestor == NULL || dst == NULL) {
		return NULL;
	}

	/* Form a pending request. */
	struct knot_request *request = request_make(requestor->mm);
	if (request == NULL) {
		return NULL;
	}

	memcpy(&request->data.remote, dst, sockaddr_len(dst));
	if (src) {
		memcpy(&request->data.origin, src, sockaddr_len(src));
	}

	request->state = NS_PROC_DONE;
	request->data.fd = -1;
	request->data.query = query;
	request->data.flags = flags;
	return request;
}

int knot_requestor_enqueue(struct knot_requestor *requestor, struct knot_request *request, void *param)
{
	if (requestor == NULL || request == NULL) {
		return KNOT_EINVAL;
	}

	/* Determine comm protocol. */
	int sock_type = SOCK_DGRAM;
	if (use_tcp(request)) {
		sock_type = SOCK_STREAM;
	}

	/* Fetch a bound socket. */
	int fd = net_connected_socket(sock_type, &request->data.remote,
	                              &request->data.origin, O_NONBLOCK);
	if (fd < 0) {
		return KNOT_ECONN;
	}

	/* Form a pending request. */
	request->data.fd = fd;
	request->process.mm = requestor->mm;
	request->state = knot_process_begin(&request->process, param, requestor->module);

	/* We have a query to be sent. */
	if (request->data.query) {
		request->state = NS_PROC_FULL;
	}

	add_tail(&requestor->pending, &request->data.node);

	return KNOT_EOK;
}

int knot_requestor_dequeue(struct knot_requestor *requestor)
{
	if (knot_requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	struct knot_request *last = HEAD(requestor->pending);
	return request_close(requestor->mm, last);
}

static int exec_request(struct knot_request *last, struct timeval *timeout)
{
	int ret = KNOT_EOK;

	/* Process any pending data. */
	if (last->state == NS_PROC_FULL) {
		ret = request_send(last, timeout);
		if (ret != KNOT_EOK) {
			return ret;
		}
		last->state = NS_PROC_MORE; /* Await response. */
	}

	/* Receive and process expected answers. */
	while (last->state == NS_PROC_MORE) {
		int rcvd = request_recv(last, timeout);
		if (rcvd < 0) {
			return rcvd;
		}

		last->state = knot_process_in(&last->process, last->pkt_buf, rcvd);
	}

	/* Expect complete request. */
	if (last->state != NS_PROC_DONE) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int knot_requestor_exec(struct knot_requestor *requestor, struct timeval *timeout)
{
	if (knot_requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	/* Execute next request. */
	int ret = exec_request(HEAD(requestor->pending), timeout);

	/* Remove it from processing. */
	knot_requestor_dequeue(requestor);

	return ret;
}
