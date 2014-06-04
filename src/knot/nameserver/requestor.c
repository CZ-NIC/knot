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

#include "knot/nameserver/requestor.h"
#include "knot/nameserver/process_answer.h"
#include "knot/server/net.h"
#include "knot/server/tcp-handler.h"

/*! \brief Single pending request. */
struct request {
	struct request_data data; /*!< Request data. */
	int state;                /*!< Processing state. */
	knot_process_t process;   /*!< Response processor. */
	uint8_t *pkt_buf;         /*!< Buffers. */
};

static struct request *request_make(mm_ctx_t *mm)
{
	struct request *request = mm_alloc(mm, sizeof(struct request));
	if (request == NULL) {
		return NULL;
	}

	memset(request, 0, sizeof(struct request));

	request->pkt_buf = mm_alloc(mm, KNOT_WIRE_MAX_PKTSIZE);
	if (request->pkt_buf == NULL) {
		mm_free(mm, request);
		request = NULL;
	}

	return request;
}

static int request_close(mm_ctx_t *mm, struct request *request)
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

static int request_send(struct request *request, const struct timeval *timeout)
{
	/* Each request has unique timeout. */
	struct timeval tv = { timeout->tv_sec, timeout->tv_usec };

	/* Wait for writeability or error. */
	int ret = request_wait(request->data.fd, NS_PROC_FULL, &tv);
	if (ret == 0) {
		return KNOT_EAGAIN;
	}

	/* Check socket error. */
	int err = 0;
	socklen_t len = sizeof(int);
	getsockopt(request->data.fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err != 0) {
		return KNOT_ECONNREFUSED;
	}

	/* Send query. */
	knot_pkt_t *query = request->data.query;
	ret = tcp_send_msg(request->data.fd, query->wire, query->size);
	if (ret != query->size) {
		return KNOT_ECONN;
	}

	return KNOT_EOK;
}

static int request_recv(struct request *request, const struct timeval *timeout)
{
	/* Each request has unique timeout. */
	struct timeval tv = { timeout->tv_sec, timeout->tv_usec };

	/* Receive it */
	int ret = tcp_recv_msg(request->data.fd, request->pkt_buf,
	                       KNOT_WIRE_MAX_PKTSIZE, &tv);
	if (ret < 0) {
		return ret;
	}

	return ret;
}

void requestor_init(struct requestor *requestor, const knot_process_module_t *module,
                    mm_ctx_t *mm)
{
	memset(requestor, 0, sizeof(struct requestor));
	requestor->module = module;
	requestor->mm = mm;
	init_list(&requestor->pending);
}

void requestor_clear(struct requestor *requestor)
{
	while (requestor_dequeue(requestor) == KNOT_EOK)
		;
}

bool requestor_finished(struct requestor *requestor)
{
	return requestor == NULL || EMPTY_LIST(requestor->pending);
}

struct request *requestor_make(struct requestor *requestor,
                               const conf_iface_t *remote,
                               knot_pkt_t *query)
{
	if (requestor == NULL || query == NULL || remote == NULL) {
		return NULL;
	}

	/* Form a pending request. */
	struct request *request = request_make(requestor->mm);
	if (request == NULL) {
		return NULL;
	}

	memcpy(&request->data.origin, &remote->via, sizeof(remote->via));
	memcpy(&request->data.remote, &remote->addr, sizeof(remote->addr));

	request->state = NS_PROC_DONE;
	request->data.fd = -1;
	request->data.query = query;
	return request;
}

int requestor_enqueue(struct requestor *requestor, struct request *request, void *param)
{
	if (requestor == NULL || request == NULL) {
		return KNOT_EINVAL;
	}

	/* Fetch a bound socket. */
	int fd = net_connected_socket(SOCK_STREAM, &request->data.remote,
	                              &request->data.origin, O_NONBLOCK);
	if (fd < 0) {
		return KNOT_ECONN;
	}

	/* Form a pending request. */
	request->data.fd = fd;
	request->state = NS_PROC_FULL; /* We have a query to be sent. */
	memcpy(&request->process.mm, requestor->mm, sizeof(mm_ctx_t));

	knot_process_begin(&request->process, param, requestor->module);

	add_tail(&requestor->pending, &request->data.node);

	return KNOT_EOK;
}

int requestor_dequeue(struct requestor *requestor)
{
	if (requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	struct request *last = HEAD(requestor->pending);
	return request_close(requestor->mm, last);
}

static int exec_request(struct request *last, struct timeval *timeout)
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

		last->state = knot_process_in(last->pkt_buf, rcvd, &last->process);
	}

	/* Expect complete request. */
	if (last->state != NS_PROC_DONE) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int requestor_exec(struct requestor *requestor, struct timeval *timeout)
{
	if (requestor_finished(requestor)) {
		return KNOT_ENOENT;
	}

	/* Execute next request. */
	int ret = exec_request(HEAD(requestor->pending), timeout);

	/* Remove it from processing. */
	requestor_dequeue(requestor);

	return ret;
}
