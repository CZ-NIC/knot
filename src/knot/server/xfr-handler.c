#include <config.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "knot/common.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/other/error.h"
#include "knot/server/socket.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-in.h"

/*!
 * \brief XFR-IN event handler function.
 *
 * Handle single XFR client event.
 *
 * \param pool Associated connection pool.
 * \param fd Associated socket.
 * \param data Associated data.
 * \param qbuf Buffer for a query wireformat.
 * \param qbuf_maxlen Buffer maximum size.
 */
static inline int xfr_client_ev(struct tcp_pool_t *pool, int fd, void *data,
				uint8_t *qbuf, size_t qbuf_maxlen)
{
	/* Check data. */
	ns_xfr_t *request = (ns_xfr_t *)data;
	if (!request) {
		return KNOT_EINVAL;
	}

	/* Read DNS/TCP packet. */
	int ret = tcp_recv(fd, qbuf, qbuf_maxlen, 0);
	if (ret <= 0) {
		return KNOT_ERROR;
	}

	/* Update xfer state. */
	request->wire = qbuf;
	request->wire_size = ret;

	/* Process incoming packet. */
	server_t *server = tcp_pool_server(pool);
	switch(request->type) {
	case NS_XFR_TYPE_AIN:
		ret = ns_process_axfrin(server->nameserver, request);
		break;
	case NS_XFR_TYPE_IIN:
		ret = ns_process_ixfrin(server->nameserver, request);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* Check return code for errors. */
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check finished zone. */
	if (request->zone) {

		/* Save finished zone and reload. */
		xfrin_zone_transferred(server->nameserver, request->zone);
	}

	return ret;
}

/*
 * Public APIs.
 */

xfrhandler_t *xfr_create(size_t thrcount, ns_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (!data) {
		return 0;
	}
	data->ns = ns;

	/* Create event queue. */
	data->q = evqueue_new();
	if (!data->q) {
		free(data);
		return 0;
	}

	/* Create TCP pool. */
	data->xfer_pool = tcp_pool_new(ns->server, xfr_client_ev);
	if (!data->xfer_pool) {
		evqueue_free(&data->q);
		free(data);
		return 0;
	}

	/* Create threading unit. */
	dt_unit_t *unit = 0;
	unit = dt_create_coherent(thrcount, &xfr_master, (void*)data);
	if (!unit) {
		tcp_pool_del(&data->xfer_pool);
		evqueue_free(&data->q);
		free(data);
		return 0;
	}
	data->unit = unit;
	dt_repurpose(unit->threads[0], &xfr_client, data->xfer_pool);

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOT_EINVAL;
	}

	/* Remove handler data. */
	evqueue_free(&handler->q);

	/* Delete TCP pool. */
	tcp_pool_del(&handler->xfer_pool);

	/* Delete unit. */
	dt_delete(&handler->unit);
	free(handler);

	return KNOT_EOK;
}

int xfr_request(xfrhandler_t *handler, ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOT_EINVAL;
	}

	int ret = evqueue_write(handler->q, req, sizeof(ns_xfr_t));
	if (ret < 0) {
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

int xfr_client_start(xfrhandler_t *handler, ns_xfr_t *req)
{
	/* Check handler. */
	if (!handler || !req) {
		return KNOT_EINVAL;
	}

	/* Fetch associated zone. */
	dnslib_zone_t *zone = (dnslib_zone_t *)req->data;
	if (!zone) {
		return KNOT_EINVAL;
	}
	const dnslib_node_t *apex = dnslib_zone_apex(zone);
	const dnslib_dname_t *dname = dnslib_node_owner(apex);

	/* Connect to remote. */
	if (req->session <= 0) {
		int fd = socket_create(req->addr.family, SOCK_STREAM);
		if (fd < 0) {
			return fd;
		}
		int ret = connect(fd, req->addr.ptr, req->addr.len);
		if (ret < 0) {
			return KNOT_ECONNREFUSED;
		}

		/* Store new socket descriptor. */
		req->session = fd;
	} else {
		/* Duplicate existing socket descriptor. */
		req->session = dup(req->session);
	}

	/* Create XFR query. */
	int ret = KNOT_ERROR;
	size_t bufsize = req->wire_size;
	switch(req->type) {
	case NS_XFR_TYPE_AIN:
		ret = xfrin_create_axfr_query(dname, req->wire, &bufsize);
		break;
	case NS_XFR_TYPE_IIN:
		ret = xfrin_create_ixfr_query(dname, req->wire, &bufsize);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* Handle errors. */
	if (ret != KNOT_EOK) {
		socket_close(req->session);
		return ret;
	}

	/* Send XFR query. */
	debug_net("xfr_in: sending XFR query (%zu bytes)\n", bufsize);
	ret = req->send(req->session, &req->addr, req->wire, bufsize);
	if (ret != bufsize) {
		socket_close(req->session);
		return KNOT_ERROR;
	}

	/* Update XFR request. */
	req->wire = 0; /* Disable shared buffer. */
	req->wire_size = 0;
	req->data = 0; /* New zone will be built. */
	req->zone = 0;

	/* Store XFR request for further processing. */
	void *data = malloc(sizeof(ns_xfr_t));
	if (!data) {
		socket_close(req->session);
		return KNOT_ENOMEM;
	}
	memcpy(data, req, sizeof(ns_xfr_t));

	/* Add to pending transfers. */
	tcp_pool_add(handler->xfer_pool, req->session, data);
	dt_activate(handler->unit->threads[0]);

	return KNOT_EOK;
}

int xfr_master(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_net("xfr_master: no data recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	debug_net("xfr_master: thread started.\n");
	for (;;) {

		/* Poll new events. */
		int ret = evqueue_poll(data->q, 0, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			debug_net("xfr_master: finished.\n");
			return KNOT_EOK;
		}

		/* Check poll count. */
		if (ret <= 0) {
			debug_net("xfr_master: queue poll returned %d.\n", ret);
			return KNOT_ERROR;
		}

		/* Read single request. */
		ns_xfr_t xfr;
		ret = evqueue_read(data->q, &xfr, sizeof(ns_xfr_t));
		if (ret != sizeof(ns_xfr_t)) {
			debug_net("xfr_master: queue read returned %d.\n", ret);
			return KNOT_ERROR;
		}

		/* Update request. */
		sockaddr_update(&xfr.addr);
		xfr.wire = buf;
		xfr.wire_size = sizeof(buf);

		/* Handle request. */
		const char *req_type = "";
		switch(xfr.type) {
		case NS_XFR_TYPE_AOUT:
			req_type = "axfr-out";
			ret = ns_answer_axfr(data->ns, &xfr);
			dnslib_packet_free(&xfr.query); /* Free query. */
			debug_net("xfr_master: ns_answer_axfr() returned %d.\n",
				  ret);
			break;
		case NS_XFR_TYPE_IOUT:
			req_type = "ixfr-out";
			ret = ns_answer_ixfr(data->ns, &xfr);
			dnslib_packet_free(&xfr.query); /* Free query. */
			debug_net("xfr_master: ns_answer_ixfr() returned %d.\n",
				  ret);
			break;
		case NS_XFR_TYPE_AIN:
			req_type = "axfr-in";
			ret = xfr_client_start(data, &xfr);
			break;
		case NS_XFR_TYPE_IIN:
			req_type = "ixfr-in";
			ret = xfr_client_start(data, &xfr);
			break;
		default:
			break;
		}

		/* Report. */
		if (ret != KNOT_EOK) {
			log_server_error("%s request failed: %s\n",
					 req_type, knot_strerror(ret));
		}
	}


	// Stop whole unit
	debug_net("xfr_master: finished.\n");
	return KNOT_EOK;
}

int xfr_client(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_net("xfr_client: no data recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	/* Run TCP pool. */
	int ret = tcp_pool(thread);

	debug_net("xfr_client: finished.\n");
	return ret;
}
