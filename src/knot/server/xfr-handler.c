#include <config.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

/*! \brief XFR event wrapper for libev. */
struct xfr_io_t
{
	ev_io io;
	xfrhandler_t *h;
	ns_xfr_t data;
};

/*!
 * \brief XFR-IN event handler function.
 *
 * Handle single XFR client event.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static inline void xfr_client_ev(struct ev_loop *loop, ev_io *w, int revents)
{
	/* Check data. */
	struct xfr_io_t* xfr_w = (struct xfr_io_t *)w;
	ns_xfr_t *request = &xfr_w->data;
	if (!request) {
		return;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Read DNS/TCP packet. */
	int ret = tcp_recv(w->fd, buf, sizeof(buf), 0);
	if (ret <= 0) {
		ev_io_stop(loop, (ev_io *)w);
		close(((ev_io *)w)->fd);
		free(xfr_w);
		return;
	}

	/* Update xfer state. */
	request->wire = buf;
	request->wire_size = ret;

	/* Process incoming packet. */
		switch(request->type) {
	case NS_XFR_TYPE_AIN:
		ret = ns_process_axfrin(xfr_w->h->ns, request);
		break;
	case NS_XFR_TYPE_IIN:
		ret = ns_process_ixfrin(xfr_w->h->ns, request);
		break;
	default:
		ret = KNOT_EINVAL;
		break;
	}

	/* Check return code for errors. */
	if (ret != KNOT_EOK) {
		return;
	}

	/* Check finished zone. */
	if (request->zone) {

		/* Save finished zone and reload. */
		xfrin_zone_transferred(xfr_w->h->ns, request->zone);

		/* Return error code to make TCP client disconnect. */
		return;
	}

	return;
}

/*!
 * \brief TCP loop to event queue bridge event.
 *
 * Read single request from event queue and move it to the TCP loop.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static inline void xfr_bridge_ev(struct ev_loop *loop, ev_io *w, int revents)
{
	/* Check data. */
	struct xfr_io_t* xfr_w = (struct xfr_io_t *)w;
	xfrhandler_t *handler = xfr_w->h;
	if (!handler) {
		return;
	}

	/* Poll new events. */
	int ret = evqueue_poll(handler->cq, 0, 0);

	/* Check poll count. */
	if (ret <= 0) {
		debug_xfr("xfr_bridge_ev: poll returned %d.\n", ret);
		return;
	}

	/* Read single request. */
	struct xfr_io_t *req = malloc(sizeof(struct xfr_io_t));
	if (!req) {
		log_server_error("xfr_bridge_ev: not enough memory.\n");
		return;
	}

	req->data.session = -1;
	ret = evqueue_read(handler->cq, req, sizeof(struct xfr_io_t));
	if (ret != sizeof(struct xfr_io_t)) {
		debug_xfr("xfr_bridge_ev: queue read returned %d.\n", ret);
	}

	/* Check session descriptor. */
	if (req->data.session < 0) {
		debug_xfr("xfr_bridge_ev: quitting\n");
		ev_io_stop(loop, w);
		ev_unloop(loop, EVUNLOOP_ALL);

		/* Stop threading unit. */
		dt_stop(handler->unit);
		free(req);
		return;
	}

	/* Move to TCP queue. */
	ev_io_init((ev_io *)req, xfr_client_ev, req->data.session, EV_READ);
	ev_io_start(loop, (ev_io *)req);
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

	/* Create client requests queue. */
	data->cq = evqueue_new();
	if (!data->cq) {
		evqueue_free(&data->q);
		free(data);
		return 0;
	}

	/* Create event loop. */
	data->loop = ev_loop_new(0);
	if (!data->loop) {
		evqueue_free(&data->q);
		evqueue_free(&data->cq);
		free(data);
		return 0;
	}

	/* Create threading unit. */
	dt_unit_t *unit = 0;
	unit = dt_create_coherent(thrcount, &xfr_master, (void*)data);
	if (!unit) {
		evqueue_free(&data->q);
		evqueue_free(&data->cq);
		ev_loop_destroy(data->loop);
		free(data);
		return 0;
	}
	data->unit = unit;

	dt_repurpose(unit->threads[0], &xfr_client, data);

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOT_EINVAL;
	}

	/* Remove handler data. */
	evqueue_free(&handler->q);

	/* Remove client requests queue. */
	evqueue_free(&handler->cq);

	/* Free event loop. */
	ev_loop_destroy(handler->loop);

	/* Delete unit. */
	dt_delete(&handler->unit);
	free(handler);

	return KNOT_EOK;
}

int xfr_stop(xfrhandler_t *handler)
{
	/* Break loop. */
	struct xfr_io_t brk;
	memset(&brk, 0, sizeof(struct xfr_io_t));
	brk.data.session = -1;
	evqueue_write(handler->cq, &brk, sizeof(struct xfr_io_t));

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
	debug_xfr("xfr_in: sending XFR query (%zu bytes)\n", bufsize);
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
	struct xfr_io_t w;
	memset(&w, 0, sizeof(struct xfr_io_t));
	w.h = handler;
	memcpy(&w.data, req, sizeof(ns_xfr_t));

	/* Add to pending transfers. */
	evqueue_write(handler->cq, &w, sizeof(struct xfr_io_t));

	return KNOT_EOK;
}

int xfr_master(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_xfr("xfr_master: no data recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	debug_xfr("xfr_master: thread started.\n");
	for (;;) {

		/* Poll new events. */
		int ret = evqueue_poll(data->q, 0, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			debug_xfr("xfr_master: finished.\n");
			return KNOT_EOK;
		}

		/* Check poll count. */
		if (ret <= 0) {
			debug_xfr("xfr_master: queue poll returned %d.\n", ret);
			return KNOT_ERROR;
		}

		/* Read single request. */
		ns_xfr_t xfr;
		ret = evqueue_read(data->q, &xfr, sizeof(ns_xfr_t));
		if (ret != sizeof(ns_xfr_t)) {
			debug_xfr("xfr_master: queue read returned %d.\n", ret);
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
			debug_xfr("xfr_master: ns_answer_axfr() = %d.\n", ret);
			if (ret != KNOT_EOK) {
				socket_close(xfr.session);
			}
			break;
		case NS_XFR_TYPE_IOUT:
			req_type = "ixfr-out";
			ret = ns_answer_ixfr(data->ns, &xfr);
			dnslib_packet_free(&xfr.query); /* Free query. */
			debug_xfr("xfr_master: ns_answer_ixfr() = %d.\n", ret);
			if (ret != KNOT_EOK) {
				socket_close(xfr.session);
			}
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
	debug_xfr("xfr_master: finished.\n");
	return KNOT_EOK;
}

int xfr_client(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_xfr("xfr_client: no data received, finishing.\n");
		return KNOT_EINVAL;
	}

	/* Bridge evqueue pollfd to event loop. */
	struct xfr_io_t bridge;
	memset(&bridge, 0, sizeof(struct xfr_io_t));
	bridge.h = data;
	ev_io_init((ev_io *)&bridge, xfr_bridge_ev,
		   evqueue_pollfd(data->cq), EV_READ);
	ev_io_start(data->loop, (ev_io *)&bridge);
	debug_xfr("xfr_client: bridge to libev initiated\n");

	/* Accept requests. */
	debug_xfr("xfr_client: loop started\n");

	/* Cancellation point. */
	if (dt_is_cancelled(thread)) {
		debug_xfr("xfr_client: finished.\n");
		return KNOT_EOK;
	}

	/* Run event loop. */
	ev_loop(data->loop, 0);

	debug_xfr("xfr_client: finished.\n");

	return KNOT_EOK;
}
