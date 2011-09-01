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

#include <urcu.h>

#include "knot/common.h"
#include "knot/server/xfr-handler.h"
#include "libknot/nameserver/name-server.h"
#include "knot/other/error.h"
#include "knot/server/socket.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "libknot/updates/xfr-in.h"
#include "knot/server/zones.h"
#include "libknot/util/error.h"
#include "common/evsched.h"

/*! \brief XFR event wrapper for libev. */
struct xfr_io_t
{
	ev_io io;
	xfrhandler_t *h;
	knot_ns_xfr_t data;
};

/*! \brief Query event wrapper for libev. */
struct qr_io_t
{
	ev_io io;
	int type;
	sockaddr_t addr;
	knot_nameserver_t *ns;
	event_t* ev;
};

/*! \brief Interrupt libev ev_loop execution. */
static void xfr_interrupt(xfrhandler_t *h)
{
	/* Break loop. */
	evqueue_write(h->cq, "", 1);
}

/*!
 * \brief SOA query timeout handler.
 */
static int qr_timeout_ev(event_t *e)
{
	struct qr_io_t* qw = (struct qr_io_t *)e->data;
	if (!qw) {
		return KNOTD_EINVAL;
	}

	/* Close socket. */
	debug_xfr("qr_response_ev: timeout on fd=%d\n", ((ev_io *)qw)->fd);
	close(((ev_io *)qw)->fd);
	return KNOTD_EOK;
}

/*!
 * \brief Query reponse event handler function.
 *
 * Handle single query response event.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static inline void qr_response_ev(struct ev_loop *loop, ev_io *w, int revents)
{
	/* Check data. */
	struct qr_io_t* qw = (struct qr_io_t *)w;
	if (!qw->ns) {
		return;
	}

	/* Prepare msg header. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = qbuf;
	iov.iov_len = SOCKET_MTU_SZ;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = qw->addr.ptr;
	msg.msg_namelen = qw->addr.len;

	/* Receive msg. */
	debug_xfr("qr_response_ev: reading response\n");
	ssize_t n = recvmsg(w->fd, &msg, 0);
	size_t resp_len = sizeof(qbuf);
	if (n > 0) {
		debug_xfr("qr_response_ev: processing response\n");
		udp_handle(qbuf, n, &resp_len, &qw->addr, qw->ns);
	}

	/* Disable timeout. */
	evsched_t *sched =
		((server_t *)knot_ns_get_data(qw->ns))->sched;
	if (qw->ev) {
		evsched_cancel(sched, qw->ev);
		evsched_event_free(sched, qw->ev);
		qw->ev = 0;
	}

	/* Close after receiving response. */
	debug_xfr("qr_response_ev: closing socket %d\n", w->fd);
	ev_io_stop(loop, w);
	close(w->fd);
	free(qw);
	return;
}

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
	knot_ns_xfr_t *request = &xfr_w->data;
	if (!request) {
		return;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Read DNS/TCP packet. */
	int ret = tcp_recv(w->fd, buf, sizeof(buf), 0);
	if (ret <= 0) {
		debug_xfr("xfr_client_ev: closing socket %d\n",
			  ((ev_io *)w)->fd);
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
	case XFR_TYPE_AIN:
		ret = knot_ns_process_axfrin(xfr_w->h->ns, request);
		break;
	case XFR_TYPE_IIN:
		ret = knot_ns_process_ixfrin(xfr_w->h->ns, request);
		break;
	default:
		ret = KNOTD_EINVAL;
		break;
	}

	/* Check return code for errors. */
	debug_xfr("xfr_client_ev: processed incoming XFR packet (res =  %d)\n",
		  ret);
	if (ret < 0) {
		/*! \todo Log error. */
		return;
	}

	/* Check finished zone. */
	if (ret > 0) {

		switch(request->type) {
		case XFR_TYPE_AIN:
			debug_xfr("xfr_client_ev: AXFR/IN saving new zone\n");
			ret = zones_save_zone(request);
			if (ret != KNOTD_EOK) {
				log_server_error("axfr_in: Failed to save "
						 "transferred zone - %s\n",
						 knotd_strerror(ret));
			} else {
				debug_xfr("xfr_client_ev: new zone saved\n");
				ret = knot_ns_switch_zone(xfr_w->h->ns, request);
				if (ret != KNOTD_EOK) {
					log_server_error("axfr_in: Failed to "
							 "switch in-memory zone "
							 "- %s\n",
							 knotd_strerror(ret));
				}
			}
			debug_xfr("xfr_client_ev: AXFR/IN transfer finished\n");
			break;
		case XFR_TYPE_IIN:
			/* Save changesets. */
			debug_xfr("xfr_client_ev: IXFR/IN saving changesets\n");
			ret = zones_store_changesets(request);
			if (ret != KNOTD_EOK) {
				log_server_error("ixfr_in: Failed to save "
						 "transferred changesets - %s\n",
						 knotd_strerror(ret));
			} else {
				/* Update zone. */
				ret = zones_apply_changesets(request);
				if (ret != KNOTD_EOK) {
					log_server_error("ixfr_in: Failed to "
							 "apply changesets - %s\n",
							 knotd_strerror(ret));
				}
			}
			/* Free changesets, but not the data. */
			knot_changesets_t *chs = (knot_changesets_t *)request->data;
			free(chs->sets);
			free(chs);
			request->data = 0;
			debug_xfr("xfr_client_ev: IXFR/IN transfer finished\n");
			break;
		default:
			ret = KNOTD_EINVAL;
			break;
		}

		/* Update timers. */
		server_t *server = (server_t *)knot_ns_get_data(xfr_w->h->ns);
		knot_zone_t *zone = (knot_zone_t *)request->zone;
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		zones_timers_update(zone, zd->conf, server->sched);

		/* Return error code to make TCP client disconnect. */
		ev_io_stop(loop, (ev_io *)w);
		close(((ev_io *)w)->fd);
		free(xfr_w);
		return;
	}

	return;
}

/*!
 * \brief TCP loop to event queue bridge event.
 *
 * Read single request from event queue and execute it.
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
	knot_ns_xfr_t *req = &xfr_w->data;
	if (!handler || !req) {
		return;
	}

	/* Read event. */
	int ret = evqueue_read(handler->cq, req, sizeof(knot_ns_xfr_t));
	if (ret != sizeof(knot_ns_xfr_t)) {
		debug_xfr("xfr_bridge_ev: queue read returned %d.\n", ret);
		ev_io_stop(loop, w);
		ev_unloop(loop, EVUNLOOP_ALL);
		dt_stop(handler->unit);
		return;
	}

	/* Process pending SOA/NOTIFY requests. */
	if (req->type == XFR_TYPE_SOA || req->type == XFR_TYPE_NOTIFY) {

		/* Watch bound socket. */
		struct qr_io_t *qw = malloc(sizeof(struct qr_io_t));
		if (!qw) {
			log_server_error("xfr-in: failed to watch socket for "
					 "pending query\n");
			socket_close(req->session);
			return;
		}
		memset(qw, 0, sizeof(struct qr_io_t));
		qw->ns = handler->ns;
		qw->type = req->type;
		memcpy(&qw->addr, &req->addr, sizeof(sockaddr_t));
		sockaddr_update(&qw->addr);

		/* Add timeout. */
		evsched_t *sch = ((server_t *)knot_ns_get_data(qw->ns))->sched;
		qw->ev = evsched_schedule_cb(sch, qr_timeout_ev, qw, SOA_QRY_TIMEOUT);

		/* Add to pending transfers. */
		ev_io_init((ev_io *)qw, qr_response_ev, req->session, EV_READ);
		ev_io_start(loop, (ev_io *)qw);
		debug_xfr("xfr_bridge_ev: waiting for query response\n");
		return;
	}

	/* Fetch associated zone. */
	knot_zone_t *zone = (knot_zone_t *)req->data;
	if (!zone) {
		return;
	}

	/* Connect to remote. */
	if (req->session <= 0) {
		int fd = socket_create(req->addr.family, SOCK_STREAM);
		if (fd < 0) {
			return;
		}
		ret = connect(fd, req->addr.ptr, req->addr.len);
		if (ret < 0) {
			return;
		}

		/* Store new socket descriptor. */
		req->session = fd;
	} else {
		/* Duplicate existing socket descriptor. */
		req->session = dup(req->session);
	}

	/* Fetch zone contents. */
	rcu_read_lock();
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (!contents && req->type == XFR_TYPE_IIN) {
		rcu_read_unlock();
		debug_xfr("xfr_in: failed start IXFR on zone with no contents\n");
		socket_close(req->session);
		return;
	}

	/* Create XFR query. */
	ret = KNOTD_ERROR;
	size_t bufsize = req->wire_size;
	switch(req->type) {
	case XFR_TYPE_AIN:
		ret = xfrin_create_axfr_query(zone->name, req->wire, &bufsize);
		break;
	case XFR_TYPE_IIN:
		ret = xfrin_create_ixfr_query(contents, req->wire, &bufsize);
		break;
	default:
		ret = KNOTD_EINVAL;
		break;
	}

	/* Unlock zone contents. */
	rcu_read_unlock();

	/* Handle errors. */
	if (ret != KNOTD_EOK) {
		debug_xfr("xfr_in: failed to create XFR query type %d\n",
			  req->type);
		socket_close(req->session);
		return;
	}

	/* Send XFR query. */
	debug_xfr("xfr_in: sending XFR query (%zu bytes)\n", bufsize);
	ret = req->send(req->session, &req->addr, req->wire, bufsize);
	if (ret != bufsize) {
		debug_xfr("xfr_in: failed to send XFR query type %d\n",
			  req->type);
		socket_close(req->session);
		return;
	}

	/* Update XFR request. */
	req->wire = 0; /* Disable shared buffer. */
	req->wire_size = 0;
	req->data = 0; /* New zone will be built. */
	req->zone = 0;

	/* Store XFR request for further processing. */
	struct xfr_io_t *cl_w = malloc(sizeof(struct xfr_io_t));
	if (!cl_w) {
		socket_close(req->session);
		return;
	}
	cl_w->h = xfr_w->h;
	memcpy(&cl_w->data, req, sizeof(knot_ns_xfr_t));

	/* Add to pending transfers. */
	ev_io_init((ev_io *)cl_w, xfr_client_ev, req->session, EV_READ);
	ev_io_start(loop, (ev_io *)cl_w);
}

/*
 * Public APIs.
 */

xfrhandler_t *xfr_create(size_t thrcount, knot_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (!data) {
		return 0;
	}
	data->ns = ns;
	data->interrupt = 0;
	data->loop = 0;

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

	/* Repurpose first thread as xfr_client. */
	dt_repurpose(unit->threads[0], &xfr_client, (void*)data);

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOTD_EINVAL;
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

	return KNOTD_EOK;
}

int xfr_stop(xfrhandler_t *handler)
{
	/* Break loop. */
	struct xfr_io_t brk;
	memset(&brk, 0, sizeof(struct xfr_io_t));
	brk.data.session = -1;
	evqueue_write(handler->cq, &brk, sizeof(struct xfr_io_t));

	return KNOTD_EOK;
}

int xfr_request(xfrhandler_t *handler, knot_ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOTD_EINVAL;
	}

	int ret = evqueue_write(handler->q, req, sizeof(knot_ns_xfr_t));
	if (ret < 0) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

int xfr_client_relay(xfrhandler_t *handler, knot_ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOTD_EINVAL;
	}

	int ret = evqueue_write(handler->cq, req, sizeof(knot_ns_xfr_t));
	if (ret < 0) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

int xfr_master(dthread_t *thread)
{
	xfrhandler_t *xfrh = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (xfrh < 0) {
		debug_xfr("xfr_master: no data recevied, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	debug_xfr("xfr_master: thread started.\n");
	for (;;) {

		/* Poll new events. */
		int ret = evqueue_poll(xfrh->q, 0, 0);

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			debug_xfr("xfr_master: finished.\n");
			return KNOTD_EOK;
		}

		/* Check poll count. */
		if (ret <= 0) {
			debug_xfr("xfr_master: queue poll returned %d.\n", ret);
			return KNOTD_ERROR;
		}

		/* Read single request. */
		knot_ns_xfr_t xfr;
		ret = evqueue_read(xfrh->q, &xfr, sizeof(knot_ns_xfr_t));
		if (ret != sizeof(knot_ns_xfr_t)) {
			debug_xfr("xfr_master: queue read returned %d.\n", ret);
			return KNOTD_ERROR;
		}

		/* Update request. */
		sockaddr_update(&xfr.addr);
		xfr.wire = buf;
		xfr.wire_size = sizeof(buf);

		/* Handle request. */
		const char *req_type = "";
		knot_rcode_t rcode;
		
		rcu_read_lock();
		
		switch(xfr.type) {
		case XFR_TYPE_AOUT:
			req_type = "axfr-out";
			
			ret = knot_ns_init_xfr(xfrh->ns, &xfr);
			if (ret != KNOT_EOK) {
				debug_xfr("xfr_master: failed to init XFR: %s\n",
				          knotd_strerror(ret));
				socket_close(xfr.session);
			}
			
			ret = zones_xfr_check_zone(&xfr, &rcode);
			if (ret != KNOTD_EOK) {
				knot_ns_xfr_send_error(&xfr, rcode);
				socket_close(xfr.session);
			}			

			ret = knot_ns_answer_axfr(xfrh->ns, &xfr);
			free(xfr.query->wireformat);
			knot_packet_free(&xfr.query); /* Free query. */
			debug_xfr("xfr_master: ns_answer_axfr() = %d.\n", ret);
			if (ret != KNOTD_EOK) {
				socket_close(xfr.session);
			}
			
			rcu_read_unlock();
			break;
		case XFR_TYPE_IOUT:
			req_type = "ixfr-out";
			
			ret = knot_ns_init_xfr(xfrh->ns, &xfr);
			if (ret != KNOT_EOK) {
				debug_xfr("xfr_master: failed to init XFR: %s\n",
				          knotd_strerror(ret));
				socket_close(xfr.session);
			}
			
			ret = zones_xfr_check_zone(&xfr, &rcode);
			if (ret != KNOTD_EOK) {
				knot_ns_xfr_send_error(&xfr, rcode);
				socket_close(xfr.session);
			}
			
			ret = zones_xfr_load_changesets(&xfr);
			if (ret != KNOTD_EOK) {
				knot_ns_xfr_send_error(&xfr, 
				                         KNOT_RCODE_SERVFAIL);
				socket_close(xfr.session);
			}
			
			ret = knot_ns_answer_ixfr(xfrh->ns, &xfr);
			free(xfr.query->wireformat);
			knot_packet_free(&xfr.query); /* Free query. */
			debug_xfr("xfr_master: ns_answer_ixfr() = %d.\n", ret);
			if (ret != KNOTD_EOK) {
				socket_close(xfr.session);
			}
			break;
		case XFR_TYPE_AIN:
			req_type = "axfr-in";
			xfr_client_relay(xfrh, &xfr);
			ret = KNOTD_EOK;
			break;
		case XFR_TYPE_IIN:
			req_type = "ixfr-in";
			xfr_client_relay(xfrh, &xfr);
			ret = KNOTD_EOK;
			break;
		default:
			break;
		}

		/* Report. */
		if (ret != KNOTD_EOK) {
			log_server_error("%s request failed: %s\n",
					 req_type, knotd_strerror(ret));
		}
	}


	/* Stop whole unit. */
	debug_xfr("xfr_master: finished.\n");
	return KNOTD_EOK;
}

int xfr_client(dthread_t *thread)
{
	xfrhandler_t *data = (xfrhandler_t *)thread->data;

	/* Check data. */
	if (data < 0) {
		debug_xfr("xfr_client: no data received, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Install interrupt handler. */
	data->interrupt = &xfr_interrupt;

	/* Bridge evqueue pollfd to event loop. */
	struct xfr_io_t* bridge = malloc(sizeof(struct xfr_io_t));
	memset(bridge, 0, sizeof(struct xfr_io_t));
	bridge->h = data;
	ev_io_init((ev_io *)bridge, xfr_bridge_ev,
		   evqueue_pollfd(data->cq), EV_READ);
	ev_io_start(data->loop, (ev_io *)bridge);
	debug_xfr("xfr_client: bridge to libev initiated\n");

	/* Accept requests. */
	debug_xfr("xfr_client: loop started\n");

	/* Cancellation point. */
	if (dt_is_cancelled(thread)) {
		debug_xfr("xfr_client: finished.\n");
		return KNOTD_EOK;
	}

	/* Run event loop. */
	ev_loop(data->loop, 0);
	data->interrupt = 0;

	/* Destroy pollfd watcher. */
	free(bridge);

	debug_xfr("xfr_client: finished.\n");

	return KNOTD_EOK;
}
