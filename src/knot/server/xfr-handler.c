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

///*! \brief XFR event wrapper for libev. */
//struct xfr_io_t
//{
//	ev_io io;
//	xfrhandler_t *h;
//	knot_ns_xfr_t data;
//};

///*! \brief Query event wrapper for libev. */
//struct qr_io_t
//{
//	ev_io io;
//	int type;
//	sockaddr_t addr;
//	knot_nameserver_t *ns;
//	event_t* ev;
//};

///*!
// * \brief SOA query timeout handler.
// */
//static int qr_timeout_ev(event_t *e)
//{
//	struct qr_io_t* qw = (struct qr_io_t *)e->data;
//	if (!qw) {
//		return KNOTD_EINVAL;
//	}

//	/* Close socket. */
//	debug_xfr("qr_response_ev: timeout on fd=%d\n", ((ev_io *)qw)->fd);
//	close(((ev_io *)qw)->fd);
//	return KNOTD_EOK;
//}

///*!
// * \brief Query reponse event handler function.
// *
// * Handle single query response event.
// *
// * \param loop Associated event pool.
// * \param w Associated socket watcher.
// * \param revents Returned events.
// */
//static inline void qr_response_ev(struct ev_loop *loop, ev_io *w, int revents)
//{
//	/* Check data. */
//	struct qr_io_t* qw = (struct qr_io_t *)w;
//	if (!qw->ns) {
//		return;
//	}

//	/* Prepare msg header. */
//	uint8_t qbuf[SOCKET_MTU_SZ];
//	struct msghdr msg;
//	memset(&msg, 0, sizeof(struct msghdr));
//	struct iovec iov;
//	memset(&iov, 0, sizeof(struct iovec));
//	iov.iov_base = qbuf;
//	iov.iov_len = SOCKET_MTU_SZ;
//	msg.msg_iov = &iov;
//	msg.msg_iovlen = 1;
//	msg.msg_name = qw->addr.ptr;
//	msg.msg_namelen = qw->addr.len;

//	/* Receive msg. */
//	ssize_t n = recvmsg(w->fd, &msg, 0);
//	size_t resp_len = sizeof(qbuf);
//	if (n > 0) {
//		debug_xfr("qr_response_ev: processing response\n");
//		udp_handle(qbuf, n, &resp_len, &qw->addr, qw->ns);
//	}

//	/* Disable timeout. */
//	evsched_t *sched =
//		((server_t *)knot_ns_get_data(qw->ns))->sched;
//	if (qw->ev) {
//		evsched_cancel(sched, qw->ev);
//		if (qw->ev) {
//			evsched_event_free(sched, qw->ev);
//			qw->ev = 0;
//		}
//	}

//	/* Close after receiving response. */
//	debug_xfr("qr_response_ev: closing socket %d\n", w->fd);
//	ev_io_stop(loop, w);
//	close(w->fd);
//	free(qw);
//	return;
//}

/*!
 * \brief XFR-IN event handler function.
 *
 * Handle single XFR client event.
 *
 * \param loop Associated event pool.
 * \param w Associated socket watcher.
 * \param revents Returned events.
 */
static inline int xfr_process_xfrin(int fd, knot_ns_xfr_t *request, xfrworker_t *w)
{
//	/* Buffer for answering. */
//	uint8_t buf[65535];

//	/* Read DNS/TCP packet. */
//	int ret = tcp_recv(fd, buf, sizeof(buf), 0);
//	if (ret <= 0) {
//		debug_xfr("xfr_process_xfrin: closing socket %d\n", fd);
//		fdset_remove(w->fdset, fd);
//		close(fd);
//		free(request);
//		return;
//	}

//	/* Update xfer state. */
//	request->wire = buf;
//	request->wire_size = ret;

//	/* Process incoming packet. */
//	switch(request->type) {
//	case XFR_TYPE_AIN:
//		ret = knot_ns_process_axfrin(xfr_w->h->ns, request);
//		break;
//	case XFR_TYPE_IIN:
//		ret = knot_ns_process_ixfrin(xfr_w->h->ns, request);
//		break;
//	default:
//		ret = KNOTD_EINVAL;
//		break;
//	}

//	/* Check return code for errors. */
//	debug_xfr("xfr_client_ev: processed incoming XFR packet (res =  %d)\n",
//		  ret);
//	if (ret < 0) {
//		/*! \todo Log error. */
//		debug_xfr("xfr_client_ev: closing socket %d\n",
//			  ((ev_io *)w)->fd);
//		log_server_error("%cxfr_in: Failed to process response - %s\n",
//				 request->type == XFR_TYPE_AIN ? 'a' : 'i',
//				 knotd_strerror(ret));
//		ev_io_stop(loop, (ev_io *)w);
//		close(((ev_io *)w)->fd);
//		free(xfr_w);
//		return;
//	}

//	/* Check finished zone. */
//	if (ret > 0) {

//		switch(request->type) {
//		case XFR_TYPE_AIN:
//			debug_xfr("xfr_client_ev: AXFR/IN saving new zone\n");
//			ret = zones_save_zone(request);
//			if (ret != KNOTD_EOK) {
//				log_server_error("axfr_in: Failed to save "
//						 "transferred zone - %s\n",
//						 knotd_strerror(ret));
//			} else {
//				debug_xfr("xfr_client_ev: new zone saved\n");
//				ret = knot_ns_switch_zone(xfr_w->h->ns, request);
//				if (ret != KNOTD_EOK) {
//					log_server_error("axfr_in: Failed to "
//							 "switch in-memory zone "
//							 "- %s\n",
//							 knotd_strerror(ret));
//				}
//			}
//			log_server_info("AXFR/IN transfer finished.\n");
//			break;
//		case XFR_TYPE_IIN:
//			/* Save changesets. */
//			debug_xfr("xfr_client_ev: IXFR/IN saving changesets\n");
//			ret = zones_store_changesets(request);
//			if (ret != KNOTD_EOK) {
//				log_server_error("ixfr_in: Failed to save "
//						 "transferred changesets - %s\n",
//						 knotd_strerror(ret));
//			} else {
//				/* Update zone. */
//				ret = zones_apply_changesets(request);
//				if (ret != KNOTD_EOK) {
//					log_server_error("ixfr_in: Failed to "
//							 "apply changesets - %s\n",
//							 knotd_strerror(ret));
//				}
//			}
//			/* Free changesets, but not the data. */
//			knot_changesets_t *chs = (knot_changesets_t *)request->data;
//			free(chs->sets);
//			free(chs);
//			request->data = 0;
//			log_server_info("IXFR/IN transfer finished.\n");
//			break;
//		default:
//			ret = KNOTD_EINVAL;
//			break;
//		}

//		/* Update timers. */
//		server_t *server = (server_t *)knot_ns_get_data(xfr_w->h->ns);
//		knot_zone_t *zone = (knot_zone_t *)request->zone;
//		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
//		zones_timers_update(zone, zd->conf, server->sched);

//		/* Return error code to make TCP client disconnect. */
//		ev_io_stop(loop, (ev_io *)w);
//		close(((ev_io *)w)->fd);
//		free(xfr_w);
//		return;
//	}

//	return;
	return 0;
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
//	/* Check data. */
//	struct xfr_io_t* xfr_w = (struct xfr_io_t *)w;
//	xfrhandler_t *handler = xfr_w->h;
//	knot_ns_xfr_t *req = &xfr_w->data;
//	if (!handler || !req) {
//		return;
//	}

//	/* Read event. */
//	int ret = evqueue_read(handler->cq, req, sizeof(knot_ns_xfr_t));
//	if (ret != sizeof(knot_ns_xfr_t)) {
//		debug_xfr("xfr_bridge_ev: queue read returned %d.\n", ret);
//		ev_io_stop(loop, w);
//		ev_unloop(loop, EVUNLOOP_ALL);
//		dt_stop(handler->unit);
//		return;
//	}

//	/* Process pending SOA/NOTIFY requests. */
//	if (req->type == XFR_TYPE_SOA || req->type == XFR_TYPE_NOTIFY) {

//		/* Watch bound socket. */
//		struct qr_io_t *qw = malloc(sizeof(struct qr_io_t));
//		if (!qw) {
//			log_server_error("xfr-in: failed to watch socket for "
//					 "pending query\n");
//			socket_close(req->session);
//			return;
//		}
//		memset(qw, 0, sizeof(struct qr_io_t));
//		qw->ns = handler->ns;
//		qw->type = req->type;
//		memcpy(&qw->addr, &req->addr, sizeof(sockaddr_t));
//		sockaddr_update(&qw->addr);

//		/* Add timeout. */
//		evsched_t *sch = ((server_t *)knot_ns_get_data(qw->ns))->sched;
//		qw->ev = evsched_schedule_cb(sch, qr_timeout_ev, qw, SOA_QRY_TIMEOUT);

//		/* Add to pending transfers. */
//		ev_io_init((ev_io *)qw, qr_response_ev, req->session, EV_READ);
//		ev_io_start(loop, (ev_io *)qw);
//		debug_xfr("xfr_bridge_ev: waiting for query response\n");
//		return;
//	}

//	/* Fetch associated zone. */
//	knot_zone_t *zone = (knot_zone_t *)req->data;
//	if (!zone) {
//		return;
//	}

//	/* Update address. */
//	sockaddr_update(&req->addr);
//	int r_port = -1;
//#ifdef DISABLE_IPV6
//	char r_addr[INET_ADDRSTRLEN];
//	memset(r_addr, 0, sizeof(r_addr));
//#else
//	/* Load IPv6 addr if default. */
//	char r_addr[INET6_ADDRSTRLEN];
//	memset(r_addr, 0, sizeof(r_addr));
//	if (req->addr.family == AF_INET6) {
//		r_port = ntohs(req->addr.addr6.sin6_port);
//		inet_ntop(req->addr.family, &req->addr.addr6.sin6_addr,
//			  r_addr, sizeof(r_addr));
//	}
//#endif
//	/* Load IPv4 if set. */
//	if (req->addr.family == AF_INET) {
//		r_port = ntohs(req->addr.addr4.sin_port);
//		inet_ntop(req->addr.family, &req->addr.addr4.sin_addr,
//			  r_addr, sizeof(r_addr));
//	}

//	/* Connect to remote. */
//	if (req->session <= 0) {
//		int fd = socket_create(req->addr.family, SOCK_STREAM);
//		if (fd < 0) {
//			log_server_warning("Failed to create socket "
//					   "(type=%s, family=%s).\n",
//					   "SOCK_STREAM",
//					   req->addr.family == AF_INET ?
//					   "AF_INET" : "AF_INET6");
//			return;
//		}
//		ret = connect(fd, req->addr.ptr, req->addr.len);
//		if (ret < 0) {
//			log_server_warning("Failed to connect to %cXFR master "
//					   "at %s:%d.\n",
//					   req->type == XFR_TYPE_AIN ? 'A' : 'I',
//					   r_addr, r_port);
//			if (!knot_zone_contents(zone)) {
//				log_zone_notice("Zone AXFR bootstrap failed.\n");
//			}
//			return;
//		}

//		/* Store new socket descriptor. */
//		req->session = fd;
//	} else {
//		/* Duplicate existing socket descriptor. */
//		req->session = dup(req->session);
//	}

//	/* Fetch zone contents. */
//	rcu_read_lock();
//	const knot_zone_contents_t *contents = knot_zone_contents(zone);
//	if (!contents && req->type == XFR_TYPE_IIN) {
//		rcu_read_unlock();
//		log_server_warning("Failed start IXFR on zone with no "
//				   "contents\n");
//		socket_close(req->session);
//		return;
//	}

//	/* Create XFR query. */
//	ret = KNOTD_ERROR;
//	size_t bufsize = req->wire_size;
//	switch(req->type) {
//	case XFR_TYPE_AIN:
//		ret = xfrin_create_axfr_query(zone->name, req->wire, &bufsize);
//		break;
//	case XFR_TYPE_IIN:
//		ret = xfrin_create_ixfr_query(contents, req->wire, &bufsize);
//		break;
//	default:
//		ret = KNOTD_EINVAL;
//		break;
//	}

//	/* Unlock zone contents. */
//	rcu_read_unlock();

//	/* Handle errors. */
//	if (ret != KNOTD_EOK) {
//		debug_xfr("xfr_in: failed to create XFR query type %d\n",
//			  req->type);
//		socket_close(req->session);
//		return;
//	}

//	/* Send XFR query. */
//	log_server_info("Sending %cXFR query to %s:%d (%zu bytes).\n",
//			req->type == XFR_TYPE_AIN ? 'A' : 'I',
//			r_addr, r_port, bufsize);
//	ret = req->send(req->session, &req->addr, req->wire, bufsize);
//	if (ret != bufsize) {
//		log_server_notice("Failed to send %cXFR query.",
//				  req->type == XFR_TYPE_AIN ? 'A' : 'I');
//		socket_close(req->session);
//		return;
//	}

//	/* Update XFR request. */
//	req->wire = 0; /* Disable shared buffer. */
//	req->wire_size = 0;
//	req->data = 0; /* New zone will be built. */
//	req->zone = 0;

//	/* Store XFR request for further processing. */
//	struct xfr_io_t *cl_w = malloc(sizeof(struct xfr_io_t));
//	if (!cl_w) {
//		socket_close(req->session);
//		return;
//	}
//	cl_w->h = xfr_w->h;
//	memcpy(&cl_w->data, req, sizeof(knot_ns_xfr_t));

//	/* Add to pending transfers. */
//	ev_io_init((ev_io *)cl_w, xfr_client_ev, req->session, EV_READ);
//	ev_io_start(loop, (ev_io *)cl_w);
}

/*
 * Public APIs.
 */

static xfrworker_t* xfr_worker_create(knot_nameserver_t *ns)
{
	xfrworker_t *w = malloc(sizeof(xfrworker_t));
	if(!w) {
		return 0;
	}
	
	/* Set nameserver. */
	w->ns = ns;
	
	/* Create event queue. */
	w->q = evqueue_new();
	if (!w->q) {
		free(w);
		return 0;
	}
	
	/* Create fdset. */
	w->fdset = fdset_new();
	if (!w->fdset) {
		evqueue_free(&w->q);
		free(w);
		return 0;
	}
	
	/* Add evqueue to fdset. */
	fdset_add(w->fdset, evqueue_pollfd(w->q), OS_EV_READ);
	
	return w;
}

static void xfr_worker_free(xfrworker_t *w) {
	if (w) {
		evqueue_free(&w->q);
		fdset_destroy(w->fdset);
		free(w);
	}
}

xfrhandler_t *xfr_create(size_t thrcount, knot_nameserver_t *ns)
{
	/* Create XFR handler data. */
	xfrhandler_t *data = malloc(sizeof(xfrhandler_t));
	if (!data) {
		return 0;
	}
	memset(data, 0, sizeof(xfrhandler_t));
	
	/* Create RR mutex. */
	pthread_mutex_init(&data->rr_mx, 0);
	
	/* Initialize threads. */
	data->workers = malloc(thrcount * sizeof(xfrhandler_t*));
	if(data->workers == 0) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data);
	}
	
	/* Create threading unit. */
	dt_unit_t *unit = dt_create(thrcount);
	if (!unit) {
		pthread_mutex_destroy(&data->rr_mx);
		free(data->workers);
		free(data);
		return 0;
	}
	data->unit = unit;
	
	/* Create worker threads. */
	unsigned initialized = 0;
	for (unsigned i = 0; i < thrcount; ++i) {
		data->workers[i] = xfr_worker_create(ns);
		if(data->workers[i] == 0) {
			break;
		}
		++initialized;
	}
	
	/* Check for initialized. */
	if (initialized != thrcount) {
		for (unsigned i = 0; i < initialized; ++i) {
			xfr_worker_free(data->workers[i]);
		}
		pthread_mutex_destroy(&data->rr_mx);
		free(data->workers);
		free(data->unit);
		free(data);
		return 0;
	}
	
	/* Assign worker threads. */
	for (unsigned i = 0; i < thrcount; ++i) {
		dt_repurpose(unit->threads[i], xfr_worker, data->workers[i]);
	}

	return data;
}

int xfr_free(xfrhandler_t *handler)
{
	if (!handler) {
		return KNOTD_EINVAL;
	}
	
	/* Free RR mutex. */
	pthread_mutex_destroy(&handler->rr_mx);

	/* Delete unit. */
	dt_delete(&handler->unit);
	free(handler);

	return KNOTD_EOK;
}

int xfr_stop(xfrhandler_t *handler)
{
	/* Break loop. */
	dt_stop(handler->unit);
	return KNOTD_EOK;
}

int xfr_request(xfrhandler_t *handler, knot_ns_xfr_t *req)
{
	if (!handler || !req) {
		return KNOTD_EINVAL;
	}
	
	/* Get next worker in RR fashion */
	pthread_mutex_lock(&handler->rr_mx);
	evqueue_t *q = handler->workers[handler->rr]->q;
	handler->rr = get_next_rr(handler->rr, handler->unit->size);
	pthread_mutex_unlock(&handler->rr_mx);

	/* Delegate request. */
	int ret = evqueue_write(q, req, sizeof(knot_ns_xfr_t));
	if (ret < 0) {
		return KNOTD_ERROR;
	}

	return KNOTD_EOK;
}

static int xfr_process_request(xfrworker_t *w, uint8_t *buf, size_t buflen)
{
	/* Poll new events. */
	int ret = evqueue_poll(w->q, 0, 0);

	/* Check poll count. */
	if (ret <= 0) {
		debug_xfr("xfr_process_request: queue poll returned %d.\n", ret);
		return KNOTD_ERROR;
	}

	/* Read single request. */
	knot_ns_xfr_t xfr;
	ret = evqueue_read(w->q, &xfr, sizeof(knot_ns_xfr_t));
	if (ret != sizeof(knot_ns_xfr_t)) {
		debug_xfr("xfr_process_request: queue read returned %d.\n", ret);
		return KNOTD_ERROR;
	}

	/* Update request. */
	sockaddr_update(&xfr.addr);
	xfr.wire = buf;
	xfr.wire_size = buflen;
	int r_port = -1;
#ifdef DISABLE_IPV6
	char r_addr[INET_ADDRSTRLEN];
	memset(r_addr, 0, sizeof(r_addr));
#else
	/* Load IPv6 addr if default. */
	char r_addr[INET6_ADDRSTRLEN];
	memset(r_addr, 0, sizeof(r_addr));
	if (xfr.addr.family == AF_INET6) {
		r_port = ntohs(xfr.addr.addr6.sin6_port);
		inet_ntop(xfr.addr.family, &xfr.addr.addr6.sin6_addr,
			  r_addr, sizeof(r_addr));
	}
#endif
	/* Load IPv4 if set. */
	if (xfr.addr.family == AF_INET) {
		r_port = ntohs(xfr.addr.addr4.sin_port);
		inet_ntop(xfr.addr.family, &xfr.addr.addr4.sin_addr,
			  r_addr, sizeof(r_addr));
	}

	/* Handle request. */
	const char *req_type = "";
	knot_rcode_t rcode;
	
	rcu_read_lock();
	
	switch(xfr.type) {
	case XFR_TYPE_AOUT:
		req_type = "AXFR/OUT";
		
		ret = knot_ns_init_xfr(w->ns, &xfr);
		if (ret != KNOT_EOK) {
			log_server_notice("AXFR/OUT transfer initialization "
					  "to %s:%d failed: %s\n",
					  r_addr, r_port,
					  knot_strerror(ret));
			socket_close(xfr.session);
		}

		int init_failed = ret != KNOT_EOK;
		ret = zones_xfr_check_zone(&xfr, &rcode);
		if (ret != KNOTD_EOK) {
			if (!init_failed) {
				knot_ns_xfr_send_error(&xfr, rcode);
				socket_close(xfr.session);
				log_server_notice("AXFR/OUT transfer check "
						  "to %s:%d failed: %s\n",
						  r_addr, r_port,
						  knotd_strerror(ret));
			}
		} else {

			ret = knot_ns_answer_axfr(w->ns, &xfr);
			debug_xfr("xfr_master: ns_answer_axfr() = %d.\n", ret);
			if (ret != KNOTD_EOK) {
				socket_close(xfr.session);
			} else {
				log_server_info("AXFR/OUT transfer "
						"to %s:%d successful.\n",
						r_addr, r_port);
			}
		}
		
		free(xfr.query->wireformat);
		xfr.query->wireformat = 0;
		knot_packet_free(&xfr.query); /* Free query. */
		rcu_read_unlock();
		break;
	case XFR_TYPE_IOUT:
		req_type = "IXFR/OUT";
		
		ret = knot_ns_init_xfr(w->ns, &xfr);
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
		
		ret = knot_ns_answer_ixfr(w->ns, &xfr);
		free(xfr.query->wireformat);
		knot_packet_free(&xfr.query); /* Free query. */
		debug_xfr("xfr_master: ns_answer_ixfr() = %d.\n", ret);
		if (ret != KNOTD_EOK) {
			socket_close(xfr.session);
		} else{
			log_server_info("IXFR/OUT transfer "
					"to %s:%d successful.\n",
					r_addr, r_port);
		}
		break;
	case XFR_TYPE_AIN:
		req_type = "AXFR/IN";
		/*! \todo Create request and map it to fd. */
//		xfr_client_relay(w, &xfr);
		ret = KNOTD_ENOTSUP;
		break;
	case XFR_TYPE_IIN:
		req_type = "IXFR/IN";
//			xfr_client_relay(w, &xfr);
		ret = KNOTD_ENOTSUP;
		break;
	default:
		break;
	}

	/* Report. */
	if (ret != KNOTD_EOK && ret != KNOTD_EACCES) {
		log_server_error("%s request from %s:%d failed: %s\n",
				 req_type, r_addr, r_port,
				 knotd_strerror(ret));
	}
	
	return ret;
}

int xfr_worker(dthread_t *thread)
{
	xfrworker_t *w = (xfrworker_t *)thread->data;	

	/* Check data. */
	if (w < 0) {
		debug_xfr("xfr_worker: NULL worker data, finishing.\n");
		return KNOTD_EINVAL;
	}

	/* Buffer for answering. */
	uint8_t buf[65535];

	/* Accept requests. */
	debug_xfr("xfr_worker: thread started.\n");
	for (;;) {
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Poll fdset. */
		int nfds = fdset_wait(w->fdset);
		if (nfds <= 0) {
			continue;
		}
		
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Iterate fdset. */
		int rfd = evqueue_pollfd(w->q);
		fdset_it_t it;
		fdset_begin(w->fdset, &it);
		while(1) {
			
			/* Check if it request. */
			if (it.fd == rfd) {
				debug_xfr("xfr_worker: processing request.\n");
				xfr_process_request(w, buf, sizeof(buf));
			} else {
				debug_xfr("xfr_worker: processing event on "
				          "fd=%d.\n", it.fd);
//				xfr_process_event(thread, w, fd);
			}
			
			/* Next fd. */
			if (fdset_next(w->fdset, &it) < 0) {
				break;
			}
		}
	}


	/* Stop whole unit. */
	debug_xfr("xfr_worker: finished.\n");
	xfr_worker_free(w);
	thread->data = 0;
	return KNOTD_EOK;
}
