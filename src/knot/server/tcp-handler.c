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

#include <ev.h>

#include "common/sockaddr.h"
#include "common/skip-list.h"
#include "knot/common.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/other/error.h"
#include "knot/stat/stat.h"
#include "dnslib/wire.h"
#include "knot/server/zones.h"

/*! \brief TCP watcher. */
typedef struct tcp_io_t {
	ev_io io;
	struct ev_loop   *loop;   /*!< Associated event loop. */
	server_t         *server; /*!< Name server */
	iohandler_t      *io_h;   /*!< Master I/O handler. */
	stat_t           *stat;   /*!< Statistics gatherer */
	unsigned         data;    /*!< Watcher-related data. */
} tcp_io_t;

/*
 * Forward decls.
 */

/*! \brief Wrapper for TCP send. */
static int xfr_send_cb(int session, sockaddr_t *addr, uint8_t *msg, size_t msglen)
{
	UNUSED(addr);
	return tcp_send(session, msg, msglen);
}

/*! \brief Create new TCP connection watcher. */
static inline tcp_io_t* tcp_conn_new(struct ev_loop *loop, int fd, tcp_cb_t cb)
{
	tcp_io_t *w = malloc(sizeof(tcp_io_t));
	if (w) {
		/* Omit invalid filedescriptors. */
		w->io.fd = -1;
		if (fd >= 0) {
			ev_io_init((ev_io *)w, cb, fd, EV_READ);
			ev_io_start(loop, (ev_io *)w);
		}

		w->data = 0;
		w->loop = loop;
	}

	return w;
}

/*! \brief Delete a TCP connection watcher. */
static inline void tcp_conn_free(struct ev_loop *loop, tcp_io_t *w)
{
	ev_io_stop(loop, (ev_io *)w);
	close(((ev_io *)w)->fd);
	free(w);
}

/*! \brief Noop event handler. */
static void tcp_noop(struct ev_loop *loop, ev_io *w, int revents)
{
}

/*!
 * \brief TCP event handler function.
 *
 * Handle single TCP event.
 *
 * \param w Associated I/O event.
 * \param revents Returned events.
 */
static void tcp_handle(struct ev_loop *loop, ev_io *w, int revents)
{
	debug_net("tcp: handling TCP event in thread %p.\n",
		  (void*)pthread_self());

	tcp_io_t *tcp_w = (tcp_io_t *)w;
	dnslib_nameserver_t *ns = tcp_w->server->nameserver;
	xfrhandler_t *xfr_h = tcp_w->server->xfr_h;

	/* Check address type. */
	sockaddr_t addr;
	if (sockaddr_init(&addr, tcp_w->io_h->type) != KNOT_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 tcp_w->io_h->type);
		return;
	}

	/* Receive data. */
	uint8_t qbuf[65535]; /*! \todo This may be problematic. */
	size_t qbuf_maxlen = sizeof(qbuf);
	int n = tcp_recv(w->fd, qbuf, qbuf_maxlen, &addr);
	if (n <= 0) {
		debug_net("tcp: client disconnected\n");
		tcp_conn_free(loop, tcp_w);
		return;
	}

	/* Parse query. */
//	dnslib_response_t *resp = dnslib_response_new(qbuf_maxlen);
	size_t resp_len = qbuf_maxlen; // 64K

	/* Parse query. */
	dnslib_packet_type_t qtype = DNSLIB_QUERY_NORMAL;

	dnslib_packet_t *packet =
		dnslib_packet_new(DNSLIB_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		uint16_t pkt_id = dnslib_wire_get_id(qbuf);
		dnslib_ns_error_response(ns, pkt_id, DNSLIB_RCODE_SERVFAIL,
				  qbuf, &resp_len);
		return;
	}

	int res = dnslib_ns_parse_packet(qbuf, n, packet, &qtype);
	if (unlikely(res != KNOT_EOK)) {

		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = dnslib_wire_get_id(qbuf);
			dnslib_ns_error_response(ns, pkt_id, res,
					  qbuf, &resp_len);
		}

//		dnslib_response_free(&resp);
		dnslib_packet_free(&packet);
		return;
	}

	/* Handle query. */
	dnslib_ns_xfr_t xfr;
	res = KNOT_ERROR;
	switch(qtype) {

	/* Response types. */
	case DNSLIB_RESPONSE_NORMAL:
	case DNSLIB_RESPONSE_AXFR:
	case DNSLIB_RESPONSE_IXFR:
	case DNSLIB_RESPONSE_NOTIFY:
		/*! \todo Implement packet handling. */
		break;

	/* Query types. */
	case DNSLIB_QUERY_NORMAL:
		res = dnslib_ns_answer_normal(ns, packet, qbuf, &resp_len);
		break;
	case DNSLIB_QUERY_AXFR:
		memset(&xfr, 0, sizeof(dnslib_ns_xfr_t));
		xfr.type = XFR_TYPE_AOUT;
		xfr.query = packet;
		xfr.send = xfr_send_cb;
		xfr.session = w->fd;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		xfr_request(xfr_h, &xfr);
		debug_net("tcp: enqueued AXFR query\n");
		return;
	case DNSLIB_QUERY_IXFR:
		memset(&xfr, 0, sizeof(dnslib_ns_xfr_t));
		xfr.type = XFR_TYPE_IOUT;
		xfr.query = packet; /* Will be freed after processing. */
		xfr.send = xfr_send_cb;
		xfr.session = w->fd;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		xfr_request(xfr_h, &xfr);
		debug_net("tcp: enqueued IXFR query\n");
		return;
	case DNSLIB_QUERY_NOTIFY:
	case DNSLIB_QUERY_UPDATE:
		break;
	}

	debug_net("tcp: got answer of size %zd.\n",
		  resp_len);

	dnslib_packet_free(&packet);

	/* Send answer. */
	if (res == KNOT_EOK) {
		assert(resp_len > 0);
		res = tcp_send(w->fd, qbuf, resp_len);

		/* Check result. */
		if (res != (int)resp_len) {
			debug_net("tcp: %s: failed: %d - %d.\n",
				  "socket_send()",
				  res, errno);
		}
	}

	return;
}

static void tcp_accept(struct ev_loop *loop, ev_io *w, int revents)
{
	tcp_io_t *tcp_w = (tcp_io_t *)w;

	/* Accept incoming connection. */
	debug_net("tcp: accepting connection on fd = %d\n", w->fd);
	int incoming = accept(w->fd, 0, 0);

	/* Evaluate connection. */
	if (incoming < 0) {
		if (errno != EINTR) {
			log_server_error("Cannot accept connection "
					 "(%d).\n", errno);
		}
	} else {
		/*! \todo Improve allocation performance. */
		tcp_io_t *conn = tcp_conn_new(loop, incoming, tcp_handle);
		if (conn) {
			conn->server = tcp_w->server;
			conn->stat = tcp_w->stat;
			conn->io_h = tcp_w->io_h;
		}
	}
}

static void tcp_interrupt(iohandler_t *h)
{
	/* For each thread in unit. */
	for (unsigned i = 0; i < h->unit->size; ++i) {
		tcp_io_t *w = (tcp_io_t *)(h->unit->threads[i]->data);

		/* Only if watcher exists and isn't I/O handler. */
		if (w && (void*)w != (void*)h) {
			/* Stop master socket watcher. */
			if (w->io.fd >= 0) {
				ev_io_stop(w->loop, (ev_io *)w);
			}

			/* Break loop. */
			ev_unloop(w->loop, EVUNLOOP_ALL);
		}
	}
}

static void tcp_loop_install(dthread_t *thread, int fd, tcp_cb_t cb)
{
	iohandler_t *handler = (iohandler_t *)thread->data;

	/* Install interrupt handler. */
	handler->interrupt = tcp_interrupt;

	/* Create event loop. */
	/*! \todo Maybe check for EVFLAG_NOSIGMASK support? */
	struct ev_loop *loop = ev_loop_new(0);

	/* Watch bound socket if exists. */
	tcp_io_t *w = tcp_conn_new(loop, fd, cb);
	if (w) {
		w->io_h = handler;
		w->server = handler->server;
		w->stat = 0; //!< \todo Implement stat.
	}

	/* Reinstall as thread-specific data. */
	thread->data = w;
}

static void tcp_loop_uninstall(dthread_t *thread)
{
	tcp_io_t *w = (tcp_io_t *)thread->data;

	/* Free watcher if exists. */
	if (w) {
		ev_loop_destroy(w->loop);
		free(w);
	}

	/* Invalidate thread data. */
	thread->data = 0;
}

/*! \brief Switch event loop in threading unit in RR fashion
 *         and accept connection in it.
 */
static void tcp_accept_rr(struct ev_loop *loop, ev_io *w, int revents)
{
	tcp_io_t *tcp_w = (tcp_io_t *)w;

	/* Select next loop thread. */
	dt_unit_t *unit = tcp_w->io_h->unit;
	dthread_t *thr = unit->threads[tcp_w->data];

	/* Select loop from selected thread. */
	tcp_io_t *thr_w = (tcp_io_t *)thr->data;
	if (thr_w) {
		loop = thr_w->loop;
	}

	/* Move to next thread in unit. */
	tcp_w->data = get_next_rr(tcp_w->data, unit->size);

	/* Accept incoming connection in target loop. */
	tcp_accept(loop, w, revents);
}

static int tcp_loop_run(dthread_t *thread)
{
	debug_dt("dthreads: [%p] running TCP loop, state: %d\n",
		 thread, thread->state);

	/* Fetch loop. */
	tcp_io_t *w = (tcp_io_t *)thread->data;

	/* Accept clients. */
	debug_net("tcp: loop started, backend = 0x%x\n", ev_backend(w->loop));
	for (;;) {

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Run event loop for accepting connections. */
		ev_loop(w->loop, 0);
	}

	/* Stop whole unit. */
	debug_net("tcp: loop finished\n");

	return KNOT_EOK;
}

int tcp_loop_master_rr(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;

	/* Check socket. */
	if (handler->fd < 0) {
		debug_net("tcp_master: null socket recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	debug_net("tcp_master: threading unit master with %d workers\n",
		  thread->unit->size - 1);

	int dupfd = dup(handler->fd);
	int ret = tcp_loop(thread, dupfd, tcp_accept_rr);
	close(dupfd);

	return ret;
}

/*
 * Public APIs.
 */

int tcp_send(int fd, uint8_t *msg, size_t msglen)
{

	/*! \brief TCP corking.
	 *  \see http://vger.kernel.org/~acme/unbehaved.txt
	 */
#ifdef TCP_CORK
	int cork = 1;
	setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
#endif

	/* Send message size. */
	unsigned short pktsize = htons(msglen);
	int sent = send(fd, &pktsize, sizeof(pktsize), 0);
	if (sent < 0) {
		return KNOT_ERROR;
	}

	/* Send message data. */
	sent = send(fd, msg, msglen, 0);
	if (sent < 0) {
		return KNOT_ERROR;
	}

#ifdef TCP_CORK
	/* Uncork. */
	cork = 0;
	setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
#endif
	return sent;
}

int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr)
{
	/* Receive size. */
	unsigned short pktsize = 0;
	int n = recv(fd, &pktsize, sizeof(unsigned short), 0);
	if (n < 0) {
		return KNOT_ERROR;
	}

	pktsize = ntohs(pktsize);

	// Check packet size for NULL
	if (pktsize == 0) {
		return KNOT_ERROR;
	}

	debug_net("tcp: incoming packet size=%hu on fd=%d\n",
		  pktsize, fd);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Receive payload. */
	n = recv(fd, buf, pktsize, 0);
	if (n <= 0) {
		return KNOT_ERROR;
	}

	/* Get peer name. */
	if (addr) {
		socklen_t alen = addr->len;
		getpeername(fd, addr->ptr, &alen);
	}

	debug_net("tcp: received packet size=%hu on fd=%d\n",
		  pktsize, fd);

	return n;
}

int tcp_loop(dthread_t *thread, int fd, tcp_cb_t cb)
{
	/* Install event loop. */
	tcp_loop_install(thread, fd, cb);

	/* Run event loop. */
	int ret = tcp_loop_run(thread);

	/* Uninstall event loop. */
	tcp_loop_uninstall(thread);

	return ret;
}

int tcp_loop_master(dthread_t *thread)
{
	iohandler_t *handler = (iohandler_t *)thread->data;

	/* Check socket. */
	if (handler->fd < 0) {
		debug_net("tcp_master: null socket recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	debug_net("tcp_master: created with %d workers\n",
		  thread->unit->size - 1);

	int dupfd = dup(handler->fd);
	int ret = tcp_loop(thread, dupfd, tcp_accept);
	close(dupfd);

	return ret;
}

int tcp_loop_worker(dthread_t *thread)
{
	return tcp_loop(thread, -1, tcp_noop);
}

int tcp_loop_unit(dt_unit_t *unit)
{
	if (unit->size < 1) {
		return KNOT_EINVAL;
	}

	/*! \todo Implement working master+worker threads. */
	/* Repurpose first thread as master (unit controller). */
	//dt_repurpose(unit->threads[0], tcp_loop_master_rr, 0);

	/* Repurpose remaining threads as workers. */
	//for (unsigned i = 1; i < unit->size; ++i) {
	//	dt_repurpose(unit->threads[i], tcp_loop_worker, 0);
	//}

	for (unsigned i = 0; i < 1; ++i) {
		dt_repurpose(unit->threads[i], tcp_loop_master, 0);
	}

	return KNOT_EOK;
}
