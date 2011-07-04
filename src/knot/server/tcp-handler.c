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

/*! \brief TCP connection. */
typedef struct tcp_io_t {
	ev_io io;
	ns_nameserver_t  *ns;    /*!< Name server */
	iohandler_t      *io_h;  /*!< Master I/O handler. */
	xfrhandler_t     *xfr_h; /*!< XFR handler. */
	stat_t           *stat;  /*!< Statistics gatherer */
} tcp_io_t;

/*
 * Forward decls.
 */

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
	tcp_io_t *tcp_w = (tcp_io_t *)w;

	/* Check address type. */
	sockaddr_t addr;
	if (sockaddr_init(&addr, tcp_w->io_h->type) != KNOT_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 tcp_w->io_h->type);
//!		return KNOT_ENOTSUP;
		return;
	}

	/* Receive data. */
	uint8_t qbuf[65535]; /*! \todo This may be problematic. */
	size_t qbuf_maxlen = sizeof(qbuf);
	int n = tcp_recv(w->fd, qbuf, qbuf_maxlen, &addr);
	if (n <= 0) {
//!		return KNOT_ERROR;
		debug_net("tcp: client disconnected\n");
		ev_io_stop(loop, w);
		free(tcp_w);
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
		ns_error_response(tcp_w->ns, pkt_id, DNSLIB_RCODE_SERVFAIL,
				  qbuf, &resp_len);
//!		return KNOT_ENOMEM;
		return;
	}

	int res = ns_parse_packet(qbuf, n, packet, &qtype);
	if (unlikely(res != KNOT_EOK)) {

		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = dnslib_wire_get_id(qbuf);
			ns_error_response(tcp_w->ns, pkt_id, res,
					  qbuf, &resp_len);
		}

//		dnslib_response_free(&resp);
		dnslib_packet_free(&packet);
//!		return res;
		return;
	}

	/* Handle query. */
	ns_xfr_t xfr;
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
		res = ns_answer_normal(tcp_w->ns, packet, qbuf, &resp_len);
		break;
	case DNSLIB_QUERY_AXFR:
		xfr.query = packet;
		xfr.send = tcp_send;
		xfr.session = w->fd;
		xfr.wire = 0;
		xfr.wire_size = 0;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		xfr_request(tcp_w->xfr_h, &xfr);
		debug_net("tcp: enqueued AXFR query\n");
//!		return KNOT_EOK;
		return;
	case DNSLIB_QUERY_IXFR:
		memset(&xfr, 0, sizeof(ns_xfr_t));
		xfr.type = NS_XFR_TYPE_IOUT;
		xfr.query = packet; /* Will be freed after processing. */
		xfr.send = tcp_send;
		xfr.session = w->fd;
		xfr.wire = 0;
		xfr.wire_size = 0;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		xfr_request(tcp_w->xfr_h, &xfr);
		debug_net("tcp: enqueued IXFR query\n");
//!		return KNOT_EOK;
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

//!	return res;
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
		/*! \todo Store references to pending connections! */
		tcp_io_t *conn = malloc(sizeof(tcp_io_t));
		conn->ns = tcp_w->ns;
		conn->stat = tcp_w->stat;
		conn->xfr_h = tcp_w->xfr_h;
		conn->io_h = tcp_w->io_h;

		/* Register connection. */
		ev_io_init((ev_io *)conn, tcp_handle, incoming, EV_READ);
		ev_io_start(loop, (ev_io *)conn);
	}
}

static void tcp_interrupt(iohandler_t *h)
{
	/*! \todo Using default loop is sub-optimal solution. */
	ev_io *w = (ev_io *)h->data;
	struct ev_loop *loop = ev_default_loop(0);

	/* Stop master socket watcher. */
	ev_io_stop(loop, w);
	ev_unloop(loop, EVUNLOOP_ALL);
}

int tcp_send(int fd, uint8_t *msg, size_t msglen)
{

	/*! \brief TCP corking.
	 *  \see http://vger.kernel.org/~acme/unbehaved.txt
	 */
	int cork = 1;
	setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));

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

	/* Uncork. */
	cork = 0;
	setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
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

	debug_net("tcp: incoming packet size on %d: %hu buffer size: %zu\n",
		  fd, pktsize, len);

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

	return n;
}

int tcp_master(dthread_t *thread)
{
	dt_unit_t *unit = thread->unit;
	iohandler_t *handler = (iohandler_t *)thread->data;

	int master_sock = handler->fd;

	/* Check socket. */
	if (master_sock < 0) {
		debug_net("tcp_master: null socket recevied, finishing.\n");
		return KNOT_EINVAL;
	}

	debug_dt("dthreads: [%p] is TCP master, state: %d\n",
	         thread, thread->state);

	/* Trim other threads. */
	/*! \todo Multithreaded event-loop handling. */
	if (unit->size > 1) {
		dt_resize(unit, 1);
	}

	/* Create event loop. */
	struct ev_loop *loop = ev_default_loop(0);

	/* Install interrupt handler. */
	handler->interrupt = tcp_interrupt;

	/* Watch bound socket for incoming connections. */
	tcp_io_t *tcp_w = malloc(sizeof(tcp_io_t));
	tcp_w->io_h = handler;
	tcp_w->ns = handler->server->nameserver;
	tcp_w->stat = 0; //!< \todo Implement stat.
	tcp_w->xfr_h = handler->server->xfr_h;

	ev_io_init((ev_io *)tcp_w, tcp_accept, master_sock, EV_READ);
	ev_io_start(loop, (ev_io *)tcp_w);
	handler->data = tcp_w;

	/* Accept clients. */
	debug_net("tcp: running 1 master with %d pools\n", unit->size - 1);
	for (;;) {

		// Cancellation point
		if (dt_is_cancelled(thread)) {
			debug_net("tcp: stopping (%d master, %d pools)\n",
				  1, unit->size - 1);
			return KNOT_EOK;
		}

		/*! \bug Implement cancellation point somehow. */
		ev_loop(loop, 0);
	}

	// Stop whole unit
	debug_net("tcp: stopping (%d master, %d pools)\n", 1, unit->size - 1);
	handler->data = 0;
	free(tcp_w);


	return KNOT_EOK;
}
