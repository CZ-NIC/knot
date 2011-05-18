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

#include "common/sockaddr.h"
#include "common/skip-list.h"
#include "knot/common.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/other/error.h"
#include "knot/stat/stat.h"
#include "dnslib/wire.h"

/*! \brief TCP connection pool. */
typedef struct tcp_pool_t {
	int                epfd;       /*!< Epoll socket. */
	int                evcount;    /*!< Epoll events counter */
	struct epoll_event *events;    /*!< Epoll events backing store. */
	int                ebs_size;   /*!< Epoll events backing store size. */
	skip_list_t        *ev_data;   /*!< User data for polled sockets. */
	pthread_mutex_t    mx;         /*!< Pool synchronisation lock. */
	server_t           *server;    /*!< Server instance. */
	tcp_event_f        on_event;   /* TCP event handler. */
	iohandler_t        *io_h;      /* master I/O handler */
	stat_t             *stat;      /* statistics gatherer */
} tcp_pool_t;

/*
 * Forward decls.
 */

/*!
 * \brief Compare function for skip-list.
 */
static int tcp_pool_compare(void *k1, void *k2)
{
	/* Key = socket filedescriptor. */
	ssize_t diff = (ssize_t)k1 - (ssize_t)k2;
	if (diff < 0) {
		return -1;
	}
	if (diff > 0) {
		return 1;
	}

	return 0;
}

/*! \brief Lock TCP pool. */
static inline int tcp_pool_lock(tcp_pool_t *pool)
{
	return pthread_mutex_lock(&pool->mx);
}

/*! \brief Unlock TCP pool. */
static inline int tcp_pool_unlock(tcp_pool_t *pool)
{
	return pthread_mutex_unlock(&pool->mx);
}

/*!
 * \brief TCP event handler function.
 *
 * Handle single TCP event.
 *
 * \param pool Associated connection pool.
 * \param fd Associated socket.
 * \param data Associated data.
 * \param qbuf Buffer for a query wireformat.
 * \param qbuf_maxlen Buffer maximum size.
 */
static inline int tcp_handle(tcp_pool_t *pool, int fd, void *data,
			     uint8_t *qbuf, size_t qbuf_maxlen)
{
	sockaddr_t addr;
	if (sockaddr_init(&addr, pool->io_h->type) != KNOT_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 pool->io_h->type);
		return KNOT_ENOTSUP;
	}

	/* Receive data. */
	int n = tcp_recv(fd, qbuf, qbuf_maxlen, &addr);
	if (n <= 0) {
		return KNOT_ERROR;
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
		ns_error_response(pool->server->nameserver, pkt_id,
				  DNSLIB_RCODE_SERVFAIL, qbuf, &resp_len);
		return KNOT_ENOMEM;
	}

	int res = ns_parse_packet(qbuf, n, packet, &qtype);
	if (unlikely(res != KNOT_EOK)) {

		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = dnslib_wire_get_id(qbuf);
			ns_error_response(pool->server->nameserver, pkt_id, res,
					  qbuf, &resp_len);
		}

//		dnslib_response_free(&resp);
		dnslib_packet_free(&packet);
		return res;
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
		res = ns_answer_normal(pool->server->nameserver, packet,
				       qbuf, &resp_len);
		break;
	case DNSLIB_QUERY_AXFR:
		memset(&xfr, 0, sizeof(ns_xfr_t));
		xfr.type = NS_XFR_TYPE_AOUT;
		xfr.query = packet;
		xfr.send = tcp_send;
		xfr.session = fd;
		xfr.wire = 0;
		xfr.wire_size = 0;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		xfr_request(pool->server->xfr_h, &xfr);
		debug_net("tcp: enqueued AXFR request size %zd.\n",
			  resp_len);
		return KNOT_EOK;
	case DNSLIB_QUERY_IXFR:
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
		res = tcp_send(fd, qbuf, resp_len);

		/* Check result. */
		if (res != (int)resp_len) {
			debug_net("tcp: %s: failed: %d - %d.\n",
				  "socket_send()",
				  res, errno);
		}
	}

	return res;
}

/*!
 * \brief Reserve backing store for a given number of sockets.
 *
 * \param pool Given TCP pool instance.
 * \param size Minimum requested backing store size.
 * \retval 0 on success.
 * \retval <0 on error.
 */
static int tcp_pool_reserve(tcp_pool_t *pool, uint size)
{
	if (pool->ebs_size >= size) {
		return 0;
	}

	// Alloc new events
	struct epoll_event *new_events =
	                malloc(size * sizeof(struct epoll_event));

	if (new_events == 0) {
		return -1;
	}

	// Free and replace old events backing-store
	if (pool->events != 0) {
		free(pool->events);
	}

	pool->ebs_size = size;
	pool->events = new_events;
	return 0;
}

/*!
 * \brief Disconnect TCP client.
 *
 * \param pool Associated connection pool.
 * \param fd Associated socket.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_ERROR on error.
 */
int tcp_disconnect(tcp_pool_t *pool, int fd)
{
	if (!pool || fd <= 0) {
		return KNOT_ERROR;
	}

	debug_net("tcp: disconnected: %d\n", fd);
	tcp_pool_lock(pool);
	int ret = tcp_pool_remove(pool, fd);
	--pool->evcount;
	socket_close(fd);
	tcp_pool_unlock(pool);
	return ret;
}

/*
 * Public APIs.
 */

tcp_pool_t *tcp_pool_new(server_t *server, tcp_event_f hfunc)
{
	// Alloc
	tcp_pool_t *pool = malloc(sizeof(tcp_pool_t));
	if (pool == 0) {
		return 0;
	}

	// Initialize
	memset(pool, 0, sizeof(tcp_pool_t));
	pool->io_h = 0;
	pool->evcount = 0;
	pool->ebs_size = 0;
	pool->server = server;
	pool->on_event = hfunc;

	// Create epoll fd
	pool->epfd = epoll_create(1);
	if (pool->epfd == -1) {
		free(pool);
		return 0;
	}

	// Alloc backing-store
	if (tcp_pool_reserve(pool, 1) != 0) {
		close(pool->epfd);
		free(pool);
		return 0;
	}

	// Initialize synchronisation
	if (pthread_mutex_init(&pool->mx, 0) != 0) {
		close(pool->epfd);
		free(pool->events);
		free(pool);
		return 0;
	}

	/* Create skip-list for TCP session data. */
	pool->ev_data = skip_create_list(tcp_pool_compare);
	if (!pool->ev_data) {
		pthread_mutex_destroy(&pool->mx);
		close(pool->epfd);
		free(pool->events);
		free(pool);
	}

	// Create stat gatherer
	STAT_INIT(pool->stat);
	stat_set_protocol(pool->stat, stat_TCP);

	return pool;
}

void tcp_pool_del(tcp_pool_t **pool)
{
	// Check
	if (pool == 0) {
		return;
	}

	// Close epoll fd
	close((*pool)->epfd);

	// Free backing store
	if ((*pool)->events != 0) {
		free((*pool)->events);
	}

	// Destroy synchronisation
	pthread_mutex_destroy(&(*pool)->mx);

	// Delete stat
	stat_free((*pool)->stat);

	// Delete session data
	skip_destroy_list(&(*pool)->ev_data, 0, free);

	// Free
	free((*pool));
	*pool = 0;
}

int tcp_pool_add(tcp_pool_t* pool, int sock, void *data)
{
	if (!pool) {
		return -1;
	}

	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));

	// All polled events should use non-blocking mode.
	int old_flag = fcntl(sock, F_GETFL, 0);
	if (fcntl(sock, F_SETFL, old_flag | O_NONBLOCK) == -1) {
		log_server_error("Error setting non-blocking mode "
		                 "on the socket.\n");
		return -1;
	}

	// Register to epoll
	ev.data.fd = sock;
	ev.events = EPOLLIN;
	if (epoll_ctl(pool->epfd, EPOLL_CTL_ADD, sock, &ev) != 0) {
		debug_net("Failed to add socket to "
			  "event set (%d).\n",
			  errno);
		return -1;
	}

	// Increase event count
	++pool->evcount;

	/* Append data. */
	skip_insert(pool->ev_data, (void*)((ssize_t)sock), data, 0);

	return 0;
}

int tcp_pool_remove(tcp_pool_t* pool, int sock)
{
	if (!pool) {
		return -1;
	}

	// Compatibility with kernels < 2.6.9, require non-0 ptr.
	struct epoll_event ev;

	if (epoll_ctl(pool->epfd, EPOLL_CTL_DEL, sock, &ev) != 0) {
		debug_net("Failed to remove socket from "
			  "event set (%d).\n",
			  errno);
		return -1;
	}

	/* Remove data if exist, data will be freed. */
	skip_remove(pool->ev_data, (void*)((ssize_t)sock), 0, free);

	return 0;
}

server_t* tcp_pool_server(tcp_pool_t *pool)
{
	return pool->server;
}

int tcp_pool(dthread_t *thread)
{
	tcp_pool_t *pool = (tcp_pool_t *)thread->data;

	debug_net("tcp: entered pool #%d\n", pool->epfd);

	// Poll new data from clients
	int nfds = 0;
	uint8_t qbuf[64 * 1024 - 1]; // 64K buffer
	while (pool->evcount > 0) {

		// Poll sockets
		tcp_pool_reserve(pool, pool->evcount * 2);
		nfds = epoll_wait(pool->epfd, pool->events,
				  pool->ebs_size, -1);

		// Cancellation point
		if (dt_is_cancelled(thread)) {
			debug_net("tcp: pool #%d thread is cancelled\n",
				  pool->epfd);
			break;
		}

		debug_net("tcp: pool #%d, %d events (%d sockets).\n",
			  pool->epfd, nfds, pool->evcount);

		for (int i = 0; i < nfds; ++i) {

			/* Get client fd. */
			int fd = pool->events[i].data.fd;

			/* Process. */
			debug_net("tcp: pool #%d processing fd=%d.\n",
				  pool->epfd, fd);

			/* Handle TCP request. */
			int ret = KNOT_EOK;
			if (pool->events[i].events & EPOLLERR) {
				tcp_disconnect(pool, fd);
			} else {
				/* Lookup associated data. */
				void *d = skip_find(pool->ev_data,
						    (void*)((size_t)fd));
				ret = pool->on_event(pool, fd, d,
						     qbuf, sizeof(qbuf));
				if (ret != KNOT_EOK) {
					tcp_disconnect(pool, fd);
				}
			}

			debug_net("tcp: pool #%d finished fd=%d (%d remain).\n",
				  pool->epfd, fd, pool->evcount);
		}
	}

	// If exiting, cleanup
	if (pool->io_h) {
		if (pool->io_h->state == ServerIdle) {
			debug_net("tcp: pool #%d is finishing\n", pool->epfd);
			tcp_pool_del(&pool);
			return 0;
		}
	}

	debug_net("tcp: pool #%d going to idle.\n", pool->epfd);
	return 0;
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
	debug_net("tcp: incoming packet size on %d: %hu buffer size: %zu\n",
		  fd, pktsize, len);

	// Check packet size for NULL
	if (pktsize == 0) {
		return KNOT_ERROR;
	}

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

	/*
	 * Create N pools of TCP connections.
	 * Each pool is responsible for its own
	 * set of clients.
	 *
	 * Pool instance is deallocated by their assigned thread.
	 */
	int pool_id = -1;

	// Accept clients
	debug_net("tcp: running 1 master with %d pools\n", unit->size - 1);
	for (;;) {

		// Cancellation point
		if (dt_is_cancelled(thread)) {
			debug_net("tcp: stopping (%d master, %d pools)\n",
				  1, unit->size - 1);
			return KNOT_EOK;
		}

		// Accept on master socket
		int incoming = accept(master_sock, 0, 0);

		// Register to worker
		if (incoming < 0) {
			if (errno != EINTR) {
				log_server_error("Cannot accept connection "
						 "(%d).\n", errno);
			}
		} else {

			// Select next pool (Round-Robin)
			dt_unit_lock(unit);
			int pool_count = unit->size - 1;
			pool_id = get_next_rr(pool_id, pool_count);
			dthread_t *t = unit->threads[pool_id + 1];

			// Allocate new pool if needed
			if (t->run != &tcp_pool) {
				tcp_pool_t *pool = tcp_pool_new(handler->server,
								tcp_handle);
				dt_repurpose(t, &tcp_pool, pool);
				pool->io_h = handler;

				debug_dt("dthreads: [%p] repurposed "
				         "as TCP pool\n", t);
			}

			// Add incoming socket to selected pool
			tcp_pool_t *pool = (tcp_pool_t *)t->_adata;
			tcp_pool_lock(pool);
			debug_net("tcp_master: accept: assigned socket %d "
			          "to pool #%d\n",
			          incoming, pool_id);

			tcp_pool_add(pool, incoming, 0);

			// Activate pool
			dt_activate(t);
			tcp_pool_unlock(pool);
			dt_unit_unlock(unit);
		}
	}


	// Stop whole unit
	debug_net("tcp: stopping (%d master, %d pools)\n", 1, unit->size - 1);
	return KNOT_EOK;
}
