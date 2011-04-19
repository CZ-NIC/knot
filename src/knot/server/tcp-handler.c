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

#include "knot/common.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/other/error.h"
#include "knot/stat/stat.h"
#include "dnslib/packet.h"

/*! \brief TCP connection pool. */
typedef struct tcp_pool_t {
	int                epfd;       /*!< Epoll socket. */
	int                evcount;    /*!< Epoll events counter */
	struct epoll_event *events;    /*!< Epoll events backing store. */
	int                ebs_size;   /*!< Epoll events backing store size. */
	pthread_mutex_t    mx;         /*!< Pool synchronisation lock. */
	ns_nameserver_t    *ns;        /* reference to name server */
	iohandler_t        *io_h;      /* master I/O handler */
	xfrhandler_t       *xfr_h;     /* XFR handler */
	stat_t             *stat;      /* statistics gatherer */
} tcp_pool_t;

/*
 * Forward decls.
 */
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
 * \brief Send TCP message.
 *
 * \param fd Associated socket.
 * \param msg Buffer for a query wireformat.
 * \param msglen Buffer maximum size.
 *
 * \retval Number of sent data on success.
 * \retval KNOT_ERROR on error.
 */
static inline int tcp_send(int fd, uint8_t *msg, size_t msglen)
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

/*!
 * \brief Send TCP message.
 *
 * \param fd Associated socket.
 * \param buf Buffer for incoming bytestream.
 * \param len Buffer maximum size.
 * \param addr Source address.
 *
 * \retval Number of read bytes on success.
 * \retval KNOT_ERROR on error.
 * \retval KNOT_ENOMEM on potential buffer overflow.
 */
static inline int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr)
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
	n = recvfrom(fd, buf, pktsize, 0, addr->ptr, &addr->len);
	if (n <= 0) {
		return KNOT_ERROR;
	}

	return n;
}

/*!
 * \brief TCP event handler function.
 *
 * Handle single TCP event.
 *
 * \param pool Associated connection pool.
 * \param fd Associated socket.
 * \param qbuf Buffer for a query wireformat.
 * \param qbuf_maxlen Buffer maximum size.
 */
static inline int tcp_handle(tcp_pool_t *pool, int fd,
			     uint8_t *qbuf, size_t qbuf_maxlen)
{
	sockaddr_t addr;
	if (socket_initaddr(&addr, pool->io_h->type) != KNOT_EOK) {
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
	dnslib_response_t *resp = dnslib_response_new(qbuf_maxlen);
	size_t resp_len = qbuf_maxlen; // 64K

	/* Parse query. */
	dnslib_query_t qtype = DNSLIB_QUERY_NORMAL;
	int res = ns_parse_query(qbuf, n, resp, &qtype);
	if (unlikely(res != KNOT_EOK)) {

		/* Send error response on dnslib RCODE. */
		if (res > 0) {
			uint16_t pkt_id = dnslib_packet_get_id(qbuf);
			ns_error_response(pool->ns, pkt_id, res,
					  qbuf, &resp_len);
		}

		dnslib_response_free(&resp);
		return res;
	}

	/* Handle query. */
	ns_xfr_t xfr;
	switch(qtype) {
	case DNSLIB_QUERY_NORMAL:
		res = ns_answer_normal(pool->ns, resp, qbuf, &resp_len);
		break;
	case DNSLIB_QUERY_AXFR:
		xfr.response = resp;
		xfr.send = tcp_send;
		xfr.session = fd;
		xfr.response_wire = 0;
		xfr.rsize = 0;
		xfr_request(pool->xfr_h, &xfr);
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

	dnslib_response_free(&resp);

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
 * \brief Create new TCP pool.
 *
 * Create and initialize new TCP pool with empty set.
 *
 * \param handler Associated I/O handler.
 * \retval New instance on success.
 * \retval NULL on errors.
 */
static tcp_pool_t *tcp_pool_new(iohandler_t *handler)
{
	// Alloc
	tcp_pool_t *pool = malloc(sizeof(tcp_pool_t));
	if (pool == 0) {
		return 0;
	}

	// Initialize
	memset(pool, 0, sizeof(tcp_pool_t));
	pool->io_h = handler;
	pool->ns = handler->server->nameserver;
	pool->evcount = 0;
	pool->ebs_size = 0;
	pool->xfr_h = handler->server->xfr_h;

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

	// Create stat gatherer
	STAT_INIT(pool->stat);
	stat_set_protocol(pool->stat, stat_TCP);

	return pool;
}

/*! \brief Delete TCP pool instance. */
static void tcp_pool_del(tcp_pool_t **pool)
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

	// Free
	free((*pool));
	*pool = 0;
}

/*!
 * \brief Add socket to the TCP pool.
 *
 * \param pool Given TCP pool.
 * \param newsock Socket to be added to the TCP pool.
 * \param events Events to be registered (usually just EPOLLIN).
 * \retval 0 on success.
 * \retval <0 on error.
 */
static int tcp_pool_add(tcp_pool_t* pool, int newsock, uint32_t events)
{
	if (!pool) {
		return -1;
	}

	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));

	// All polled events should use non-blocking mode.
	int old_flag = fcntl(newsock, F_GETFL, 0);
	if (fcntl(newsock, F_SETFL, old_flag | O_NONBLOCK) == -1) {
		log_server_error("Error setting non-blocking mode "
		                 "on the socket.\n");
		return -1;
	}

	// Register to epoll
	ev.data.fd = newsock;
	ev.events = events;
	if (epoll_ctl(pool->epfd, EPOLL_CTL_ADD, newsock, &ev) != 0) {
		debug_net("Failed to add socket to "
			  "event set (%d).\n",
			  errno);
		return -1;
	}

	return 0;
}

/*!
 * \brief Remove socket from a TCP pool.
 */
static int tcp_pool_remove(tcp_pool_t* pool, int socket)
{
	if (!pool) {
		return -1;
	}

	// Compatibility with kernels < 2.6.9, require non-0 ptr.
	struct epoll_event ev;

	if (epoll_ctl(pool->epfd, EPOLL_CTL_DEL, socket, &ev) != 0) {
		debug_net("Failed to remove socket from "
			  "event set (%d).\n",
			  errno);
		return -1;
	}

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
static inline int tcp_disconnect(tcp_pool_t *pool, int fd)
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

/*!
 * \brief TCP pool main function.
 *
 * TCP pool receives new connection and organizes them into it's own pool.
 * Handled connections are then polled for events.
 * TCP pooling scales almost linearly with the number of threads.
 *
 * \retval 0 on success.
 * \retval <0 on error.
 */
static int tcp_pool(dthread_t *thread)
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
				ret = tcp_handle(pool, fd, qbuf, sizeof(qbuf));
				if (ret != KNOT_EOK) {
					tcp_disconnect(pool, fd);
				}
			}

			debug_net("tcp: pool #%d finished fd=%d (%d remain).\n",
			          pool->epfd, fd, pool->evcount);
		}
	}

	// If exiting, cleanup
	if (pool->io_h->state == ServerIdle) {
		debug_net("tcp: pool #%d is finishing\n", pool->epfd);
		tcp_pool_del(&pool);
		return 0;
	}

	debug_net("tcp: pool #%d going to idle.\n", pool->epfd);
	return 0;
}

/*
 * Public APIs.
 */

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
				dt_repurpose(t, &tcp_pool, tcp_pool_new(handler));
				debug_dt("dthreads: [%p] repurposed "
				         "as TCP pool\n", t);
			}

			// Add incoming socket to selected pool
			tcp_pool_t *pool = (tcp_pool_t *)t->_adata;
			tcp_pool_lock(pool);
			debug_net("tcp_master: accept: assigned socket %d "
			          "to pool #%d\n",
			          incoming, pool_id);

			if (tcp_pool_add(pool, incoming, EPOLLIN) == 0) {
				++pool->evcount;
			}

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
