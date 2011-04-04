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
#include "knot/server/name-server.h"
#include "knot/other/error.h"
#include "knot/stat/stat.h"

/*! \brief TCP connection pool. */
typedef struct tcp_pool_t {
	int                epfd;       /*!< Epoll socket. */
	int                evcount;    /*!< Epoll events counter */
	struct epoll_event *events;    /*!< Epoll events backing store. */
	int                ebs_size;   /*!< Epoll events backing store size. */
	pthread_mutex_t    mx;         /*!< Pool synchronisation lock. */
	ns_nameserver      *ns;        /* reference to name server */
	iohandler_t        *handler;   /* master I/O handler */
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
 * \brief TCP query answering function.
 *
 * Socket receives a single query a replies to it.
 *
 * \param fd Associated socket.
 * \param src Buffer for a received query.
 * \param inbuf_sz Read buffer maximum size.
 * \param dest Buffer for reply.
 * \param outbuf_sz Reply buffer maximum size.
 * \param pool Associated connection pool.
 */
static inline int tcp_answer(int fd, uint8_t *src, int inbuf_sz, uint8_t *dest,
                              int outbuf_sz, tcp_pool_t *pool)
{
	// Receive size
	unsigned short pktsize = 0;
	int n = recv(fd, &pktsize, sizeof(unsigned short), 0);
	pktsize = ntohs(pktsize);
	debug_net("tcp: incoming packet size on %d: %u buffer size: %u\n",
	          fd, (unsigned) pktsize, (unsigned) inbuf_sz);

	// Receive payload
	if (n > 0 && pktsize > 0) {
		if (pktsize <= inbuf_sz) {
			/*! \todo Check buffer overflow. */
			n = recv(fd, src, pktsize, 0);
		} else {
			/*! \todo Buffer too small error code. */
			n = 0;
			return -1;
		}
	}

	//! \todo Real address;
	struct sockaddr_in faddr;
	faddr.sin_family = AF_INET;
	faddr.sin_port = htons(0);
	faddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	stat_get_first(pool->stat, (struct sockaddr*)&faddr);

	// Check read result
	if (n > 0) {

		// Send answer
		size_t answer_size = outbuf_sz - sizeof(short);
		int res = ns_answer_request(pool->ns, src, n,
		                            dest + sizeof(short),
		                            &answer_size);

		debug_net("tcp: answer wire format (size %u, result %d).\n",
		          (unsigned) answer_size, res);

		if (res >= 0) {

			/*! \brief TCP corking.
			 *  \see http://vger.kernel.org/~acme/unbehaved.txt
			 */
			int cork = 1;
			setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));

			// Copy header
			((unsigned short *) dest)[0] = htons(answer_size);
			int sent = -1;
			while (sent < 0) {
				sent = send(fd, dest,
				            answer_size + sizeof(short),
				            0);
			}

			// Uncork
			cork = 0;
			setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
			stat_get_second(pool->stat);
			debug_net("tcp: sent answer to %d\n", fd);
		}
	}
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
	pool->handler = handler;
	pool->ns = handler->server->nameserver;
	pool->evcount = 0;
	pool->ebs_size = 0;

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
		log_server_error("tcp: Error setting non-blocking mode "
		                 "on the socket.\n");
		return -1;
	}

	// Register to epoll
	ev.data.fd = newsock;
	ev.events = events;
	if (epoll_ctl(pool->epfd, EPOLL_CTL_ADD, newsock, &ev) != 0) {
		log_server_error("tcp: Failed to add socket to "
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
		log_server_error("tcp: Failed to remove socket from "
				 "event set (%d).\n",
				 errno);
		return -1;
	}

	return 0;
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
	/*!
	 * \todo Use custom allocator.
	 *       Although this is much cheaper,
	 *       16kB worth of buffers *may* pose a problem.
	 */
	tcp_pool_t *pool = (tcp_pool_t *)thread->data;
	uint8_t buf[SOCKET_MTU_SZ];
	uint8_t answer[SOCKET_MTU_SZ];

	int nfds = 0;
	debug_net("tcp: entered pool #%d\n", pool->epfd);

	// Poll new data from clients
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

		// Evaluate
		debug_net("tcp: pool #%d, %d events (%d sockets).\n",
		          pool->epfd, nfds, pool->evcount);

		int fd = 0;
		for (int i = 0; i < nfds; ++i) {

			// Get client fd
			fd = pool->events[i].data.fd;

			debug_net("tcp: pool #%d processing fd=%d.\n",
			          pool->epfd, fd);
			tcp_answer(fd, buf, SOCKET_MTU_SZ,
			           answer,  SOCKET_MTU_SZ,
			           pool);
			debug_net("tcp: pool #%d finished fd=%d (%d remain).\n",
			          pool->epfd, fd, pool->evcount);

			// Disconnect
			debug_net("tcp: disconnected: %d\n", fd);
			tcp_pool_lock(pool);
			tcp_pool_remove(pool, fd);
			--pool->evcount;
			socket_close(fd);
			tcp_pool_unlock(pool);
		}
	}

	// If exiting, cleanup
	if (pool->handler->state == ServerIdle) {
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
			return -1;
		}

		// Accept on master socket
		int incoming = accept(master_sock, 0, 0);

		// Register to worker
		if (incoming < 0) {
			if (errno != EINTR) {
				log_server_error("tcp_master: Cannot accept "
						 "connection (%d).\n",
						 errno);
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
