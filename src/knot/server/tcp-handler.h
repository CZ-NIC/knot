/*!
 * \file tcp-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief TCP sockets threading model.
 *
 * The master socket distributes incoming connections among
 * the worker threads ("buckets"). Each threads processes it's own
 * set of sockets, and eliminates mutual exclusion problem by doing so.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOT_TCPHANDLER_H_
#define _KNOT_TCPHANDLER_H_

#include <stdint.h>

#include "knot/server/socket.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

/*! \brief TCP pool structure. */
struct tcp_pool_t;

/*!
 * \brief TCP event handler function prototype.
 *
 * Handle single TCP event.
 *
 * \param pool Associated connection pool.
 * \param fd Associated socket.
 * \param qbuf Buffer for a query wireformat.
 * \param qbuf_maxlen Buffer maximum size.
 */
typedef int (*tcp_handle_t)(struct tcp_pool_t *pool, int fd,
			     uint8_t *qbuf, size_t qbuf_maxlen);

/*!
 * \brief Create new TCP pool.
 *
 * Create and initialize new TCP pool with empty set.
 *
 * \param server Server instance.
 * \param hfunc TCP event handler.
 *
 * \retval New instance on success.
 * \retval NULL on errors.
 */
struct tcp_pool_t *tcp_pool_new(server_t *server, tcp_handle_t hfunc);

/*!
 * \brief Delete TCP pool instance.
 *
 * \param pool Pointer to pool instance.
 */
void tcp_pool_del(struct tcp_pool_t **pool);

/*!
 * \brief Add socket to the TCP pool.
 *
 * \param pool Given TCP pool.
 * \param newsock Socket to be added to the TCP pool.
 * \param events Events to be registered (usually just EPOLLIN).
 * \retval 0 on success.
 * \retval <0 on error.
 */
int tcp_pool_add(struct tcp_pool_t* pool, int newsock, uint32_t events);

/*!
 * \brief Remove socket from a TCP pool.
 */
int tcp_pool_remove(struct tcp_pool_t* pool, int socket);

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
int tcp_pool(dthread_t *thread);

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
int tcp_send(int fd, uint8_t *msg, size_t msglen);

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
int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr);

/*!
 * \brief TCP master socket runnable.
 *
 * Accepts new TCP connections and distributes them among the rest
 * of the threads in unit, which are repurposed as a TCP connection pools.
 * New pools are initialized ad-hoc, function implements a cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_master(dthread_t *thread);

#endif // _KNOT_TCPHANDLER_H_

/*! @} */
