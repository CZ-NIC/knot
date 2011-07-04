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
 * \todo Improve documentation of TCP pool API and use proper error codes.
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
