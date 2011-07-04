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

#include <ev.h>

#include "knot/server/socket.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

/*! \brief TCP event callback. */
typedef void (*tcp_cb_t)(struct ev_loop *, ev_io*, int);

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
 * \brief Generic TCP event loop.
 *
 * Run TCP handler event loop.
 *
 * \param thread Associated thread from DThreads unit.
 * \param fd First descriptor to be watched (or -1).
 * \param cb Callback on fd event.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_loop(dthread_t *thread, int fd, tcp_cb_t cb);

/*!
 * \brief TCP event loop for accepting connections.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_loop_master(dthread_t *thread);

/*!
 * \brief TCP event loop for processing requests.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_loop_worker(dthread_t *thread);

/*!
 * \brief Create TCP event handler from threading unit.
 *
 * Set-up threading unit for processing TCP requests.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_loop_unit(dt_unit_t *unit);

#endif // _KNOT_TCPHANDLER_H_

/*! @} */
