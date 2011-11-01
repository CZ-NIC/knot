/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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

#ifndef _KNOTD_TCPHANDLER_H_
#define _KNOTD_TCPHANDLER_H_

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
 * \retval KNOTD_ERROR on error.
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
 * \retval KNOTD_ERROR on error.
 * \retval KNOTD_ENOMEM on potential buffer overflow.
 */
int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr);

/*!
 * \brief TCP event loop for accepting connections.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 */
int tcp_loop_master(dthread_t *thread);

/*!
 * \brief TCP event loop for processing requests.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 */
int tcp_loop_worker(dthread_t *thread);

/*!
 * \brief Create TCP event handler from threading unit.
 *
 * Set-up threading unit for processing TCP requests.
 *
 * \param ioh Associated I/O handler.
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL invalid parameters.
 */
int tcp_loop_unit(iohandler_t *ioh, dt_unit_t *unit);

#endif // _KNOTD_TCPHANDLER_H_

/*! @} */
