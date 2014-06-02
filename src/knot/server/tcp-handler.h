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
 * \addtogroup server
 * @{
 */

#pragma once

#include <stdint.h>

#include "knot/server/net.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

/* Constants */
#define TCP_SWEEP_INTERVAL 2 /* [secs] granularity of connection sweeping */

/*!
 * \brief Accept a TCP connection.
 * \param fd Associated socket.
 *
 * \retval Created connection fd if success.
 * \retval <0 on error.
 */
int tcp_accept(int fd);

/*!
 * \brief Receive a block of data from TCP socket with wait.
 *
 * \param fd  File descriptor.
 * \param buf Data buffer.
 * \param len Block length.
 * \param timeout Timeout for the operation, NULL for infinite.
 *
 * \return number of bytes received or an error
 */
int tcp_recv_data(int fd, uint8_t *buf, int len, struct timeval *timeout);

/*!
 * \brief Send a TCP message.
 *
 * \param fd Associated socket.
 * \param msg Buffer for a query wireformat.
 * \param msglen Buffer maximum size.
 *
 * \retval Number of sent data on success.
 * \retval KNOT_ERROR on error.
 */
int tcp_send_msg(int fd, const uint8_t *msg, size_t msglen);

/*!
 * \brief Receive a TCP message.
 *
 * \param fd Associated socket.
 * \param buf Buffer for incoming bytestream.
 * \param len Buffer maximum size.
 * \param timeout Message receive timeout.
 *
 * \retval Number of read bytes on success.
 * \retval KNOT_ERROR on error.
 * \retval KNOT_ENOMEM on potential buffer overflow.
 */
int tcp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout);

/*!
 * \brief TCP handler thread runnable.
 *
 * Listens to both bound TCP sockets for client connections and
 * serves TCP clients. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int tcp_master(dthread_t *thread);

/*!
 * \brief Destructor for TCP handler thread.
 */
int tcp_master_destruct(dthread_t *thread);

/*! @} */
