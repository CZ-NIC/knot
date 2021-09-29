/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \brief UDP sockets threading model.
 *
 * The master socket locks one worker thread at a time
 * and saves events in it's own backing store for asynchronous processing.
 * The worker threads work asynchronously in thread pool.
 */

#pragma once

#include "knot/server/dthreads.h"

#define RECVMMSG_BATCHLEN 10 /*!< Default recvmmsg() batch size. */

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

/*! \brief Control message to fit IP_PKTINFO or IPv6_RECVPKTINFO, and TOS/ECN. */
typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(uint8_t)) + // TOS/ECN
                CMSG_SPACE(sizeof(struct in6_pktinfo))]; // Local addr            
} cmsg_pktinfo_t;

/*!
 * \brief UDP handler thread runnable.
 *
 * Listen to DNS datagrams in a loop on a UDP socket and
 * reply to them. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL invalid parameters.
 */
int udp_master(dthread_t *thread);
