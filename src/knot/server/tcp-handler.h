/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief TCP sockets threading model.
 *
 * The master socket distributes incoming connections among
 * the worker threads ("buckets"). Each threads processes it's own
 * set of sockets, and eliminates mutual exclusion problem by doing so.
 */

#pragma once

#include "knot/server/dthreads.h"

#define TCP_BACKLOG_SIZE  10 /*!< TCP listen backlog size. */

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
