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

#include "knot/server/socket.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

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
