/*!
 * \file udp-handler.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief UDP sockets threading model.
 *
 * The master socket locks one worker thread at a time
 * and saves events in it's own backing store for asynchronous processing.
 * The worker threads work asynchronously in thread pool.
 *
 * \addtogroup server
 * @{
 */

#ifndef _KNOTDUDPHANDLER_H_
#define _KNOTDUDPHANDLER_H_

#include "knot/server/socket.h"
#include "knot/server/server.h"
#include "knot/server/dthreads.h"

/*!
 * \brief UDP handler thread runnable.
 *
 * Listen to DNS datagrams in a loop on a UDP socket and
 * reply to them. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval KNOTDEOK on success.
 * \retval KNOTDEINVAL invalid parameters.
 */
int udp_master(dthread_t *thread);

#endif

/*! @} */
