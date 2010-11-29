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

#ifndef _CUTEDNS_UDPHANDLER_H_
#define _CUTEDNS_UDPHANDLER_H_

#include "socket.h"
#include "server.h"
#include "dthreads.h"

/*!
 * \brief UDP handler thread runnable.
 *
 * Listen to DNS datagrams in a loop on a UDP socket and
 * reply to them. This runnable is designed to be used as coherent
 * and implements cancellation point.
 *
 * \param thread Associated thread from DThreads unit.
 *
 * \retval  0 On success.
 * \retval <0 If an error occured.
 */
int udp_master(dthread_t *thread);

#endif

/*! @} */

