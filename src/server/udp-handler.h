/*!
 * \file udp-handler.h
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

int udp_master(dthread_t *thread);

#endif

/*! @} */

