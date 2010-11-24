/*!
 * \file tcp-handler.h
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

#ifndef _CUTEDNS_TCPHANDLER_H_
#define _CUTEDNS_TCPHANDLER_H_

#include "socket.h"
#include "server.h"
#include "dthreads.h"

int tcp_master(dthread_t *thread);

#endif // _CUTEDNS_TCPHANDLER_H_

/*! @} */

