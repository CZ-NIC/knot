/*!
  * \file udp-handler.h
  *
  * UDP sockets threading model.
  *
  * The master socket locks one worker thread at a time
  * and saves events in it's own backing store for asynchronous processing.
  * The worker threads work asynchronously in thread pool.
  */

#ifndef UDPHANDLER_H
#define UDPHANDLER_H

#include "socket.h"
#include "server.h"
#include "dthreads.h"

int udp_master (dthread_t* thread);

#endif
