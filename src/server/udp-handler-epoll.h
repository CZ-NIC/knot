/*!
  * \file udp-handler.h
  *
  * UDP sockets threading model.
  *
  * The master socket locks one worker thread at a time
  * and saves events in it's own backing store for asynchronous processing.
  * The worker threads work asynchronously in thread pool.
  */

#ifndef UDPHANDLER_EPOLL_H
#define UDPHANDLER_EPOLL_H

#include "socket.h"
#include "server.h"

void *udp_epoll_master( void *obj );
void *udp_epoll_worker( void *obj );

#endif
