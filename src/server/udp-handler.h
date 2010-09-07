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

#include "socket-manager.h"

void *udp_master( void *obj );
void *udp_worker( void *obj );

#endif
