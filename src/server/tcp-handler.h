/*!
  * \file tcp-handler.h
  *
  * TCP sockets threading model.
  *
  * The master socket distributes incoming connections among
  * the worker threads ("buckets"). Each threads processes it's own
  * set of sockets, and eliminates mutual exclusion problem by doing so.
  */

#ifndef TCPHANDLER_H
#define TCPHANDLER_H

#include "socket.h"
#include "server.h"
#include "dthreads.h"

int tcp_master (dthread_t* thread);

#endif
