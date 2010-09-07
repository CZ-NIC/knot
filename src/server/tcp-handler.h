#ifndef TCPHANDLER_H
#define TCPHANDLER_H

#include "socket-manager.h"

void *tcp_master( void *obj );
void *tcp_worker( void *obj );

#endif
