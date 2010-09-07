#ifndef UDPHANDLER_H
#define UDPHANDLER_H

#include "socket-manager.h"

void *udp_master( void *obj );
void *udp_worker( void *obj );

#endif
