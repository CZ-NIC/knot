#ifndef SERVER
#define SERVER

#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"

/*----------------------------------------------------------------------------*/

typedef struct cute_server {
    sm_manager *socket_mgr;
    dpt_dispatcher *dispatcher;
    ns_nameserver *nameserver;
    zdb_database *zone_db;
} cute_server;

/*----------------------------------------------------------------------------*/

cute_server *cute_create();

int cute_start( cute_server *server );

void cute_destroy( cute_server **server );

/*----------------------------------------------------------------------------*/

#endif
