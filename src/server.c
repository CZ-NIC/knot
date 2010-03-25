#include "server.h"
#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/

static const int DEFAULT_THR_COUNT = 2;
static const unsigned short DEFAULT_PORT = 53535;

/*----------------------------------------------------------------------------*/

cute_server *cute_create()
{
    cute_server *server = malloc(sizeof(cute_server));
    if (server == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    server->zone_db = zdb_create();
    if (server->zone_db == NULL) {
        return NULL;
    }

    server->nameserver = ns_create(server->zone_db);
    if (server->nameserver == NULL) {
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    server->socket_mgr = sm_create(DEFAULT_PORT, server->nameserver);

    if (server->socket_mgr == NULL) {
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    server->dispatcher = dpt_create(DEFAULT_THR_COUNT, sm_listen,
                                    server->socket_mgr);

    if (server->dispatcher == NULL) {
        sm_destroy(&server->socket_mgr);
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    return server;
}

/*----------------------------------------------------------------------------*/

int cute_start( cute_server *server )
{
    return dpt_start(server->dispatcher);
}

/*----------------------------------------------------------------------------*/

void cute_destroy( cute_server **server )
{
    dpt_destroy(&(*server)->dispatcher);
    sm_destroy(&(*server)->socket_mgr);
    ns_destroy(&(*server)->nameserver);
    zdb_destroy(&(*server)->zone_db);
    free(*server);
    *server = NULL;
}
