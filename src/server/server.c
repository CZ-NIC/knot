#include "server.h"
#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/

static const int DEFAULT_THR_COUNT = 2;
static const unsigned short DEFAULT_PORT = 53535;

/*----------------------------------------------------------------------------*/

cute_server *cute_create()
{
    debug_server("Creating Server structure..\n");
    cute_server *server = malloc(sizeof(cute_server));
    if (server == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Zone Database structure..\n");

    server->zone_db = zdb_create();
    if (server->zone_db == NULL) {
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Name Server structure..\n");

    server->nameserver = ns_create(server->zone_db);
    if (server->nameserver == NULL) {
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Socket Manager structure..\n");

    server->socket_mgr = sm_create(server->nameserver);
    if (server->socket_mgr == NULL) {
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    debug_server("Done\n\n");
    debug_server("Creating Dispatcher structure..\n");

    server->dispatcher = dpt_create(DEFAULT_THR_COUNT, sm_listen,
                                    server->socket_mgr);
    if (server->dispatcher == NULL) {
        sm_destroy(&server->socket_mgr);
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }

    debug_server("Done\n\n");

    return server;
}

/*----------------------------------------------------------------------------*/

int cute_start( cute_server *server, const char *filename )
{
    debug_server("Parsing zone file %s..\n", filename);
    if (zp_parse_zone(filename, server->zone_db) != 0) {
        return -1;
    }

    debug_server("Opening sockets..\n");
    if (sm_open_socket(server->socket_mgr, DEFAULT_PORT) != 0) {
        return -1;
    }

    debug_server("Starting the Dispatcher..\n");
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
