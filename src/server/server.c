#include "server.h"
#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <stdio.h>

#define CUTE_DEBUG

/*----------------------------------------------------------------------------*/

static const int DEFAULT_THR_COUNT = 2;
static const unsigned short DEFAULT_PORT = 53535;

/*----------------------------------------------------------------------------*/

cute_server *cute_create()
{
#ifdef CUTE_DEBUG
    printf("Creating Server structure..\n");
#endif
    cute_server *server = malloc(sizeof(cute_server));
    if (server == NULL) {
        ERR_ALLOC_FAILED;
        return NULL;
    }
#ifdef CUTE_DEBUG
    printf("Done\n\n");
#endif

#ifdef CUTE_DEBUG
    printf("Creating Zone Database structure..\n");
#endif
    server->zone_db = zdb_create();
    if (server->zone_db == NULL) {
        return NULL;
    }
#ifdef CUTE_DEBUG
    printf("Done\n\n");
#endif

#ifdef CUTE_DEBUG
    printf("Creating Name Server structure..\n");
#endif
    server->nameserver = ns_create(server->zone_db);
    if (server->nameserver == NULL) {
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }
#ifdef CUTE_DEBUG
    printf("Done\n\n");
#endif

#ifdef CUTE_DEBUG
    printf("Creating Socket Manager structure..\n");
#endif
    server->socket_mgr = sm_create(server->nameserver);
    if (server->socket_mgr == NULL) {
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }
#ifdef CUTE_DEBUG
    printf("Done\n\n");
#endif

#ifdef CUTE_DEBUG
    printf("Creating Dispatcher structure..\n");
#endif
    server->dispatcher = dpt_create(DEFAULT_THR_COUNT, sm_listen,
                                    server->socket_mgr);
    if (server->dispatcher == NULL) {
        sm_destroy(&server->socket_mgr);
        ns_destroy(&server->nameserver);
        zdb_destroy(&server->zone_db);
        free(server);
        return NULL;
    }
#ifdef CUTE_DEBUG
    printf("Done\n\n");
#endif

    return server;
}

/*----------------------------------------------------------------------------*/

int cute_start( cute_server *server, const char *filename )
{
#ifdef CUTE_DEBUG
    printf("Parsing zone file %s..\n", filename);
#endif
    if (zp_parse_zone(filename, server->zone_db) != 0) {
        return -1;
    }

#ifdef CUTE_DEBUG
    printf("Opening sockets..\n");
#endif
    if (sm_open_socket(server->socket_mgr, DEFAULT_PORT) != 0) {
        return -1;
    }

#ifdef CUTE_DEBUG
    printf("Starting the Dispatcher..\n");
#endif
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
