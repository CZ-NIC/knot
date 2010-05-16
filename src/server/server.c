#include "server.h"
#include "dispatcher.h"
#include "socket-manager.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/

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

    for(int i = 0; i < 2; i++) {
        server->manager[i] = sm_create(server->nameserver);
        if (server->manager[i] == NULL ) {
            ns_destroy(&server->nameserver);
            zdb_destroy(&server->zone_db);
            free(server);
            return NULL;
        }
    }

    // Register socket handlers
    sm_register_handler(server->manager[UDP], &sm_udp_handler);
    sm_register_handler(server->manager[TCP], &sm_tcp_handler);

    debug_server("Done\n\n");
    debug_server("Creating Dispatcher structure..\n");

    // Create master dispatchers
    for(int i = 0; i < 2; i++) {
        server->dispatcher[i] = dpt_create(1, &sm_listen, server->manager[i]);
        if (server->dispatcher[i] == NULL) {
            sm_destroy(&server->manager[UDP]);
            sm_destroy(&server->manager[TCP]);
            ns_destroy(&server->nameserver);
            zdb_destroy(&server->zone_db);
            free(server);
            return NULL;
        }
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
    server->manager[UDP]->is_running = 1;
    if (sm_open_socket(server->manager[UDP], DEFAULT_PORT, UDP) != 0) {
        perror("sm_open_socket");
        return -1;
    }
#ifdef CUTE_DEBUG
    printf("TCP(%d) ", DEFAULT_PORT); fflush(stdout);
#endif
    server->manager[TCP]->is_running = 1;
    if (sm_open_socket(server->manager[TCP], DEFAULT_PORT, TCP) != 0) {
#ifdef CUTE_DEBUG
        printf("[failed]\n");
#endif
        perror("sm_open_socket");
        return -1;
    }
#ifdef CUTE_DEBUG
    printf("\nDone\n\n");
#endif

    debug_server("Starting the Dispatcher..\n");

    // Start dispatchers
    int ret = 0;
    ret = dpt_start(server->dispatcher[TCP]);
#ifdef CUTE_DEBUG
    printf("   TCP handler: %u threads started.\n", server->dispatcher[TCP]->thread_count);
#endif
    ret += dpt_start(server->dispatcher[UDP]);
#ifdef CUTE_DEBUG
    printf("   UDP handler: %u threads started.\n", server->dispatcher[UDP]->thread_count);
#endif
    if(ret < 0)
        return ret;

    // Wait for dispatchers to finish
    ret = dpt_wait(server->dispatcher[TCP]);
#ifdef CUTE_DEBUG
    printf("TCP handler finished.\n");
#endif
    ret += dpt_wait(server->dispatcher[UDP]);
#ifdef CUTE_DEBUG
    printf("UDP handler finished.\n");
#endif
    return ret;
}

/*----------------------------------------------------------------------------*/

void cute_stop( cute_server *server )
{
    // Notify servers to stop
    for(int i = 0; i < 2; i++) {
        sm_stop(server->manager[i]);
    }
}

/*----------------------------------------------------------------------------*/

void cute_destroy( cute_server **server )
{
    dpt_destroy(&(*server)->dispatcher[UDP]);
    dpt_destroy(&(*server)->dispatcher[TCP]);
    sm_destroy(&(*server)->manager[UDP]);
    sm_destroy(&(*server)->manager[TCP]);
    ns_destroy(&(*server)->nameserver);
    zdb_destroy(&(*server)->zone_db);
    free(*server);
    *server = NULL;
}
