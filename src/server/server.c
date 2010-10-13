#include "server.h"
#include "udp-handler.h"
#include "tcp-handler.h"
#include "zone-database.h"
#include "name-server.h"
#include "zone-parser.h"
#include <stdio.h>

/*----------------------------------------------------------------------------*/

static const unsigned short DEFAULT_PORT = 53531;
static const int DEFAULT_THR_COUNT = 3;

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

    // Create socket handlers
    server->manager[UDP] = sm_create(server->nameserver, &udp_master, &udp_worker, DEFAULT_THR_COUNT);
    server->manager[TCP] = sm_create(server->nameserver, &tcp_master, &tcp_worker, 2*DEFAULT_THR_COUNT);

    // Check socket handlers
    for(int i = 0; i < 2; i++) {
        if (server->manager[i] == NULL ) {

            if(i == 1) {
                sm_destroy(&server->manager[0]);
            }

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

int cute_start( cute_server *server, char **filenames, uint zones )
{
	debug_server("Starting server with %u zone files.\n", zones);

	for (uint i = 0; i < zones; ++i) {
		debug_server("Parsing zone file %s..\n", filenames[i]);
		if (zp_parse_zone(filenames[i], server->zone_db) != 0) {
			return -1;
		}
	}

    debug_server("Opening sockets (port %d)..\n", DEFAULT_PORT);
    if (sm_open(server->manager[UDP], DEFAULT_PORT, UDP) != 0) {
        perror("sm_open_socket");
        return -1;
    }

    if (sm_open(server->manager[TCP], DEFAULT_PORT, TCP) != 0) {
        debug_server("[failed]\n");
        perror("sm_open_socket");
        return -1;
    }
    debug_server("\nDone\n\n");
    debug_server("Starting servers..\n");

    // Start dispatchers
    int ret = 0;
    ret = sm_start(server->manager[TCP]);

    debug_server("   TCP server: %u workers.\n", server->manager[TCP]->workers_dpt->thread_count);

    ret += sm_start(server->manager[UDP]);

    debug_server("   UDP server: %u workers.\n", server->manager[UDP]->workers_dpt->thread_count);
    debug_server("Done\n\n");

    if(ret < 0)
        return ret;

    // Server is ready
    raise(SIGREADY);

    // Wait for dispatchers to finish
    ret = sm_wait(server->manager[TCP]);

    debug_server("TCP handler finished.\n");

    ret += sm_wait(server->manager[UDP]);

    debug_server("UDP handler finished.\n");

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
    sm_destroy(&(*server)->manager[UDP]);
    sm_destroy(&(*server)->manager[TCP]);
    ns_destroy(&(*server)->nameserver);
    zdb_destroy(&(*server)->zone_db);
    free(*server);
    *server = NULL;
}
