#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "other/debug.h"
#include "server/server.h"
#include "server/udp-handler.h"
#include "server/tcp-handler.h"
#include "server/name-server.h"
#include "stat/stat.h"
#include "dnslib/zonedb.h"
#include "dnslib/zone-load.h"
#include "dnslib/debug.h"
#include "dnslib/dname.h"

cute_server *cute_create()
{
	// Create TCP+UDP sockets
	debug_server("Binding sockets..\n");
	int udp_sock = socket_create(PF_INET, SOCK_DGRAM);
	if (socket_bind(udp_sock, "0.0.0.0", DEFAULT_PORT) < 0) {
		socket_close(udp_sock);
		return 0;
	}

	int tcp_sock = socket_create(PF_INET, SOCK_STREAM);
	if (socket_bind(tcp_sock, "0.0.0.0", DEFAULT_PORT) < 0) {
		socket_close(udp_sock);
		socket_close(tcp_sock);
		return 0;
	}
	socket_listen(tcp_sock, TCP_BACKLOG_SIZE);
	debug_server("Done\n\n");

	// Create server structure
	cute_server *server = malloc(sizeof(cute_server));
	server->handlers = NULL;
	server->state = ServerIdle;
	if (server == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	debug_server("Done\n\n");
	debug_server("Creating Zone Database structure..\n");

	server->zone_db = dnslib_zonedb_new();
	if (server->zone_db == NULL) {
		return NULL;
	}

	debug_server("Done\n\n");
	debug_server("Creating Name Server structure..\n");

	server->nameserver = ns_create(server->zone_db);
	if (server->nameserver == NULL) {
		dnslib_zonedb_deep_free(&server->zone_db);
		free(server);
		return NULL;
	}

	debug_server("Done\n\n");

	// Estimate number of threads/manager
	int thr_count = dt_optimal_size();
	debug_server("Estimated number of threads per handler: %d\n",
		     thr_count);

	// Create socket handlers
	debug_server("Creating UDP workers..\n");
	dt_unit_t *unit = dt_create_coherent(thr_count, &udp_master, 0);
	cute_create_handler(server, udp_sock, unit);
	debug_server("Done\n\n");

	// Create TCP handlers
	int tcp_unit_size = (thr_count >> 1);
	if (tcp_unit_size < 2) {
		tcp_unit_size = 2;
	}

	debug_server("Creating TCP workers..\n");
	unit = dt_create(tcp_unit_size);
	dt_repurpose(unit->threads[0], &tcp_master, 0);
	cute_create_handler(server, tcp_sock, unit);

	debug_server("Done\n\n");

	return server;
}

iohandler_t *cute_create_handler(cute_server *server, int fd, dt_unit_t *unit)
{
	// Create new worker
	iohandler_t *handler = malloc(sizeof(iohandler_t));
	if (handler == 0) {
		return 0;
	}

	// Initialize
	handler->fd = fd;
	handler->state = ServerIdle;
	handler->next = server->handlers;
	handler->server = server;
	handler->unit = unit;

	// Update unit data object
	for (int i = 0; i < unit->size; ++i) {
		dthread_t *thread = unit->threads[i];
		dt_repurpose(thread, thread->run, handler);
	}

	// Update list
	server->handlers = handler;

	// Run if server is online
	if (server->state & ServerRunning) {
		dt_start(handler->unit);
	}

	return handler;
}

int cute_remove_handler(cute_server *server, iohandler_t *ref)
{
	// Find worker
	iohandler_t *w = 0, *p = 0;
	for (w = server->handlers; w != NULL; p = w, w = w->next) {

		// Compare fd
		if (w == ref) {

			// Disconnect
			if (p == 0) {
				server->handlers = w->next;
			} else {
				p->next = w->next;
			}
			break;
		}
	}

	// Check
	if (w == 0) {
		return -1;
	}

	// Wait for dispatcher to finish
	if (w->state & ServerRunning) {
		w->state = ServerIdle;
		dt_stop(w->unit);
		dt_join(w->unit);
	}

	// Close socket
	socket_close(w->fd);

	// Destroy dispatcher and worker
	dt_delete(&w->unit);
	free(w);
	return 0;
}

int cute_start(cute_server *server, char **filenames, uint zones)
{
	// Check server
	if (server == 0) {
		return -1;
	}

	debug_server("Starting server with %u zone files.\n", zones);
	//stat

	stat_static_gath_start();

	//!stat
	dnslib_zone_t *zone = NULL;

	for (uint i = 0; i < zones; ++i) {
		debug_server("Parsing zone file %s..\n", filenames[i]);
		if (!((zone = dnslib_zload_load(filenames[i])) != NULL
		    && dnslib_zonedb_add_zone(server->zone_db, zone) == 0)) {
			return -1;
		}
		// dump zone
		//dnslib_zone_dump(zone);
	}

	debug_server("\nDone\n\n");
	debug_server("Starting servers..\n");

	// Start dispatchers
	int ret = 0;
	server->state |= ServerRunning;
	for (iohandler_t *w = server->handlers; w != NULL; w = w->next) {
		w->state = ServerRunning;
		ret += dt_start(w->unit);
	}

	return ret;
}

int cute_wait(cute_server *server)
{
	// Wait for dispatchers to finish
	int ret = 0;
	while (server->handlers != NULL) {
		debug_server("server: [%p] joining threading unit\n",
			     server->handlers);
		ret += dt_join(server->handlers->unit);
		cute_remove_handler(server, server->handlers);
		debug_server("server: joined threading unit\n");
	}

	return ret;
}

void cute_stop(cute_server *server)
{
	// Notify servers to stop
	server->state &= ~ServerRunning;
	for (iohandler_t *w = server->handlers; w != NULL; w = w->next) {
		w->state = ServerIdle;
		dt_stop(w->unit);
	}
}

void cute_destroy(cute_server **server)
{
	// Check server
	if (!server) {
		return;
	}
	if (!*server) {
		return;
	}

	// Free workers
	iohandler_t *w = (*server)->handlers;
	while (w != NULL) {
		iohandler_t *n = w->next;
		cute_remove_handler(*server, w);
		w = n;
	}

	stat_static_gath_free();
	ns_destroy(&(*server)->nameserver);
	dnslib_zonedb_deep_free(&(*server)->zone_db);
	free(*server);
	*server = NULL;
}

