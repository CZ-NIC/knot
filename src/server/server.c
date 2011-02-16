#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "debug.h"
#include "server.h"
#include "conf.h"
#include "udp-handler.h"
#include "tcp-handler.h"
#include "name-server.h"
#include "stat.h"
#include "zonedb.h"
#include "zone-load.h"
#include "dnslib/debug.h"
#include "dnslib/dname.h"


cute_server *cute_create()
{
	// Create interfaces
	node *n = 0;
	int ifaces_count = conf()->ifaces_count;
	int tcp_loaded = 0, udp_loaded = 0;
	int *tcp_socks = malloc(ifaces_count * sizeof(int));
	int *udp_socks = malloc(ifaces_count * sizeof(int));

	debug_server("Binding sockets..\n");
	WALK_LIST(n, conf()->ifaces) {

		// Get interface descriptor
		int opt = 1024 * 1024; // 1M buffers for send/recv
		conf_iface_t *iface = (conf_iface_t*)n;

		// Create TCP+UDP sockets
		int udp_sock = socket_create(PF_INET, SOCK_DGRAM);
		if (socket_bind(udp_sock, iface->address, iface->port) < 0) {
			log_server_error("Could not bind to "
			                 "UDP interface on '%s:%d'.\n",
			                 iface->address, iface->port);
			break;
		}
		udp_socks[udp_loaded++] = udp_sock;

		/* Set socket options. */
		setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
		setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));

		int tcp_sock = socket_create(PF_INET, SOCK_STREAM);
		if (socket_bind(tcp_sock, iface->address, iface->port) < 0) {
			log_server_error("Could not bind to "
			                 "TCP interface on '%s:%d'.\n",
			                 iface->address, iface->port);
			break;
		}
		socket_listen(tcp_sock, TCP_BACKLOG_SIZE);
		tcp_socks[tcp_loaded++] = tcp_sock;
	}

	// Evaluate if all sockets loaded.
	debug_server("Done\n\n");
	if ((tcp_loaded != ifaces_count) ||
	    (udp_loaded != ifaces_count)) {
		for (int i = 0; i < udp_loaded; ++i) {
			close(udp_socks[i]);
		}
		for (int i = 0; i < tcp_loaded; ++i) {
			close(tcp_socks[i]);
		}

		return 0;
	}

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
	int tcp_unit_size = (thr_count >> 1);
	if (tcp_unit_size < 2) {
		tcp_unit_size = 2;
	}

	// Create socket handlers
	// udp_loaded is equal to tcp_loaded.
	debug_server("Creating socket handlers..\n");
	for (int i = 0; i < udp_loaded; ++i) {
		dt_unit_t *unit = dt_create_coherent(thr_count, &udp_master, 0);
		cute_create_handler(server, udp_socks[i], unit);
		unit = dt_create(tcp_unit_size);
		dt_repurpose(unit->threads[0], &tcp_master, 0);
		cute_create_handler(server, tcp_socks[i], unit);
	}
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

int cute_load_zone(cute_server *server, const char *origin, const char *db)
{
	dnslib_zone_t *zone = NULL;

	// Check path
	if (db) {
		debug_server("Parsing zone database '%s'\n", db);
		zone = dnslib_zload_load(db);
		if (zone) {
			if (dnslib_zonedb_add_zone(server->zone_db, zone) != 0){
				dnslib_zone_deep_free(&zone);
			}
		}
		if (!zone) {
			struct stat st;
			if (stat(db, &st) != 0) {
				log_server_error(
				        "Database file '%s' not exists.\n",
				        db);
				log_server_error(
				        "Please recompile zone databases.\n");
			} else {
				log_server_error("Could not load database '%s' "
				                 "for zone '%s'\n",
				                 db, origin);
			}
			return -1;
		}
	} else {
		log_server_error("Invalid database '%s' for zone '%s'\n",
		                 db, origin);
	}

	return 0;
}

int cute_start(cute_server *server, const char **filenames, uint zones)
{
	// Check server
	if (server == 0) {
		return -1;
	}

	debug_server("Starting server with %u zone files.\n", zones);
	//stat

	stat_static_gath_start();

	//!stat

	// Load zones from config
	node *n = 0;
	WALK_LIST (n, conf()->zones) {

		// Fetch zone
		conf_zone_t *z = (conf_zone_t*)n;

		// Load zone
		if (cute_load_zone(server, z->name, z->db) < 0) {
			return -1;
		}
	}

	// Load given zones
	for (uint i = 0; i < zones; ++i) {
		if (cute_load_zone(server, "??", filenames[i]) < 0) {
			return -1;
		}
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

