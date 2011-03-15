#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>

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
#include "conf/conf.h"

typedef struct {
	int fd;
	int type;
} ifaced_t;

server_t *server_create()
{
	/* Create interfaces. */
	node *n = 0;
	int ifaces_count = conf()->ifaces_count;
	int tcp_loaded = 0, udp_loaded = 0;
	ifaced_t *tcp_socks = malloc(ifaces_count * sizeof(ifaced_t));
	ifaced_t *udp_socks = malloc(ifaces_count * sizeof(ifaced_t));

	debug_server("Binding sockets..\n");
	WALK_LIST(n, conf()->ifaces) {

		/* Get interface descriptor. */
		int opt = 1024 * 256; // 1M buffers for send/recv
		int snd_opt = 1024 * 8;
		conf_iface_t *iface = (conf_iface_t*)n;

		/* Create TCP & UDP sockets. */
		int udp_sock = socket_create(iface->family, SOCK_DGRAM);
		if (udp_sock <= 0) {
			log_server_error("Could not create UDP socket: %s.\n",
			                 strerror(errno));
			break;
		}
		if (socket_bind(udp_sock, iface->family, iface->address, iface->port) < 0) {
			log_server_error("Could not bind to "
			                 "UDP interface on '%s:%d'.\n",
			                 iface->address, iface->port);
			break;
		}
		udp_socks[udp_loaded].fd = udp_sock;
		udp_socks[udp_loaded].type = iface->family;
		udp_loaded++;

		/* Set socket options. */
		if (setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, &snd_opt, sizeof(snd_opt)) < 0) {
			fprintf(stderr, "SO_SNDBUF setting failed\n");
		}
		if (setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
			fprintf(stderr, "SO_SNDBUF setting failed\n");
		}


		int tcp_sock = socket_create(iface->family, SOCK_STREAM);
		if (tcp_sock <= 0) {
			log_server_error("Could not create TCP socket: %s.\n",
			                 strerror(errno));
			break;
		}
		if (socket_bind(tcp_sock, iface->family, iface->address, iface->port) < 0) {
			log_server_error("Could not bind to "
			                 "TCP interface on '%s:%d'.\n",
			                 iface->address, iface->port);
			break;
		}
		socket_listen(tcp_sock, TCP_BACKLOG_SIZE);
		tcp_socks[tcp_loaded].fd = tcp_sock;
		tcp_socks[tcp_loaded].type = iface->family;
		tcp_loaded++;
	}

	/* Evaluate if all sockets loaded. */
	if ((tcp_loaded != ifaces_count) ||
	    (udp_loaded != ifaces_count)) {
		for (int i = 0; i < udp_loaded; ++i) {
			close(udp_socks[i].fd);
		}
		for (int i = 0; i < tcp_loaded; ++i) {
			close(tcp_socks[i].fd);
		}
		free(udp_socks);
		free(tcp_socks);

		return 0;
	}

	// Create server structure
	server_t *server = malloc(sizeof(server_t));
	if (server == NULL) {
		ERR_ALLOC_FAILED;
		free(udp_socks);
		free(tcp_socks);
		return NULL;
	}
	server->handlers = NULL;
	server->state = ServerIdle;

	// Create zone database structure
	debug_server("Creating Zone Database structure..\n");
	server->zone_db = dnslib_zonedb_new();
	if (server->zone_db == NULL) {
		ERR_ALLOC_FAILED;
		free(udp_socks);
		free(tcp_socks);
		free(server);
		return NULL;
	}

	// Create name server
	debug_server("Creating Name Server structure..\n");
	server->nameserver = ns_create(server->zone_db);
	if (server->nameserver == NULL) {
		dnslib_zonedb_deep_free(&server->zone_db);
		free(server);
		free(udp_socks);
		free(tcp_socks);
		return NULL;
	}
	debug_server("Done\n\n");
	debug_server("Initializing OpenSSL...\n");
	OpenSSL_add_all_digests();

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
	iohandler_t* h = 0;
	for (int i = 0; i < udp_loaded; ++i) {
		dt_unit_t *unit = dt_create_coherent(thr_count, &udp_master, 0);
		h = server_create_handler(server, udp_socks[i].fd, unit);
		h->type = udp_socks[i].type;

		unit = dt_create(tcp_unit_size);
		dt_repurpose(unit->threads[0], &tcp_master, 0);
		h = server_create_handler(server, tcp_socks[i].fd, unit);
		h->type = tcp_socks[i].type;
	}

	free(udp_socks);
	free(tcp_socks);
	debug_server("Done\n\n");

	return server;
}

iohandler_t *server_create_handler(server_t *server, int fd, dt_unit_t *unit)
{
	// Create new worker
	iohandler_t *handler = malloc(sizeof(iohandler_t));
	if (handler == 0) {
		ERR_ALLOC_FAILED;
		return 0;
	}

	// Initialize
	handler->fd = fd;
	handler->type = 0;
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

int server_remove_handler(server_t *server, iohandler_t *ref)
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

int server_load_zone(server_t *server, const char *origin, const char *db)
{
	dnslib_zone_t *zone = NULL;

	// Check path
	if (db) {
		debug_server("Parsing zone database '%s'\n", db);
		zloader_t *zl = dnslib_zload_open(db);
		if (!zl && errno == EILSEQ) {
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 db);
			return -1;
		}

		// Check if the db is up-to-date
		if (dnslib_zload_needs_update(zl)) {
			log_server_warning("warning: Zone file for '%s' "
			                   "has changed, it is recommended to "
			                   "recompile it.\n",
			                   origin);
		}

		zone = dnslib_zload_load(zl);
		dnslib_zload_close(zl);
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
				log_server_error("Failed to load db '%s' "
				                 "for zone '%s'.\n",
				                 db, origin);
			}
			return -1;
		}
	} else {
		log_server_error("Invalid database '%s' for zone '%s'\n",
		                 db, origin);
	}

//	dnslib_zone_dump(zone, 1);

	return 0;
}

int server_start(server_t *server, const char **filenames, uint zones)
{
	// Check server
	if (server == 0) {
		return -1;
	}

	debug_server("Starting server with %u zone files.\n",
	             zones + conf()->zones_count);
	//stat

	stat_static_gath_start();

	//!stat

	// Load zones from config
	node *n = 0; int zones_loaded = 0;
	WALK_LIST (n, conf()->zones) {

		// Fetch zone
		conf_zone_t *z = (conf_zone_t*)n;

		// Load zone
		if (server_load_zone(server, z->name, z->db) == 0) {
			++zones_loaded;
		}
	}

	// Load given zones
	for (uint i = 0; i < zones; ++i) {
		if (server_load_zone(server, "??", filenames[i]) == 0) {
			++zones_loaded;
		}
	}

	/* Check the number of loaded zones. */
	if (zones_loaded == 0) {
		log_server_error("No valid database loaded, shutting down.\n");
		return -1;
	}

	debug_server("Starting servers..\n");

	// Start dispatchers
	int ret = 0;
	server->state |= ServerRunning;
	for (iohandler_t *w = server->handlers; w != NULL; w = w->next) {
		w->state = ServerRunning;
		ret += dt_start(w->unit);
	}

	debug_server("Done\n\n");

	return ret;
}

int server_wait(server_t *server)
{
	// Wait for dispatchers to finish
	int ret = 0;
	while (server->handlers != NULL) {
		debug_server("server: [%p] joining threading unit\n",
			     server->handlers);
		ret += dt_join(server->handlers->unit);
		server_remove_handler(server, server->handlers);
		debug_server("server: joined threading unit\n");
	}

	return ret;
}

void server_stop(server_t *server)
{
	// Notify servers to stop
	server->state &= ~ServerRunning;
	for (iohandler_t *w = server->handlers; w != NULL; w = w->next) {
		w->state = ServerIdle;
		dt_stop(w->unit);
	}
}

void server_destroy(server_t **server)
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
		server_remove_handler(*server, w);
		w = n;
	}

	stat_static_gath_free();
	ns_destroy(&(*server)->nameserver);
	dnslib_zonedb_deep_free(&(*server)->zone_db);
	free(*server);

	EVP_cleanup();

	*server = NULL;
}

