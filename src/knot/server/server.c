#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <assert.h>

#include "knot/common.h"
#include "knot/other/error.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/name-server.h"
#include "knot/stat/stat.h"
#include "dnslib/zonedb.h"
#include "dnslib/zone-load.h"
#include "dnslib/debug.h"
#include "dnslib/dname.h"
#include "knot/conf/conf.h"
#include "knot/server/zones.h"

/*! \brief Event scheduler loop. */
static int evsched_run(dthread_t *thread)
{
	iohandler_t *sched_h = (iohandler_t *)thread->data;
	evsched_t *s = (evsched_t*)sched_h->data;
	if (!s) {
		return KNOT_EINVAL;
	}

	/* Run event loop. */
	event_t *ev = 0;
	while((ev = evsched_next(s))) {

		/* Error. */
		if (!ev) {
			return KNOT_ERROR;
		}

		/* Process termination event. */
		if (ev->type == EVSCHED_TERM) {
			evsched_event_free(s, ev);
			break;
		}

		/* Process event. */
		if (ev->type == EVSCHED_CB && ev->cb) {
			ev->caller = s;
			ev->cb(ev);
		} else {
			evsched_event_free(s, ev);
		}

		/* Check for thread cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
	}

	return KNOT_EOK;
}

/*! \brief List item for generic pointers. */
typedef struct pnode_t {
	struct node *next, *prev; /* Keep the ordering for lib/lists.h */
	void *p; /*!< \brief Useful data pointer. */
} pnode_t;

/*! \brief Unbind and dispose given interface. */
static void server_remove_iface(iface_t *iface)
{
	/* Free UDP handler. */
	iohandler_t *handler = iface->handler[UDP_ID];
	if (handler) {
		server_remove_handler(handler->server, handler);
	} else {
		if (iface->fd[UDP_ID] > -1) {
			close(iface->fd[UDP_ID]);
		}
	}

	/* Free TCP handler. */
	handler = iface->handler[TCP_ID];
	if (handler) {
		server_remove_handler(handler->server, handler);
	} else {
		if (iface->fd[TCP_ID] > -1) {
			close(iface->fd[TCP_ID]);
		}
	}

	/* Free interface. */
	free(iface->addr);
	free(iface);
}

/*!
 * \brief Initialize new interface from config value.
 *
 * Both TCP and UDP sockets will be created for the interface.
 *
 * \param new_if Allocated memory for the interface.
 * \param cfg_if Interface template from config.
 *
 * \retval 0 if successful (EOK).
 * \retval <0 on errors (EACCES, EINVAL, ENOMEM, EADDRINUSE).
 */
static int server_init_iface(iface_t *new_if, conf_iface_t *cfg_if)
{
	/* Initialize interface. */
	char errbuf[128];
	int opt = 1024 * 256;
	int snd_opt = 1024 * 8;
	memset(new_if, 0, sizeof(iface_t));

	/* Create UDP socket. */
	int sock = socket_create(cfg_if->family, SOCK_DGRAM);
	if (sock <= 0) {
		log_server_error("Could not create UDP socket: %s.\n",
				 strerror_r(errno, errbuf, sizeof(errbuf)));
		return sock;
	}
	if (socket_bind(sock, cfg_if->family,
	                cfg_if->address, cfg_if->port) < 0) {
		socket_close(sock);
		log_server_error("Could not bind to "
		                 "UDP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return knot_map_errno(EACCES, EINVAL, ENOMEM);
	}

	new_if->fd[UDP_ID] = sock;
	new_if->type[UDP_ID] = cfg_if->family;

	/* Set socket options. */
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &snd_opt, sizeof(snd_opt)) < 0) {
		log_server_warning("Failed to configure socket "
		                   "write buffers.\n");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
		log_server_warning("Failed to configure socket read buffers.\n");
	}

	/* Create TCP socket. */
	int ret = 0;
	sock = socket_create(cfg_if->family, SOCK_STREAM);
	if (sock <= 0) {
		socket_close(new_if->fd[UDP_ID]);
		log_server_error("Could not create TCP socket: %s.\n",
		                 strerror_r(errno, errbuf, sizeof(errbuf)));
		return sock;
	}

	ret = socket_bind(sock, cfg_if->family, cfg_if->address, cfg_if->port);
	if (ret < 0) {
		socket_close(new_if->fd[UDP_ID]);
		socket_close(sock);
		log_server_error("Could not bind to "
		                 "TCP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return ret;
	}

	ret = socket_listen(sock, TCP_BACKLOG_SIZE);
	if (ret < 0) {
		socket_close(new_if->fd[UDP_ID]);
		socket_close(sock);
		log_server_error("Failed to listen on "
		                 "TCP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return ret;
	}

	new_if->fd[TCP_ID] = sock;
	new_if->type[TCP_ID] = cfg_if->family;
	new_if->port = cfg_if->port;
	new_if->addr = strdup(cfg_if->address);
	return KNOT_EOK;
}

/*!
 * \brief Update bound sockets according to configuration.
 *
 * \param server Server instance.
 * \return number of added sockets.
 */
static int server_bind_sockets(server_t *server)
{
	/*! \todo This requires locking to disable parallel updates. */

	/* Lock configuration. */
	conf_read_lock();

	/* Prepare helper lists. */
	int bound = 0;
	node *m = 0;
	list *newlist, unmatched;
	newlist = malloc(sizeof(list));
	init_list(newlist);
	init_list(&unmatched);

	/* Duplicate current list. */
	/*! \note Pointers to addr, handlers etc. will be shared. */
	list_dup(&unmatched, server->ifaces, sizeof(iface_t));

	/* Update pointers. */
	WALK_LIST(m, unmatched) {

		/* Interfaces. */
		iface_t *m_if = (iface_t*)m;
		for (int i = 0; i <= TCP_ID; ++i) {
			iohandler_t *h = m_if->handler[i];
			if (h) {
				h->iface = m_if;
			}

		}
	}

	/* Update bound interfaces. */
	node *n = 0;
	WALK_LIST(n, conf()->ifaces) {

		/* Find already matching interface. */
		int found_match = 0;
		conf_iface_t *cfg_if = (conf_iface_t*)n;
		WALK_LIST(m, unmatched) {
			iface_t *srv_if = (iface_t*)m;

			/* Matching port and address. */
			if (cfg_if->port == srv_if->port) {
				if (strcmp(cfg_if->address, srv_if->addr) == 0) {
					found_match = 1;
					break;
				}
			}
		}

		/* Found already bound interface. */
		if (found_match) {
			rem_node(m);
		} else {

			/* Create new interface. */
			m = malloc(sizeof(iface_t));
			if (server_init_iface((iface_t*)m, cfg_if) < 0) {
				free(m);
				m = 0;
			}

			log_server_info("Binding to interface %s port %d.\n",
			                cfg_if->address, cfg_if->port);
		}

		/* Move to new list. */
		if (m) {
			add_tail(newlist, m);
			++bound;
		}
	}

	/* Unlock configuration. */
	conf_read_unlock();

	/* Publish new list. */
	list* oldlist = rcu_xchg_pointer(&server->ifaces, newlist);

	/* Ensure no one is reading old interfaces. */
	synchronize_rcu();

	/* Remove deprecated interfaces. */
	WALK_LIST_DELSAFE(n, m, unmatched) {
		iface_t *rm_if = (iface_t*)n;
		log_server_info("Removing interface %s port %d.\n",
		                rm_if->addr, rm_if->port);
		server_remove_iface(rm_if);
	}

	/* Free original list. */
	WALK_LIST_DELSAFE(n, m, *oldlist) {
		/*! \note Need to keep internal pointers, as they are shared
		 *        with the newly published list. */
		free(n);
	}
	free(oldlist);

	return bound;
}

/*!
 * \brief Update socket handlers according to configuration.
 *
 * \param server Server instance.
 * \retval 0 if successful (EOK).
 * \retval <0 on errors (EINVAL).
 */
static int server_bind_handlers(server_t *server)
{
	if (!server || !server->ifaces) {
		return KNOT_EINVAL;
	}

	/* Estimate number of threads/manager. */
	int thr_count = dt_optimal_size();
	int tcp_unit_size = (thr_count >> 1);
	if (tcp_unit_size < 3) {
		tcp_unit_size = 3;
	}

	/* Lock config. */
	conf_read_lock();

	/* Create socket handlers. */
	node *n = 0;
	iohandler_t* h = 0;
	WALK_LIST(n, *server->ifaces) {

		iface_t *iface = (iface_t*)n;

		/* Create UDP handlers. */
		dt_unit_t *unit = 0;
		if (!iface->handler[UDP_ID]) {
			unit = dt_create_coherent(thr_count, &udp_master, 0);
			h = server_create_handler(server, iface->fd[UDP_ID], unit);
			h->type = iface->type[UDP_ID];
			h->iface = iface;

			/* Save pointer. */
			rcu_set_pointer(&iface->handler[UDP_ID], h);
			debug_server("Creating UDP socket handlers for '%s:%d'\n",
			             iface->addr, iface->port);

		}

		/* Create TCP handlers. */
		if (!iface->handler[TCP_ID]) {
			unit = dt_create(tcp_unit_size);
			dt_repurpose(unit->threads[0], &tcp_master, 0);
			h = server_create_handler(server, iface->fd[TCP_ID], unit);
			h->type = iface->type[TCP_ID];
			h->iface = iface;

			/* Save pointer. */
			rcu_set_pointer(&iface->handler[TCP_ID], h);
			debug_server("Creating TCP socket handlers for '%s:%d'\n",
			             iface->addr, iface->port);
		}

	}

	/* Unlock config. */
	conf_read_unlock();

	return KNOT_EOK;
}

server_t *server_create()
{
	// Create server structure
	server_t *server = malloc(sizeof(server_t));
	if (server == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	server->state = ServerIdle;
	init_list(&server->handlers);
	server->ifaces = malloc(sizeof(list));
	init_list(server->ifaces);

	// Create event scheduler
	debug_server("Creating event scheduler...\n");
	server->sched = evsched_new();
	dt_unit_t *unit = dt_create_coherent(1, evsched_run, 0);
	iohandler_t *h = server_create_handler(server, -1, unit);
	h->data = server->sched;

	// Create name server
	debug_server("Creating Name Server structure...\n");
	server->nameserver = ns_create();
	if (server->nameserver == NULL) {
		free(server);
		return NULL;
	}
	debug_server("Initializing OpenSSL...\n");
	OpenSSL_add_all_digests();

	// Create XFR handler
	server->xfr_h = xfr_create(XFR_THREADS_COUNT, server->nameserver);
	if (!server->xfr_h) {
		ns_destroy(&server->nameserver);
		free(server);
		return NULL;
	}

	debug_server("Done.\n");
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
	handler->server = server;
	handler->unit = unit;
	handler->iface = 0;
	handler->data = 0;

	// Update unit data object
	for (int i = 0; i < unit->size; ++i) {
		dthread_t *thread = unit->threads[i];
		dt_repurpose(thread, thread->run, handler);
	}

	/*! \todo This requires either RCU compatible ptr swap or locking. */

	/* Lock RCU. */
	rcu_read_lock();

	// Update list
	add_tail(&server->handlers, (node*)handler);

	/* Unlock RCU. */
	rcu_read_unlock();

	return handler;
}

int server_remove_handler(server_t *server, iohandler_t *h)
{
	// Check
	if (h == 0) {
		return KNOT_EINVAL;
	}

	/* Lock RCU. */
	rcu_read_lock();

	/*! \todo This requires either RCU compatible ptr swap or locking. */

	// Remove node
	rem_node((node*)h);

	// Wait for dispatcher to finish
	if (h->state & ServerRunning) {
		h->state = ServerIdle;
		dt_stop(h->unit);
		dt_join(h->unit);
	}

	// Close socket
	if (h->fd >= 0) {
		socket_close(h->fd);
		h->fd = -1;
	}

	// Update interface
	if (h->iface) {
		int id = UDP_ID;
		if (h->iface->handler[TCP_ID] == h) {
			id = TCP_ID;
		}

		h->iface->fd[id] = h->fd;
		h->iface->handler[id] = 0;
	}

	/* Unlock RCU. */
	rcu_read_unlock();

	/* RCU synchronize. */
	synchronize_rcu();

	// Destroy dispatcher and worker
	dt_delete(&h->unit);
	free(h);
	return KNOT_EOK;
}

int server_start(server_t *server)
{
	// Check server
	if (server == 0) {
		return KNOT_EINVAL;
	}

	debug_server("Starting handlers...\n");

	/* Start XFR handler. */
	xfr_start(server->xfr_h);

	/* Lock configuration. */
	conf_read_lock();

	// Start dispatchers
	int ret = KNOT_EOK;
	server->state |= ServerRunning;
	iohandler_t *h = 0;
	WALK_LIST(h, server->handlers) {

		/* Already running. */
		if (h->state & ServerRunning) {
			continue;
		}

		h->state = ServerRunning;
		ret = dt_start(h->unit);
		if (ret < 0) {
			break;
		}
	}

	/* Unlock configuration. */
	conf_read_unlock();

	debug_server("Done.\n");

	return ret;
}

int server_wait(server_t *server)
{
	/* Lock RCU. */
	rcu_read_lock();

	// Wait for handlers to finish
	int ret = 0;
	iohandler_t *h = 0, *nxt = 0;
	WALK_LIST_DELSAFE(h, nxt, server->handlers) {
		debug_server("server: [%p] joining threading unit\n",
			     h);

		/* Unlock RCU. */
		rcu_read_unlock();

		/* Remove handler. */
		int dret = dt_join(h->unit);
		if (dret < 0) {
			ret = dret;
		}
		server_remove_handler(server, h);

		/* Relock RCU. */
		rcu_read_lock();

		debug_server("server: joined threading unit\n");
	}

	/* Unlock RCU. */
	rcu_read_unlock();

	/* Wait for XFR master. */
	xfr_stop(server->xfr_h);
	xfr_join(server->xfr_h);

	return ret;
}

void server_stop(server_t *server)
{
	/* Send termination event. */
	evsched_schedule_term(server->sched, 0);

	/* Lock RCU. */
	rcu_read_lock();

	// Notify servers to stop
	log_server_info("Stopping server...\n");
	server->state &= ~ServerRunning;
	iohandler_t *h = 0;
	WALK_LIST(h, server->handlers) {
		h->state = ServerIdle;
		dt_stop(h->unit);
	}

	/* Unlock RCU. */
	rcu_read_unlock();
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

	// Free interfaces
	node *n = 0, *nxt = 0;
	if ((*server)->ifaces) {
		WALK_LIST_DELSAFE(n, nxt, *(*server)->ifaces) {
			iface_t *iface = (iface_t*)n;
			server_remove_iface(iface);
		}
		free((*server)->ifaces);
	}

	// Free XFR master
	xfr_free((*server)->xfr_h);

	// Delete event scheduler
	evsched_delete(&(*server)->sched);

	stat_static_gath_free();
	ns_destroy(&(*server)->nameserver);

	free(*server);

	EVP_cleanup();

	*server = NULL;
}

int server_conf_hook(const struct conf_t *conf, void *data)
{
	server_t *server = (server_t *)data;

	if (!server) {
		return KNOT_EINVAL;
	}

	/* Update bound sockets. */
	int ret = KNOT_EOK;
	if ((ret = server_bind_sockets(server)) < 0) {
		log_server_error("Failed to bind configured "
		                 "interfaces.\n");
		return KNOT_ERROR;
	}

	/* Update handlers. */
	if ((ret = server_bind_handlers(server)) < 0) {
		log_server_error("Failed to create handlers for "
		                 "configured interfaces.\n");
		return ret;
	}

	/* Exit if the server is not running. */
	if (!(server->state & ServerRunning)) {
		return KNOT_ENOTRUNNING;
	}

	/* Lock configuration. */
	conf_read_lock();

	/* Start new handlers. */
	iohandler_t *h = 0;
	WALK_LIST(h, server->handlers) {
		if (!(h->state & ServerRunning)) {
			h->state = ServerRunning;
			ret = dt_start(h->unit);
			if (ret < 0) {
				log_server_error("Handler for %s:%d "
				                 "has failed to start.\n",
				                  h->iface->addr,
				                  h->iface->port);
				break;
			}
		}
	}

	/* Unlock config. */
	conf_read_unlock();

	return ret;
}

