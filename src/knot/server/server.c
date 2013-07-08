/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <assert.h>

#include "common/prng.h"
#include "knot/knot.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zones.h"
#include "knot/conf/conf.h"
#include "knot/stat/stat.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/zone/zonedb.h"
#include "libknot/dname.h"

/*! \brief Event scheduler loop. */
static int evsched_run(dthread_t *thread)
{
	evsched_t *s = (evsched_t*)thread->data;
	if (!s) {
		return KNOT_EINVAL;
	}

	/* Run event loop. */
	event_t *ev = 0;
	while((ev = evsched_next(s))) {

		/* Process termination event. */
		if (ev->type == EVSCHED_TERM) {
			evsched_event_finished(s);
			evsched_event_free(s, ev);
			break;
		}

		/* Process event. */
		if (ev->type == EVSCHED_CB && ev->cb) {
			ev->cb(ev);
			evsched_event_finished(s);
		} else {
			evsched_event_finished(s);
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
	if (iface->fd[IO_UDP] > -1) {
		close(iface->fd[IO_UDP]);
	}

	/* Free TCP handler. */
	if (iface->fd[IO_TCP] > -1) {
		close(iface->fd[IO_TCP]);
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
	int ret = 0;
	int sock = 0;
	char errbuf[256] = {0};
	memset(new_if, 0, sizeof(iface_t));

	/* Create UDP socket. */
	ret = socket_create(cfg_if->family, SOCK_DGRAM, IPPROTO_UDP);
	if (ret < 0) {
		if (strerror_r(errno, errbuf, sizeof(errbuf)) == 0) {
			log_server_error("Could not create UDP socket: %s.\n",
					 errbuf);
		}
		return ret;
	} else {
		sock = ret;
	}

	/* Set socket options. */
	int flag = 1;
#ifndef DISABLE_IPV6
	if (cfg_if->family == AF_INET6) {
		/* Disable dual-stack for performance reasons. */
		if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) < 0) {
			dbg_net("udp: failed to set IPV6_V6ONLY to socket, using default config\n");
		}
	}
#endif
	ret = socket_bind(sock, cfg_if->family, cfg_if->address, cfg_if->port);
	if (ret < 0) {
		socket_close(sock);
		log_server_error("Could not bind to "
		                 "UDP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return ret;
	}

	new_if->fd[IO_UDP] = sock;
	new_if->type = cfg_if->family;
	new_if->port = cfg_if->port;
	new_if->addr = strdup(cfg_if->address);

	/* Create TCP socket. */
	ret = socket_create(cfg_if->family, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		socket_close(new_if->fd[IO_UDP]);
		if (strerror_r(errno, errbuf, sizeof(errbuf)) == 0) {
			log_server_error("Could not create TCP socket: %s.\n",
					 errbuf);
		}
		return ret;
	} else {
		sock = ret;
	}

	/* Set socket options. */
#ifndef DISABLE_IPV6
	if (cfg_if->family == AF_INET6) {
		if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) < 0) {
			dbg_net("tcp: failed to set IPV6_V6ONLY to socket, using default config\n");
		}
	}
#endif
	ret = socket_bind(sock, cfg_if->family, cfg_if->address, cfg_if->port);
	if (ret < 0) {
		free(new_if->addr);
		socket_close(new_if->fd[IO_UDP]);
		socket_close(sock);
		log_server_error("Could not bind to "
		                 "TCP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return ret;
	}

	ret = socket_listen(sock, TCP_BACKLOG_SIZE);
	if (ret < 0) {
		free(new_if->addr);
		socket_close(new_if->fd[IO_UDP]);
		socket_close(sock);
		log_server_error("Failed to listen on "
		                 "TCP interface %s port %d.\n",
		                 cfg_if->address, cfg_if->port);
		return ret;
	}

	new_if->fd[IO_TCP] = sock;
	return KNOT_EOK;
}

static void remove_ifacelist(struct ref_t *p)
{
	ifacelist_t *ifaces = (ifacelist_t *)p;

	/* Remove deprecated interfaces. */
	iface_t *n = NULL, *m = NULL;
	WALK_LIST_DELSAFE(n, m, ifaces->u) {
		log_server_info("Removing interface %s port %d.\n",
		                n->addr, n->port);
		server_remove_iface(n);
	}
	WALK_LIST_DELSAFE(n, m, ifaces->l) {
		free(n);
	}

	free(ifaces);
}

/*!
 * \brief Update bound sockets according to configuration.
 *
 * \param server Server instance.
 * \return number of added sockets.
 */
static int server_bind_sockets(server_t *s)
{
	/*! \todo This requires locking to disable parallel updates (issue #278).
	 *  However, this is only used when RCU is read-locked, so count with that.
	 */

	/* Lock configuration. */
	rcu_read_lock();

	/* Prepare helper lists. */
	int bound = 0;
	iface_t *m = 0;
	ifacelist_t *newlist = malloc(sizeof(ifacelist_t));
	ref_init(&newlist->ref, &remove_ifacelist);
	ref_retain(&newlist->ref);
	init_list(&newlist->u);
	init_list(&newlist->l);


	/* Duplicate current list. */
	/*! \note Pointers to addr, handlers etc. will be shared. */
	if (s->ifaces) {
		list_dup(&s->ifaces->u, &s->ifaces->l, sizeof(iface_t));
	}

	/* Update bound interfaces. */
	node *n = 0;
	WALK_LIST(n, conf()->ifaces) {

		/* Find already matching interface. */
		int found_match = 0;
		conf_iface_t *cfg_if = (conf_iface_t*)n;
		if (s->ifaces) WALK_LIST(m, s->ifaces->u) {
			/* Matching port and address. */
			if (cfg_if->port == m->port) {
				if (strcmp(cfg_if->address, m->addr) == 0) {
					found_match = 1;
					break;
				}
			}
		}

		/* Found already bound interface. */
		if (found_match) {
			rem_node((node *)m);
		} else {
			log_server_info("Binding to interface %s port %d.\n",
			                cfg_if->address, cfg_if->port);

			/* Create new interface. */
			m = malloc(sizeof(iface_t));
			if (server_init_iface(m, cfg_if) < 0) {
				free(m);
				m = 0;
			}
		}

		/* Move to new list. */
		if (m) {
			add_tail(&newlist->l, (node *)m);
			++bound;
		}
	}

	/* Publish new list. */
	ifacelist_t *oldlist = rcu_xchg_pointer(&s->ifaces, newlist);

	/* Unlock configuration. */
	rcu_read_unlock();

	/* Ensure no one is reading old interfaces. */
	synchronize_rcu();

	/* Update UDP ifacelist (reload all threads). */
	dt_unit_t *tu = s->h[IO_UDP].unit;
	for (unsigned i = 0; i < tu->size; ++i) {
		ref_retain((ref_t *)newlist);
		s->h[IO_UDP].state[i].s |= ServerReload;
		if (s->state & ServerRunning) {
			dt_activate(tu->threads[i]);
			dt_signalize(tu->threads[i], SIGALRM);
		}
	}

	/* Update TCP ifacelist (reload master thread). */
	tu = s->h[IO_TCP].unit;
	ref_retain((ref_t *)newlist);
	s->h[IO_TCP].state[0].s |= ServerReload;
	if (s->state & ServerRunning) {
		dt_activate(tu->threads[0]);
		dt_signalize(tu->threads[0], SIGALRM);
	}

	ref_release(&oldlist->ref);

	return bound;
}

server_t *server_create()
{
	// Create server structure
	server_t *server = malloc(sizeof(server_t));
	if (server == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(server, 0, sizeof(server_t));

	// Create event scheduler
	dbg_server("server: creating event scheduler\n");
	server->sched = evsched_new();
	server->iosched = dt_create_coherent(1, evsched_run, server->sched);

	// Create name server
	dbg_server("server: creating Name Server structure\n");
	server->nameserver = knot_ns_create();
	if (server->nameserver == NULL) {
		free(server);
		return NULL;
	}
	knot_ns_set_data(server->nameserver, server);
	dbg_server("server: initializing OpenSSL\n");
	OpenSSL_add_all_digests();

	// Create XFR handler
	server->xfr = xfr_create(XFR_THREADS_COUNT, server->nameserver);
	if (!server->xfr) {
		knot_ns_destroy(&server->nameserver);
		free(server);
		return NULL;
	}

	dbg_server("server: created server instance\n");
	return server;
}

int server_init_handler(iohandler_t * h, server_t *s, dt_unit_t *tu, void *d)
{
	/* Initialize */
	memset(h, 0, sizeof(iohandler_t));
	h->server = s;
	h->unit = tu;
	h->data = d;
	h->state = malloc(tu->size * sizeof(iostate_t));

	/* Update unit data object */
	for (int i = 0; i < tu->size; ++i) {
		dthread_t *thread = tu->threads[i];
		h->state[i].h = h;
		h->state[i].s = 0;
		if (thread->run) {
			dt_repurpose(thread, thread->run, h->state + i);
		}
	}

	return KNOT_EOK;
}

int server_free_handler(iohandler_t *h)
{
	if (!h || !h->server) {
		return KNOT_EINVAL;
	}

	/* Wait for threads to finish */
	if (h->unit) {
		dt_stop(h->unit);
		dt_join(h->unit);
	}

	/* Destroy worker context. */
	if (h->dtor) {
		h->dtor(h->data);
		h->data = NULL;
	}
	dt_delete(&h->unit);
	free(h->state);
	memset(h, 0, sizeof(iohandler_t));
	return KNOT_EOK;
}

int server_start(server_t *s)
{
	// Check server
	if (s == 0) {
		return KNOT_EINVAL;
	}

	dbg_server("server: starting server instance\n");

	/* Start XFR handler. */
	xfr_start(s->xfr);

	/* Start evsched handler. */
	dt_start(s->iosched);

	/* Start I/O handlers. */
	int ret = KNOT_EOK;
	s->state |= ServerRunning;
	if (s->tu_size > 0) {
		for (unsigned i = 0; i < IO_COUNT; ++i) {
			ret = dt_start(s->h[i].unit);
		}
	}


	dbg_server("server: server started\n");

	return ret;
}

int server_wait(server_t *s)
{
	if (!s) return KNOT_EINVAL;

	xfr_join(s->xfr);
	dt_join(s->iosched);
	if (s->tu_size == 0) {
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	for (unsigned i = 0; i < IO_COUNT; ++i) {
		if ((ret = server_free_handler(s->h + i)) != KNOT_EOK) {
			break;
		}
	}

	return ret;
}

int server_refresh(server_t *server)
{
	if (server == NULL || server->nameserver == NULL) {
		return KNOT_EINVAL;
	}

	/* Lock RCU and fetch zones. */
	rcu_read_lock();
	knot_nameserver_t *ns =  server->nameserver;
	evsched_t *sch = ((server_t *)knot_ns_get_data(ns))->sched;
	const knot_zone_t **zones = knot_zonedb_zones(ns->zone_db);
	if (zones == NULL) {
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}

	/* REFRESH zones. */
	for (unsigned i = 0; i < knot_zonedb_zone_count(ns->zone_db); ++i) {
		zonedata_t *zd = (zonedata_t *)zones[i]->data;
		if (zd == NULL) {
			continue;
		}
		/* Expire REFRESH timer. */
		if (zd->xfr_in.timer) {
			evsched_cancel(sch, zd->xfr_in.timer);
			evsched_schedule(sch, zd->xfr_in.timer,
			                 tls_rand() * 500 + i/2);
			/* Cumulative delay. */
		}
	}

	/* Unlock RCU. */
	rcu_read_unlock();
	free(zones);
	return KNOT_EOK;
}

int server_reload(server_t *server, const char *cf)
{
	if (!server || !cf) {
		return KNOT_EINVAL;
	}

	log_server_info("Reloading configuration...\n");
	int cf_ret = conf_open(cf);
	switch (cf_ret) {
	case KNOT_EOK:
		log_server_info("Configuration "
				"reloaded.\n");
		break;
	case KNOT_ENOENT:
		log_server_error("Configuration "
				 "file '%s' "
				 "not found.\n",
				 conf()->filename);
		break;
	default:
		log_server_error("Configuration "
				 "reload failed.\n");
		break;
	}

	/*! \todo Close and bind to new remote control. */
	return cf_ret;
}

void server_stop(server_t *server)
{
	log_server_info("Stopping server...\n");

	/* Send termination event. */
	evsched_schedule_term(server->sched, 0);

	/* Interrupt XFR handler execution. */
	xfr_stop(server->xfr);

	/* Clear 'running' flag. */
	server->state &= ~ServerRunning;
}

void server_destroy(server_t **server)
{
	// Check server
	if (!server || !*server) {
		return;
	}

	dbg_server("server: destroying server instance\n");

	/* Free remaining interfaces. */
	ifacelist_t *ifaces = (*server)->ifaces;
	iface_t *n = NULL, *m = NULL;
	if (ifaces) {
		WALK_LIST_DELSAFE(n, m, ifaces->l) {
			server_remove_iface(n);
		}
		free(ifaces);
		(*server)->ifaces = NULL;
	}

	xfr_free((*server)->xfr);
	stat_static_gath_free();
	knot_ns_destroy(&(*server)->nameserver);
	evsched_delete(&(*server)->sched);
	dt_delete(&(*server)->iosched);
	rrl_destroy((*server)->rrl);
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

	/* Estimate number of threads/manager. */
	int ret = KNOT_EOK;
	int tu_size = conf->workers;
	if (tu_size < 1) {
		tu_size = dt_optimal_size();
	}
	if ((unsigned)tu_size != server->tu_size) {
		/* Free old handlers */
		if (server->tu_size > 0) {
			for (unsigned i = 0; i < IO_COUNT; ++i) {
				ret = server_free_handler(server->h + i);
			}
		}

		/* Initialize I/O handlers. */
		size_t udp_size = tu_size;
		if (udp_size < 2) udp_size = 2;
		dt_unit_t *tu = dt_create_coherent(udp_size, &udp_master, NULL);
		server_init_handler(server->h + IO_UDP, server, tu, NULL);
		tu = dt_create(tu_size * 2);
		server_init_handler(server->h + IO_TCP, server, tu, NULL);
		tcp_loop_unit(server->h + IO_TCP, tu);
		if (server->state & ServerRunning) {
			for (unsigned i = 0; i < IO_COUNT; ++i) {
				ret = dt_start(server->h[i].unit);
			}
		}
		server->tu_size = tu_size;
	}

	/* Rate limiting. */
	if (!server->rrl && conf->rrl > 0) {
		server->rrl = rrl_create(conf->rrl_size);
		if (!server->rrl) {
			log_server_error("Couldn't init rate limiting table.\n");
		} else {
			rrl_setlocks(server->rrl, RRL_LOCK_GRANULARITY);
		}
	}
	if (server->rrl) {
		if (rrl_rate(server->rrl) != (uint32_t)conf->rrl) {
			rrl_setrate(server->rrl, conf->rrl);
			log_server_info("Rate limiting set to %u responses/sec.\n",
			                conf->rrl);
		} /* At this point, old buckets will converge to new rate. */
	}

	/* Update bound sockets. */
	if ((ret = server_bind_sockets(server)) < 0) {
		log_server_error("Failed to bind configured "
		                 "interfaces.\n");
	}

	return ret;
}

ref_t *server_set_ifaces(server_t *s, fdset_t **fds, int *count, int type)
{
	iface_t *i = NULL;
	*count = 0;

	rcu_read_lock();
	fdset_destroy(*fds);
	*fds = fdset_new();
	if (s->ifaces) {
		WALK_LIST(i, s->ifaces->l) {
			fdset_add(*fds, i->fd[type], OS_EV_READ);
			*count += 1;
		}

	}
	rcu_read_unlock();
	return (ref_t *)s->ifaces;
}
