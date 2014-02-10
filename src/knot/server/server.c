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
#include <assert.h>

#include "knot/knot.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zones.h"
#include "knot/server/zone-load.h"
#include "knot/conf/conf.h"
#include "knot/zone/zonedb.h"
#include "libknot/dname.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"

/*! \brief Event scheduler loop. */
static int evsched_run(dthread_t *thread)
{
	evsched_t *s = (evsched_t*)thread->data;
	if (!s) {
		return KNOT_EINVAL;
	}

	/* Run event loop. */
	event_t *ev = 0;
	while((ev = evsched_begin_process(s))) {

		/* Process termination event (NULL function). */
		if (ev->cb == NULL) {
			evsched_end_process(s);
			evsched_event_free(ev);
			break;
		}

		/* Process event. */
		ev->cb(ev);
		evsched_end_process(s);

		/* Check for thread cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}
	}

	return KNOT_EOK;
}

/*! \brief Event scheduler thread destructor. */
static int evsched_destruct(dthread_t *thread)
{
	knot_crypto_cleanup_thread();
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

	/* accept() must not block */
	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		free(new_if->addr);
		socket_close(new_if->fd[IO_UDP]);
		socket_close(sock);
		log_server_error("Failed to listen on %s@%d in non-blocking mode.\n",
		                 cfg_if->address, cfg_if->port);
		return KNOT_ERROR;
	}

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
static int reconfigure_sockets(const struct conf_t *conf, server_t *s)
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
	node_t *n = 0;
	WALK_LIST(n, conf->ifaces) {

		/* Find already matching interface. */
		int found_match = 0;
		conf_iface_t *cfg_if = (conf_iface_t*)n;
		if (s->ifaces) {
			WALK_LIST(m, s->ifaces->u) {
				/* Matching port and address. */
				if (cfg_if->port == m->port) {
					if (strcmp(cfg_if->address, m->addr) == 0) {
						found_match = 1;
						break;
					}
				}
			}
		}

		/* Found already bound interface. */
		if (found_match) {
			rem_node((node_t *)m);
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
			add_tail(&newlist->l, (node_t *)m);
			++bound;
		}
	}

	/* Publish new list. */
	ifacelist_t *oldlist = rcu_xchg_pointer(&s->ifaces, newlist);

	/* Unlock configuration. */
	rcu_read_unlock();

	/* Ensure no one is reading old interfaces. */
	synchronize_rcu();

	/* Update TCP+UDP ifacelist (reload all threads). */
	for (unsigned proto = IO_UDP; proto <= IO_TCP; ++proto) {
		dt_unit_t *tu = s->handler[proto].unit;
		for (unsigned i = 0; i < tu->size; ++i) {
			ref_retain((ref_t *)newlist);
			s->handler[proto].thread_state[i] |= ServerReload;
			if (s->state & ServerRunning) {
				dt_activate(tu->threads[i]);
				dt_signalize(tu->threads[i], SIGALRM);
			}
		}
	}

	ref_release(&oldlist->ref);

	return bound;
}

int server_init(server_t *server)
{
	/* Clear the structure. */
	dbg_server("%s(%p)\n", __func__, server);
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	memset(server, 0, sizeof(server_t));

	/* Initialize event scheduler. */
	if (evsched_init(&server->sched, server) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}
	server->iosched = dt_create(1, evsched_run, evsched_destruct, &server->sched);
	if (server->iosched == NULL) {
		evsched_deinit(&server->sched);
		return KNOT_ENOMEM;
	}

	/* Create zone events threads. */
	server->xfr = xfr_create(XFR_THREADS_COUNT, server);
	if (server->xfr == NULL) {
		dt_delete(&server->iosched);
		evsched_deinit(&server->sched);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void server_deinit(server_t *server)
{
	dbg_server("%s(%p)\n", __func__, server);
	if (server == NULL) {
		return;
	}

	/* Free remaining interfaces. */
	if (server->ifaces) {
		iface_t *n = NULL, *m = NULL;
		WALK_LIST_DELSAFE(n, m, server->ifaces->l) {
			server_remove_iface(n);
		}
		free(server->ifaces);
	}

	/* Free threads and event handlers. */
	xfr_free(server->xfr);
	dt_delete(&server->iosched);

	/* Free rate limits. */
	rrl_destroy(server->rrl);

	/* Free zone database. */
	knot_edns_free(&server->opt_rr);
	knot_zonedb_deep_free(&server->zone_db);

	/* Free remaining events. */
	evsched_deinit(&server->sched);

	/* Clear the structure. */
	memset(server, 0, sizeof(server_t));
}

static int server_init_handler(server_t *server, int index, int thread_count,
                               runnable_t runnable, runnable_t destructor)
{
	/* Initialize */
	iohandler_t *h = &server->handler[index];
	memset(h, 0, sizeof(iohandler_t));
	h->server = server;
	h->unit = dt_create(thread_count, runnable, destructor, h);
	if (h->unit == NULL) {
		return KNOT_ENOMEM;
	}

	h->thread_state = calloc(thread_count, sizeof(unsigned));
	if (h->thread_state == NULL) {
		dt_delete(&h->unit);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int server_free_handler(iohandler_t *h)
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
	dt_delete(&h->unit);
	free(h->thread_state);
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
			ret = dt_start(s->handler[i].unit);
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
		if ((ret = server_free_handler(s->handler + i)) != KNOT_EOK) {
			break;
		}
	}

	return ret;
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
	event_t *term_ev = evsched_event_create(&server->sched, NULL, NULL);
	evsched_schedule(term_ev, 0);
	dt_stop(server->iosched);

	/* Interrupt XFR handler execution. */
	xfr_stop(server->xfr);

	/* Clear 'running' flag. */
	server->state &= ~ServerRunning;
}

/*! \brief Reconfigure server OPT RR. */
static int opt_rr_reconfigure(const struct conf_t *conf, server_t *server)
{
	dbg_server("%s(%p, %p)\n", __func__, conf, server);

	/* New OPT RR: keep the old pointer and free it after RCU sync. */
	knot_opt_rr_t *opt_rr = knot_edns_new();
	if (opt_rr == NULL) {
		log_server_error("Couldn't create OPT RR, please restart.\n");
	} else {
		knot_edns_set_version(opt_rr, EDNS_VERSION);
		knot_edns_set_payload(opt_rr, conf->max_udp_payload);
		if (conf->nsid_len > 0) {
			knot_edns_add_option(opt_rr, EDNS_OPTION_NSID,
			                     conf->nsid_len,
			                     (const uint8_t *)conf->nsid);
		}
	}

	knot_opt_rr_t *opt_rr_old = server->opt_rr;
	server->opt_rr = opt_rr;

	synchronize_rcu();

	knot_edns_free(&opt_rr_old);

	return KNOT_EOK;
}

/*! \brief Reconfigure UDP and TCP query processing threads. */
static int reconfigure_threads(const struct conf_t *conf, server_t *server)
{
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
				ret = server_free_handler(server->handler + i);
			}
		}

		/* Initialize I/O handlers. */
		ret = server_init_handler(server, IO_UDP, tu_size,
		                          &udp_master, &udp_master_destruct);
		if (ret != KNOT_EOK) {
			log_server_error("Failed to create UDP threads: %s\n",
			                 knot_strerror(ret));
			return ret;
		}

		/* Create at least CONFIG_XFERS threads for TCP for faster
		 * processing of massive bootstrap queries. */
		ret = server_init_handler(server, IO_TCP, MAX(tu_size * 2, CONFIG_XFERS),
		                          &tcp_master, &tcp_master_destruct);
		if (ret != KNOT_EOK) {
			log_server_error("Failed to create TCP threads: %s\n",
			                 knot_strerror(ret));
			return ret;
		}

		/* Start if server is running. */
		if (server->state & ServerRunning) {
			for (unsigned i = 0; i < IO_COUNT; ++i) {
				ret = dt_start(server->handler[i].unit);
			}
		}
		server->tu_size = tu_size;
	}

	return ret;
}

static int reconfigure_rate_limits(const struct conf_t *conf, server_t *server)
{
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
			/* We cannot free it, threads may use it.
			 * Setting it to <1 will disable rate limiting. */
			if (conf->rrl < 1) {
				log_server_info("Rate limiting disabled.\n");
			} else {
				log_server_info("Rate limiting set to %u "
				                "responses/sec.\n", conf->rrl);
			}
			rrl_setrate(server->rrl, conf->rrl);

		} /* At this point, old buckets will converge to new rate. */
	}

	return KNOT_EOK;
}

int server_reconfigure(const struct conf_t *conf, void *data)
{
	server_t *server = (server_t *)data;
	dbg_server("%s(%p, %p)\n", __func__, conf, server);
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	/* First reconfiguration. */
	if (!(server->state & ServerRunning)) {
		log_server_info("Knot DNS %s starting.\n", PACKAGE_VERSION);
	}

	/* Reconfigure rate limits. */
	int ret = KNOT_EOK;
	if ((ret = reconfigure_rate_limits(conf, server)) < 0) {
		log_server_error("Failed to reconfigure rate limits.\n");
		return ret;
	}

	/* Reconfigure OPT RR. */
	if ((ret = opt_rr_reconfigure(conf, server)) < 0) {
		log_server_error("Failed to reconfigure EDNS settings.\n");
		return ret;
	}

	/* Reconfigure server threads. */
	if ((ret = reconfigure_threads(conf, server)) < 0) {
		log_server_error("Failed to reconfigure server threads.\n");
		return ret;
	}

	/* Update bound sockets. */
	if ((ret = reconfigure_sockets(conf, server)) < 0) {
		log_server_error("Failed to reconfigure server sockets.\n");
		return ret;
	}

	return ret;
}

int server_update_zones(const struct conf_t *conf, void *data)
{
	server_t *server = (server_t *)data;

	int ret = zones_update_db_from_config(conf, server);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Trim extra heap. */
	mem_trim();

	return KNOT_EOK;
}

ref_t *server_set_ifaces(server_t *s, fdset_t *fds, int type)
{
	iface_t *i = NULL;

	rcu_read_lock();
	fdset_clear(fds);
	if (s->ifaces) {
		WALK_LIST(i, s->ifaces->l) {
			fdset_add(fds, i->fd[type], POLLIN, NULL);
		}

	}
	rcu_read_unlock();
	return (ref_t *)s->ifaces;
}
