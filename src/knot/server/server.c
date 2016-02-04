/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#define __APPLE_USE_RFC_3542

#include <stdlib.h>
#include <assert.h>
#include <urcu.h>

#include "libknot/errcode.h"
#include "knot/common/log.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb-load.h"
#include "knot/worker/pool.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/trim.h"

/*! \brief Minimal send/receive buffer sizes. */
enum {
	UDP_MIN_RCVSIZE = 4096,
	UDP_MIN_SNDSIZE = 4096,
	TCP_MIN_RCVSIZE = 4096,
	TCP_MIN_SNDSIZE = sizeof(uint16_t) + UINT16_MAX
};

/*! \brief Unbind interface and clear the structure. */
static void server_deinit_iface(iface_t *iface)
{
	/* Free UDP handler. */
	for (int i = 0; i < iface->fd_udp_count; i++) {
		if (iface->fd_udp[i] > -1) {
			close(iface->fd_udp[i]);
		}
	}
	free(iface->fd_udp);

	/* Free TCP handler. */
	if (iface->fd_tcp > -1) {
		close(iface->fd_tcp);
	}

	memset(iface, 0, sizeof(*iface));
}

/*! \brief Unbind and dispose given interface. */
static void server_remove_iface(iface_t *iface)
{
	if (!iface) {
		return;
	}

	server_deinit_iface(iface);
	free(iface);
}

/*! \brief Set lower bound for socket option. */
static bool setsockopt_min(int sock, int option, int min)
{
	int value = 0;
	socklen_t len = sizeof(value);

	if (getsockopt(sock, SOL_SOCKET, option, &value, &len) != 0) {
		return false;
	}

	assert(len == sizeof(value));
	if (value >= min) {
		return true;
	}

	return setsockopt(sock, SOL_SOCKET, option, &min, sizeof(min)) == 0;
}

/*!
 * \brief Enlarge send/receive buffers.
 */
static bool enlarge_net_buffers(int sock, int min_recvsize, int min_sndsize)
{
	return setsockopt_min(sock, SO_RCVBUF, min_recvsize) &&
	       setsockopt_min(sock, SO_SNDBUF, min_sndsize);
}

/*!
 * \brief Enable source packet information retrieval.
 */
static bool enable_pktinfo(int sock, int family)
{
	int level = 0;
	int option = 0;

	switch (family) {
	case AF_INET:
		level = IPPROTO_IP;
#if defined(IP_PKTINFO)
		option = IP_PKTINFO; /* Linux */
#elif defined(IP_RECVDSTADDR)
		option = IP_RECVDSTADDR; /* BSD */
#else
		return false;
#endif
		break;
	case AF_INET6:
		level = IPPROTO_IPV6;
		option = IPV6_RECVPKTINFO;
		break;
	default:
		return false;
	}

	const int on = 1;
	return setsockopt(sock, level, option, &on, sizeof(on)) == 0;
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
static int server_init_iface(iface_t *new_if, struct sockaddr_storage *addr, int udp_thread_count)
{
	/* Initialize interface. */
	int ret = 0;
	memset(new_if, 0, sizeof(iface_t));
	memcpy(&new_if->addr, addr, sizeof(struct sockaddr_storage));

	/* Convert to string address format. */
	char addr_str[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(addr_str, sizeof(addr_str), addr);

	int udp_socket_count = 1;
	int bind_flags = 0;

#ifdef ENABLE_REUSEPORT
	udp_socket_count = udp_thread_count;
	bind_flags |= NET_BIND_MULTIPLE;
#endif

	new_if->fd_udp = malloc(udp_socket_count * sizeof(int));
	if (!new_if->fd_udp) {
		return KNOT_ENOMEM;
	}

	/* Initialize the sockets to ensure safe early deinitialization. */
	for (int i = 0; i < udp_socket_count; i++) {
		new_if->fd_udp[new_if->fd_udp_count] = -1;
	};
	new_if->fd_tcp = -1;

	bool warn_bind = false;
	bool warn_bufsize = false;

	/* Create bound UDP sockets. */
	for (int i = 0; i < udp_socket_count; i++ ) {
		int sock = net_bound_socket(SOCK_DGRAM, addr, bind_flags);
		if (sock == KNOT_EADDRNOTAVAIL) {
			bind_flags |= NET_BIND_NONLOCAL;
			sock = net_bound_socket(SOCK_DGRAM, addr, bind_flags);
			if (sock >= 0 && !warn_bind) {
				log_warning("address '%s' is not available", addr_str);
				warn_bind = true;
			}
		}

		if (sock < 0) {
			log_error("cannot bind address '%s' (%s)", addr_str,
			          knot_strerror(sock));
			server_deinit_iface(new_if);
			return sock;
		}

		if (!enlarge_net_buffers(sock, UDP_MIN_RCVSIZE, UDP_MIN_SNDSIZE) &&
		    !warn_bufsize) {
			log_warning("failed to set network buffer sizes for UDP");
			warn_bufsize = true;
		}

		if (!enable_pktinfo(sock, addr->ss_family)) {
			log_warning("failed to enable received packet information retrieval");
		}

		new_if->fd_udp[new_if->fd_udp_count] = sock;
		new_if->fd_udp_count += 1;
	}

	/* Create bound TCP socket. */
	int sock = net_bound_socket(SOCK_STREAM, addr, bind_flags);
	if (sock < 0) {
		log_error("cannot bind address '%s' (%s)", addr_str,
		          knot_strerror(sock));
		server_deinit_iface(new_if);
		return sock;
	}

	if (!enlarge_net_buffers(sock, TCP_MIN_RCVSIZE, TCP_MIN_SNDSIZE)) {
		log_warning("failed to set network buffer sizes for TCP");
	}

	new_if->fd_tcp = sock;

	/* Listen for incoming connections. */
	ret = listen(sock, TCP_BACKLOG_SIZE);
	if (ret < 0) {
		log_error("failed to listen on TCP interface '%s'", addr_str);
		server_deinit_iface(new_if);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

static void remove_ifacelist(struct ref *p)
{
	ifacelist_t *ifaces = (ifacelist_t *)p;

	/* Remove deprecated interfaces. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	iface_t *n = NULL, *m = NULL;
	WALK_LIST_DELSAFE(n, m, ifaces->u) {
		sockaddr_tostr(addr_str, sizeof(addr_str), &n->addr);
		log_info("removing interface '%s'", addr_str);
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
static int reconfigure_sockets(conf_t *conf, server_t *s)
{
	/* Prepare helper lists. */
	int bound = 0;
	ifacelist_t *oldlist = s->ifaces;
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
	conf_val_t listen_val = conf_get(conf, C_SRV, C_LISTEN);
	conf_val_t rundir_val = conf_get(conf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);
	while (listen_val.code == KNOT_EOK) {
		iface_t *m = NULL;

		/* Find already matching interface. */
		int found_match = 0;
		struct sockaddr_storage addr = conf_addr(&listen_val, rundir);
		if (s->ifaces) {
			WALK_LIST(m, s->ifaces->u) {
				/* Matching port and address. */
				if (sockaddr_cmp(&addr, &m->addr) == 0) {
					found_match = 1;
					break;
				}
			}
		}

		/* Found already bound interface. */
		if (found_match) {
			rem_node((node_t *)m);
		} else {
			char addr_str[SOCKADDR_STRLEN] = { 0 };
			sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
			log_info("binding to interface '%s'", addr_str);

			/* Create new interface. */
			m = malloc(sizeof(iface_t));
			unsigned size = s->handlers[IO_UDP].handler.unit->size;
			if (server_init_iface(m, &addr, size) < 0) {
				free(m);
				m = 0;
			}
		}

		/* Move to new list. */
		if (m) {
			add_tail(&newlist->l, (node_t *)m);
			++bound;
		}

		conf_val_next(&listen_val);
	}
	free(rundir);

	/* Wait for readers that are reconfiguring right now. */
	/*! \note This subsystem will be reworked in #239 */
	for (unsigned proto = IO_UDP; proto <= IO_TCP; ++proto) {
		dt_unit_t *tu = s->handlers[proto].handler.unit;
		iohandler_t *ioh = &s->handlers[proto].handler;
		for (unsigned i = 0; i < tu->size; ++i) {
			while (ioh->thread_state[i] & ServerReload) {
				sleep(1);
			}
		}
	}

	/* Publish new list. */
	s->ifaces = newlist;

	/* Update TCP+UDP ifacelist (reload all threads). */
	unsigned thread_count = 0;
	for (unsigned proto = IO_UDP; proto <= IO_TCP; ++proto) {
		dt_unit_t *tu = s->handlers[proto].handler.unit;
		for (unsigned i = 0; i < tu->size; ++i) {
			ref_retain((ref_t *)newlist);
			s->handlers[proto].handler.thread_state[i] |= ServerReload;
			s->handlers[proto].handler.thread_id[i] = thread_count++;
			if (s->state & ServerRunning) {
				dt_activate(tu->threads[i]);
				dt_signalize(tu->threads[i], SIGALRM);
			}
		}
	}

	ref_release(&oldlist->ref);

	return bound;
}

int server_init(server_t *server, int bg_workers)
{
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	/* Clear the structure. */
	memset(server, 0, sizeof(server_t));

	/* Initialize event scheduler. */
	if (evsched_init(&server->sched, server) != KNOT_EOK) {
		return KNOT_ENOMEM;
	}

	server->workers = worker_pool_create(bg_workers);
	if (server->workers == NULL) {
		evsched_deinit(&server->sched);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

void server_deinit(server_t *server)
{
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
	worker_pool_destroy(server->workers);

	/* Free rate limits. */
	rrl_destroy(server->rrl);

	/* Free zone database. */
	knot_zonedb_deep_free(&server->zone_db);

	/* Free remaining events. */
	evsched_deinit(&server->sched);

	/* Close persistent timers database. */
	close_timers_db(server->timers_db);

	/* Clear the structure. */
	memset(server, 0, sizeof(server_t));
}

static int server_init_handler(server_t *server, int index, int thread_count,
                               runnable_t runnable, runnable_t destructor)
{
	/* Initialize */
	iohandler_t *h = &server->handlers[index].handler;
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

	h->thread_id = calloc(thread_count, sizeof(unsigned));
	if (h->thread_id == NULL) {
		free(h->thread_state);
		dt_delete(&h->unit);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static void server_free_handler(iohandler_t *h)
{
	if (h == NULL || h->server == NULL) {
		return;
	}

	/* Wait for threads to finish */
	if (h->unit) {
		dt_stop(h->unit);
		dt_join(h->unit);
	}

	/* Destroy worker context. */
	dt_delete(&h->unit);
	free(h->thread_state);
	free(h->thread_id);
	memset(h, 0, sizeof(iohandler_t));
}

int server_start(server_t *server, bool async)
{
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	/* Start workers. */
	worker_pool_start(server->workers);

	/* Wait for enqueued events if not asynchronous. */
	if (!async) {
		worker_pool_wait(server->workers);
	}

	/* Start evsched handler. */
	evsched_start(&server->sched);

	/* Start I/O handlers. */
	server->state |= ServerRunning;
	for (int proto = IO_UDP; proto <= IO_TCP; ++proto) {
		if (server->handlers[proto].size > 0) {
			int ret = dt_start(server->handlers[proto].handler.unit);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

void server_wait(server_t *server)
{
	if (server == NULL) {
		return;
	}

	evsched_join(&server->sched);
	worker_pool_join(server->workers);

	for (int proto = IO_UDP; proto <= IO_TCP; ++proto) {
		if (server->handlers[proto].size > 0) {
			server_free_handler(&server->handlers[proto].handler);
		}
	}
}

int server_reload(server_t *server, const char *cf)
{
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	// Check for no edit mode.
	if (cf != NULL && conf()->io.txn != NULL) {
		log_warning("reload aborted due to active config DB transaction");
		return KNOT_CONF_ETXN;
	}

	conf_t *new_conf = NULL;
	int ret = conf_clone(&new_conf);
	if (ret != KNOT_EOK) {
		log_error("failed to initialize configuration (%s)",
		          knot_strerror(ret));
		return ret;
	}

	if (cf != NULL) {
		log_info("reloading configuration file '%s'", cf);

		/* Import the configuration file. */
		ret = conf_import(new_conf, cf, true);
		if (ret != KNOT_EOK) {
			log_error("failed to load configuration file (%s)",
			          knot_strerror(ret));
			conf_free(new_conf);
			return ret;
		}
	} else {
		log_info("reloading configuration database");
	}

	/* Activate global query modules. */
	conf_activate_modules(new_conf, NULL, &new_conf->query_modules,
	                      &new_conf->query_plan);

	/* Update to the new config. */
	conf_update(new_conf);

	log_reconfigure(conf());
	server_reconfigure(conf(), server);
	server_update_zones(conf(), server);

	log_info("configuration reloaded");

	return KNOT_EOK;
}

void server_stop(server_t *server)
{
	log_info("stopping server");

	/* Stop scheduler. */
	evsched_stop(&server->sched);
	/* Interrupt background workers. */
	worker_pool_stop(server->workers);

	/* Clear 'running' flag. */
	server->state &= ~ServerRunning;
}

static int reset_handler(server_t *server, int index, unsigned size, runnable_t run)
{
	if (server->handlers[index].size != size) {
		/* Free old handlers */
		if (server->handlers[index].size > 0) {
			server_free_handler(&server->handlers[index].handler);
		}

		/* Initialize I/O handlers. */
		int ret = server_init_handler(server, index, size, run, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		/* Start if server is running. */
		if (server->state & ServerRunning) {
			ret = dt_start(server->handlers[index].handler.unit);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		server->handlers[index].size = size;
	}

	return KNOT_EOK;
}

/*! \brief Reconfigure UDP and TCP query processing threads. */
static int reconfigure_threads(conf_t *conf, server_t *server)
{
	int ret = reset_handler(server, IO_UDP, conf_udp_threads(conf), udp_master);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return reset_handler(server, IO_TCP, conf_tcp_threads(conf), tcp_master);
}

static int reconfigure_rate_limits(conf_t *conf, server_t *server)
{
	conf_val_t val = conf_get(conf, C_SRV, C_RATE_LIMIT);
	int64_t rrl = conf_int(&val);

	/* Rate limiting. */
	if (!server->rrl && rrl > 0) {
		val = conf_get(conf, C_SRV, C_RATE_LIMIT_TBL_SIZE);
		server->rrl = rrl_create(conf_int(&val));
		if (!server->rrl) {
			log_error("failed to initialize rate limiting table");
		} else {
			rrl_setlocks(server->rrl, RRL_LOCK_GRANULARITY);
		}
	}
	if (server->rrl) {
		if (rrl_rate(server->rrl) != rrl) {
			/* We cannot free it, threads may use it.
			 * Setting it to <1 will disable rate limiting. */
			if (rrl < 1) {
				log_info("rate limiting, disabled");
			} else {
				log_info("rate limiting, enabled with %i responses/second",
					 (int)rrl);
			}
			rrl_setrate(server->rrl, rrl);

		} /* At this point, old buckets will converge to new rate. */
	}

	return KNOT_EOK;
}

void server_reconfigure(conf_t *conf, server_t *server)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	/* First reconfiguration. */
	if (!(server->state & ServerRunning)) {
		log_info("Knot DNS %s starting", PACKAGE_VERSION);
	}

	/* Reconfigure rate limits. */
	int ret;
	if ((ret = reconfigure_rate_limits(conf, server)) < 0) {
		log_error("failed to reconfigure rate limits (%s)",
		          knot_strerror(ret));
	}

	/* Reconfigure server threads. */
	if ((ret = reconfigure_threads(conf, server)) < 0) {
		log_error("failed to reconfigure server threads (%s)",
		          knot_strerror(ret));
	}

	/* Update bound sockets. */
	if ((ret = reconfigure_sockets(conf, server)) < 0) {
		log_error("failed to reconfigure server sockets (%s)",
		          knot_strerror(ret));
	}
}

static void reopen_timers_database(conf_t *conf, server_t *server)
{
	close_timers_db(server->timers_db);
	server->timers_db = NULL;

	conf_val_t val = conf_default_get(conf, C_STORAGE);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_default_get(conf, C_TIMER_DB);
	char *timer_db = conf_abs_path(&val, storage);
	free(storage);

	int ret = open_timers_db(timer_db, &server->timers_db);
	free(timer_db);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		log_warning("cannot open persistent timers DB (%s)",
		            knot_strerror(ret));
	}
}

void server_update_zones(conf_t *conf, server_t *server)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	/* Prevent emitting of new zone events. */
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_freeze);
	}

	/* Suspend workers, clear wating events, finish running events. */
	worker_pool_suspend(server->workers);
	worker_pool_clear(server->workers);
	worker_pool_wait(server->workers);

	/* Reload zone database and free old zones. */
	reopen_timers_database(conf, server);
	zonedb_reload(conf, server);

	/* Trim extra heap. */
	mem_trim();

	/* Resume workers and allow events on new zones. */
	worker_pool_resume(server->workers);
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_start);
	}
}

ref_t *server_set_ifaces(server_t *server, fdset_t *fds, int index, int thread_id)
{
	if (server == NULL || server->ifaces == NULL || fds == NULL) {
		return NULL;
	}

	rcu_read_lock();
	fdset_clear(fds);

	iface_t *i = NULL;
	WALK_LIST(i, server->ifaces->l) {
#ifdef ENABLE_REUSEPORT
		int udp_id = thread_id % i->fd_udp_count;
#else
		int udp_id = 0;
#endif
		switch(index) {
		case IO_TCP:
			fdset_add(fds, i->fd_tcp, POLLIN, NULL);
			break;
		case IO_UDP:
			fdset_add(fds, i->fd_udp[udp_id], POLLIN, NULL);
			break;
		default:
			assert(0);
		}
	}
	rcu_read_unlock();

	return &server->ifaces->ref;
}
