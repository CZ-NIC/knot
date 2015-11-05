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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include "common-knot/trim.h"
#include "knot/knot.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/conf/conf.h"
#include "knot/worker/pool.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb-load.h"
#include "libknot/dname.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"

/*! \brief Minimal send/receive buffer sizes. */
enum {
	UDP_MIN_RCVSIZE = 4096,
	UDP_MIN_SNDSIZE = 4096,
	TCP_MIN_RCVSIZE = 4096,
	TCP_MIN_SNDSIZE = sizeof(uint16_t) + UINT16_MAX
};

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
	memset(new_if, 0, sizeof(iface_t));
	memcpy(&new_if->addr, &cfg_if->addr, sizeof(struct sockaddr_storage));

	/* Convert to string address format. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(&cfg_if->addr, addr_str, sizeof(addr_str));

	/* Create bound UDP socket. */
	int sock = net_bound_socket(SOCK_DGRAM, &cfg_if->addr);
	if (sock < 0) {
		return sock;
	}

	if (!enlarge_net_buffers(sock, UDP_MIN_RCVSIZE, UDP_MIN_SNDSIZE)) {
		log_warning("failed to set network buffer sizes for UDP");
	}

	/* Set UDP as non-blocking. */
	fcntl(sock, F_SETFL, O_NONBLOCK);

	new_if->fd[IO_UDP] = sock;

	/* Create bound TCP socket. */
	sock = net_bound_socket(SOCK_STREAM, &cfg_if->addr);
	if (sock < 0) {
		close(new_if->fd[IO_UDP]);
		return sock;
	}

	if (!enlarge_net_buffers(sock, TCP_MIN_RCVSIZE, TCP_MIN_SNDSIZE)) {
		log_warning("failed to set network buffer sizes for TCP");
	}

	new_if->fd[IO_TCP] = sock;

	/* Listen for incoming connections. */
	ret = listen(sock, TCP_BACKLOG_SIZE);
	if (ret < 0) {
		close(new_if->fd[IO_UDP]);
		close(new_if->fd[IO_TCP]);
		log_error("failed to listen on TCP interface '%s'", addr_str);
		return KNOT_ERROR;
	}

	/* accept() must not block */
	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
		close(new_if->fd[IO_UDP]);
		close(new_if->fd[IO_TCP]);
		log_error("failed to listen on '%s' in non-blocking mode",
			  addr_str);
		return KNOT_ERROR;
	}

	return KNOT_EOK;
}

static void remove_ifacelist(struct ref_t *p)
{
	ifacelist_t *ifaces = (ifacelist_t *)p;

	/* Remove deprecated interfaces. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	iface_t *n = NULL, *m = NULL;
	WALK_LIST_DELSAFE(n, m, ifaces->u) {
		sockaddr_tostr(&n->addr, addr_str, sizeof(addr_str));
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
static int reconfigure_sockets(const struct conf_t *conf, server_t *s)
{
	/* Prepare helper lists. */
	char addr_str[SOCKADDR_STRLEN] = {0};
	int bound = 0;
	iface_t *m = 0;
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
	node_t *n = 0;
	WALK_LIST(n, conf->ifaces) {

		/* Find already matching interface. */
		int found_match = 0;
		conf_iface_t *cfg_if = (conf_iface_t*)n;
		if (s->ifaces) {
			WALK_LIST(m, s->ifaces->u) {
				/* Matching port and address. */
				if (sockaddr_cmp(&cfg_if->addr, &m->addr) == 0) {
					found_match = 1;
					break;
				}
			}
		}

		/* Found already bound interface. */
		if (found_match) {
			rem_node((node_t *)m);
		} else {
			sockaddr_tostr(&cfg_if->addr, addr_str, sizeof(addr_str));
			log_info("binding to interface '%s'", addr_str);

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

	/* Wait for readers that are reconfiguring right now. */
	/*! \note This subsystem will be reworked in #239 */
	for (unsigned proto = IO_UDP; proto <= IO_TCP; ++proto) {
		dt_unit_t *tu = s->handler[proto].unit;
		iohandler_t *ioh = &s->handler[proto];
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
		dt_unit_t *tu = s->handler[proto].unit;
		for (unsigned i = 0; i < tu->size; ++i) {
			ref_retain((ref_t *)newlist);
			s->handler[proto].thread_state[i] |= ServerReload;
			s->handler[proto].thread_id[i] = thread_count++;
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

	server->workers = worker_pool_create(bg_workers);
	if (server->workers == NULL) {
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
	worker_pool_destroy(server->workers);
	dt_delete(&server->iosched);

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

int server_start(server_t *s, bool async)
{
	dbg_server("%s(%p, %d)\n", __func__, s, async);
	if (s == 0) {
		return KNOT_EINVAL;
	}

	/* Start workers. */
	worker_pool_start(s->workers);

	/* Wait for enqueued events if not asynchronous. */
	if (!async) {
		worker_pool_wait(s->workers);
	}

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

	return ret;
}

void server_wait(server_t *s)
{
	if (s == NULL) {
		return;
	}

	dt_join(s->iosched);
	worker_pool_join(s->workers);

	if (s->tu_size == 0) {
		return;
	}

	for (unsigned i = 0; i < IO_COUNT; ++i) {
		server_free_handler(s->handler + i);
	}
}

int server_reload(server_t *server, const char *cf)
{
	if (!server || !cf) {
		return KNOT_EINVAL;
	}

	log_info("reloading configuration");
	int cf_ret = conf_open(cf);
	switch (cf_ret) {
	case KNOT_EOK:
		log_info("configuration reloaded");
		break;
	case KNOT_ENOENT:
		log_error("configuration file '%s' not found",
			  conf()->filename);
		break;
	default:
		log_error("failed to reload the configuration (%s)",
		          knot_strerror(cf_ret));
		break;
	}

	/*! \todo Close and bind to new remote control. */
	return cf_ret;
}

void server_stop(server_t *server)
{
	log_info("stopping server");

	/* Send termination event. */
	event_t *term_ev = evsched_event_create(&server->sched, NULL, NULL);
	evsched_schedule(term_ev, 0);
	dt_stop(server->iosched);

	/* Interrupt background workers. */
	worker_pool_stop(server->workers);

	/* Clear 'running' flag. */
	server->state &= ~ServerRunning;
}

/*! \brief Reconfigure UDP and TCP query processing threads. */
static int reconfigure_threads(const struct conf_t *conf, server_t *server)
{
	/* Estimate number of threads/manager. */
	int ret = KNOT_EOK;
	int tu_size = conf_udp_threads(conf);
	if ((unsigned)tu_size != server->tu_size) {
		/* Free old handlers */
		if (server->tu_size > 0) {
			for (unsigned i = 0; i < IO_COUNT; ++i) {
				server_free_handler(server->handler + i);
			}
		}

		/* Initialize I/O handlers. */
		ret = server_init_handler(server, IO_UDP, conf_udp_threads(conf),
		                          &udp_master, &udp_master_destruct);
		if (ret != KNOT_EOK) {
			log_error("failed to create UDP threads (%s)",
			          knot_strerror(ret));
			return ret;
		}

		/* Create at least CONFIG_XFERS threads for TCP for faster
		 * processing of massive bootstrap queries. */
		ret = server_init_handler(server, IO_TCP, conf_tcp_threads(conf),
		                          &tcp_master, &tcp_master_destruct);
		if (ret != KNOT_EOK) {
			log_error("failed to create TCP threads (%s)",
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
			log_error("failed to initialize rate limiting table");
		} else {
			rrl_setlocks(server->rrl, RRL_LOCK_GRANULARITY);
		}
	}
	if (server->rrl) {
		if (rrl_rate(server->rrl) != (uint32_t)conf->rrl) {
			/* We cannot free it, threads may use it.
			 * Setting it to <1 will disable rate limiting. */
			if (conf->rrl < 1) {
				log_info("rate limiting, disabled");
			} else {
				log_info("rate limiting, enabled with %u responses/second",
					 conf->rrl);
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
		log_info("Knot DNS %s starting", PACKAGE_VERSION);
	}

	/* Reconfigure rate limits. */
	int ret = KNOT_EOK;
	if ((ret = reconfigure_rate_limits(conf, server)) < 0) {
		log_error("failed to reconfigure rate limits");
		return ret;
	}

	/* Reconfigure server threads. */
	if ((ret = reconfigure_threads(conf, server)) < 0) {
		log_error("failed to reconfigure server threads");
		return ret;
	}

	/* Update bound sockets. */
	if ((ret = reconfigure_sockets(conf, server)) < 0) {
		log_error("failed to reconfigure server sockets");
		return ret;
	}

	return ret;
}

static void reopen_timers_database(const conf_t *conf, server_t *server)
{
	close_timers_db(server->timers_db);
	server->timers_db = NULL;

	int ret = open_timers_db(conf->storage, &server->timers_db);
	if (ret != KNOT_EOK && ret != KNOT_ENOTSUP) {
		log_warning("cannot open persistent timers DB (%s)",
		            knot_strerror(ret));
	}
}

int server_update_zones(const conf_t *conf, void *data)
{
	server_t *server = (server_t *)data;

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
    //printf("print to zonedb_reload\n");
    int ret = zonedb_reload(conf, server);
    //printf("meta to zonedb_reload\n");
	/* Trim extra heap. */
	mem_trim();

	/* Resume workers and allow events on new zones. */
	worker_pool_resume(server->workers);
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_start);
	}

	return ret;
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
