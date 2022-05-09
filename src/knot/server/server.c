/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <sys/types.h>   // OpenBSD
#include <netinet/tcp.h> // TCP_FASTOPEN
#include <sys/resource.h>

#include "libknot/libknot.h"
#include "libknot/yparser/ypschema.h"
#include "libknot/xdp.h"
#include "knot/common/log.h"
#include "knot/common/stats.h"
#include "knot/common/systemd.h"
#include "knot/common/unreachable.h"
#include "knot/conf/confio.h"
#include "knot/conf/migration.h"
#include "knot/conf/module.h"
#include "knot/dnssec/kasp/kasp_db.h"
#include "knot/journal/journal_basic.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb-load.h"
#include "knot/worker/pool.h"
#include "contrib/conn_pool.h"
#include "contrib/net.h"
#include "contrib/openbsd/strlcat.h"
#include "contrib/os.h"
#include "contrib/sockaddr.h"
#include "contrib/trim.h"

#ifdef ENABLE_XDP
#include <net/if.h>
#endif

#ifdef SO_ATTACH_REUSEPORT_CBPF
#include <linux/filter.h>
#endif

/*! \brief Minimal send/receive buffer sizes. */
enum {
	UDP_MIN_RCVSIZE = 4096,
	UDP_MIN_SNDSIZE = 4096,
	TCP_MIN_RCVSIZE = 4096,
	TCP_MIN_SNDSIZE = sizeof(uint16_t) + UINT16_MAX
};

/*! \brief Unbind interface and clear the structure. */
static void server_deinit_iface(iface_t *iface, bool dealloc)
{
	assert(iface);

	/* Free UDP handler. */
	if (iface->fd_udp != NULL) {
		for (int i = 0; i < iface->fd_udp_count; i++) {
			if (iface->fd_udp[i] > -1) {
				close(iface->fd_udp[i]);
			}
		}
		free(iface->fd_udp);
	}

	for (int i = 0; i < iface->fd_xdp_count; i++) {
#ifdef ENABLE_XDP
		knot_xdp_deinit(iface->xdp_sockets[i]);
#else
		assert(0);
#endif
	}
	free(iface->fd_xdp);
	free(iface->xdp_sockets);

	/* Free TCP handler. */
	if (iface->fd_tcp != NULL) {
		for (int i = 0; i < iface->fd_tcp_count; i++) {
			if (iface->fd_tcp[i] > -1) {
				close(iface->fd_tcp[i]);
			}
		}
		free(iface->fd_tcp);
	}

	if (dealloc) {
		free(iface);
	}
}

/*! \brief Deinit server interface list. */
static void server_deinit_iface_list(iface_t *ifaces, size_t n)
{
	if (ifaces != NULL) {
		for (size_t i = 0; i < n; i++) {
			server_deinit_iface(ifaces + i, false);
		}
		free(ifaces);
	}
}

/*!
 * \brief Attach SO_REUSEPORT socket filter for perfect CPU locality.
 *
 * \param sock        Socket where to attach the CBPF filter to.
 * \param sock_count  Number of sockets.
 */
static bool server_attach_reuseport_bpf(const int sock, const int sock_count)
{
#ifdef SO_ATTACH_REUSEPORT_CBPF
	struct sock_filter code[] = {
		/* A = raw_smp_processor_id(). */
		{ BPF_LD  | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_CPU },
		/* Adjust the CPUID to socket group size. */
		{ BPF_ALU | BPF_MOD | BPF_K, 0, 0, sock_count },
		/* Return A. */
		{ BPF_RET | BPF_A, 0, 0, 0 },
	};

	struct sock_fprog prog = { 0 };
	prog.len = sizeof(code) / sizeof(*code);
	prog.filter = code;

	return setsockopt(sock, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog)) == 0;
#else
	return true;
#endif
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
 * Linux 3.15 has IP_PMTUDISC_OMIT which makes sockets
 * ignore PMTU information and send packets with DF=0.
 * Fragmentation is allowed if and only if the packet
 * size exceeds the outgoing interface MTU or the packet
 * encounters smaller MTU link in network.
 * This mitigates DNS fragmentation attacks by preventing
 * forged PMTU information.
 * FreeBSD already has same semantics without setting
 * the option.
 */
static int disable_pmtudisc(int sock, int family)
{
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_OMIT)
	if (family == AF_INET) {
		int action_omit = IP_PMTUDISC_OMIT;
		if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &action_omit,
		    sizeof(action_omit)) != 0) {
			return knot_map_errno();
		}
	}
#endif
	return KNOT_EOK;
}

static iface_t *server_init_xdp_iface(struct sockaddr_storage *addr, bool route_check,
                                      bool udp, bool tcp, unsigned *thread_id_start)
{
#ifndef ENABLE_XDP
	assert(0);
	return NULL;
#else
	conf_xdp_iface_t iface;
	int ret = conf_xdp_iface(addr, &iface);
	if (ret != KNOT_EOK) {
		log_error("failed to initialize XDP interface (%s)",
		          knot_strerror(ret));
		return NULL;
	}

	iface_t *new_if = calloc(1, sizeof(*new_if));
	if (new_if == NULL) {
		log_error("failed to initialize XDP interface");
		return NULL;
	}
	memcpy(&new_if->addr, addr, sizeof(*addr));

	new_if->fd_xdp = calloc(iface.queues, sizeof(int));
	new_if->xdp_sockets = calloc(iface.queues, sizeof(*new_if->xdp_sockets));
	if (new_if->fd_xdp == NULL || new_if->xdp_sockets == NULL) {
		log_error("failed to initialize XDP interface");
		server_deinit_iface(new_if, true);
		return NULL;
	}
	new_if->xdp_first_thread_id = *thread_id_start;
	*thread_id_start += iface.queues;

	knot_xdp_filter_flag_t xdp_flags = udp ? KNOT_XDP_FILTER_UDP : 0;
	if (tcp) {
		xdp_flags |= KNOT_XDP_FILTER_TCP;
	}
	if (route_check) {
		xdp_flags |= KNOT_XDP_FILTER_ROUTE;
	}

	for (int i = 0; i < iface.queues; i++) {
		knot_xdp_load_bpf_t mode =
			(i == 0 ? KNOT_XDP_LOAD_BPF_ALWAYS : KNOT_XDP_LOAD_BPF_NEVER);
		ret = knot_xdp_init(new_if->xdp_sockets + i, iface.name, i,
		                    xdp_flags, iface.port, 0, mode);
		if (ret == -EBUSY && i == 0) {
			log_notice("XDP interface %s@%u is busy, retrying initialization",
			           iface.name, iface.port);
			ret = knot_xdp_init(new_if->xdp_sockets + i, iface.name, i,
			                    xdp_flags, iface.port, 0,
			                    KNOT_XDP_LOAD_BPF_ALWAYS_UNLOAD);
		}
		if (ret != KNOT_EOK) {
			log_warning("failed to initialize XDP interface %s@%u, queue %d (%s)",
			            iface.name, iface.port, i, knot_strerror(ret));
			server_deinit_iface(new_if, true);
			new_if = NULL;
			break;
		}
		new_if->fd_xdp[i] = knot_xdp_socket_fd(new_if->xdp_sockets[i]);
		new_if->fd_xdp_count++;
	}

	if (ret == KNOT_EOK) {
		knot_xdp_mode_t mode = knot_eth_xdp_mode(if_nametoindex(iface.name));
		log_debug("initialized XDP interface %s@%u UDP%s, queues %d, %s mode%s",
		          iface.name, iface.port, (tcp ? "/TCP" : ""), iface.queues,
		          (mode == KNOT_XDP_MODE_FULL ? "native" : "emulated"),
		          route_check ? ", route check" : "");
	}

	return new_if;
#endif
}

/*!
 * \brief Create and initialize new interface.
 *
 * Both TCP and UDP sockets will be created for the interface.
 *
 * \param addr              Socket address.
 * \param udp_thread_count  Number of created UDP workers.
 * \param tcp_thread_count  Number of created TCP workers.
 * \param tcp_reuseport     Indication if reuseport on TCP is enabled.
 * \param socket_affinity   Indication if CBPF should be attached.
 *
 * \retval Pointer to a new initialized interface.
 * \retval NULL if error.
 */
static iface_t *server_init_iface(struct sockaddr_storage *addr,
                                  int udp_thread_count, int tcp_thread_count,
                                  bool tcp_reuseport, bool socket_affinity)
{
	iface_t *new_if = calloc(1, sizeof(*new_if));
	if (new_if == NULL) {
		log_error("failed to initialize interface");
		return NULL;
	}
	memcpy(&new_if->addr, addr, sizeof(*addr));

	/* Convert to string address format. */
	char addr_str[SOCKADDR_STRLEN] = { 0 };
	sockaddr_tostr(addr_str, sizeof(addr_str), addr);

	int udp_socket_count = 1;
	int udp_bind_flags = 0;
	int tcp_socket_count = 1;
	int tcp_bind_flags = 0;

#ifdef ENABLE_REUSEPORT
	udp_socket_count = udp_thread_count;
	udp_bind_flags |= NET_BIND_MULTIPLE;

	if (tcp_reuseport) {
		tcp_socket_count = tcp_thread_count;
		tcp_bind_flags |= NET_BIND_MULTIPLE;
	}
#endif

	new_if->fd_udp = malloc(udp_socket_count * sizeof(int));
	new_if->fd_tcp = malloc(tcp_socket_count * sizeof(int));
	if (new_if->fd_udp == NULL || new_if->fd_tcp == NULL) {
		log_error("failed to initialize interface");
		server_deinit_iface(new_if, true);
		return NULL;
	}

	bool warn_bind = true;
	bool warn_cbpf = true;
	bool warn_bufsize = true;
	bool warn_pktinfo = true;
	bool warn_flag_misc = true;

	/* Create bound UDP sockets. */
	for (int i = 0; i < udp_socket_count; i++) {
		int sock = net_bound_socket(SOCK_DGRAM, addr, udp_bind_flags);
		if (sock == KNOT_EADDRNOTAVAIL) {
			udp_bind_flags |= NET_BIND_NONLOCAL;
			sock = net_bound_socket(SOCK_DGRAM, addr, udp_bind_flags);
			if (sock >= 0 && warn_bind) {
				log_warning("address %s UDP bound, but required nonlocal bind", addr_str);
				warn_bind = false;
			}
		}

		if (sock < 0) {
			log_error("cannot bind address %s UDP (%s)", addr_str,
			          knot_strerror(sock));
			server_deinit_iface(new_if, true);
			return NULL;
		}

		if ((udp_bind_flags & NET_BIND_MULTIPLE) && socket_affinity) {
			if (!server_attach_reuseport_bpf(sock, udp_socket_count) &&
			    warn_cbpf) {
				log_warning("cannot ensure optimal CPU locality for UDP");
				warn_cbpf = false;
			}
		}

		if (!enlarge_net_buffers(sock, UDP_MIN_RCVSIZE, UDP_MIN_SNDSIZE) &&
		    warn_bufsize) {
			log_warning("failed to set network buffer sizes for UDP");
			warn_bufsize = false;
		}

		if (sockaddr_is_any(addr) && !enable_pktinfo(sock, addr->ss_family) &&
		    warn_pktinfo) {
			log_warning("failed to enable received packet information retrieval");
			warn_pktinfo = false;
		}

		int ret = disable_pmtudisc(sock, addr->ss_family);
		if (ret != KNOT_EOK && warn_flag_misc) {
			log_warning("failed to disable Path MTU discovery for IPv4/UDP (%s)",
			            knot_strerror(ret));
			warn_flag_misc = false;
		}

		new_if->fd_udp[new_if->fd_udp_count] = sock;
		new_if->fd_udp_count += 1;
	}

	warn_bind = true;
	warn_cbpf = true;
	warn_bufsize = true;
	warn_flag_misc = true;

	/* Create bound TCP sockets. */
	for (int i = 0; i < tcp_socket_count; i++) {
		int sock = net_bound_socket(SOCK_STREAM, addr, tcp_bind_flags);
		if (sock == KNOT_EADDRNOTAVAIL) {
			tcp_bind_flags |= NET_BIND_NONLOCAL;
			sock = net_bound_socket(SOCK_STREAM, addr, tcp_bind_flags);
			if (sock >= 0 && warn_bind) {
				log_warning("address %s TCP bound, but required nonlocal bind", addr_str);
				warn_bind = false;
			}
		}

		if (sock < 0) {
			log_error("cannot bind address %s TCP (%s)", addr_str,
			          knot_strerror(sock));
			server_deinit_iface(new_if, true);
			return NULL;
		}

		if (!enlarge_net_buffers(sock, TCP_MIN_RCVSIZE, TCP_MIN_SNDSIZE) &&
		    warn_bufsize) {
			log_warning("failed to set network buffer sizes for TCP");
			warn_bufsize = false;
		}

		new_if->fd_tcp[new_if->fd_tcp_count] = sock;
		new_if->fd_tcp_count += 1;

		/* Listen for incoming connections. */
		int ret = listen(sock, TCP_BACKLOG_SIZE);
		if (ret < 0) {
			log_error("failed to listen on TCP interface %s", addr_str);
			server_deinit_iface(new_if, true);
			return NULL;
		}

		if ((tcp_bind_flags & NET_BIND_MULTIPLE) && socket_affinity) {
			if (!server_attach_reuseport_bpf(sock, tcp_socket_count) &&
			    warn_cbpf) {
				log_warning("cannot ensure optimal CPU locality for TCP");
				warn_cbpf = false;
			}
		}

		/* Try to enable TCP Fast Open. */
		ret = net_bound_tfo(sock, TCP_BACKLOG_SIZE);
		if (ret != KNOT_EOK && ret != KNOT_ENOTSUP && warn_flag_misc) {
			log_warning("failed to enable TCP Fast Open on %s (%s)",
			            addr_str, knot_strerror(ret));
			warn_flag_misc = false;
		}
	}

	return new_if;
}

static void log_sock_conf(conf_t *conf)
{
	char buf[128] = "";
#if defined(ENABLE_REUSEPORT)
	strlcat(buf, "UDP", sizeof(buf));
	if (conf->cache.srv_tcp_reuseport) {
		strlcat(buf, "/TCP", sizeof(buf));
	}
	strlcat(buf, " reuseport", sizeof(buf));
	if (conf->cache.srv_socket_affinity) {
		strlcat(buf, ", socket affinity", sizeof(buf));
	}
#endif
#if defined(TCP_FASTOPEN)
	if (buf[0] != '\0') {
		strlcat(buf, ", ", sizeof(buf));
	}
	strlcat(buf, "incoming", sizeof(buf));
	if (conf->cache.srv_tcp_fastopen) {
		strlcat(buf, "/outgoing", sizeof(buf));
	}
	strlcat(buf, " TCP Fast Open", sizeof(buf));
#endif
	if (buf[0] != '\0') {
		log_info("using %s", buf);
	}
}

/*! \brief Initialize bound sockets according to configuration. */
static int configure_sockets(conf_t *conf, server_t *s)
{
	if (s->state & ServerRunning) {
		return KNOT_EOK;
	}

	conf_val_t listen_val = conf_get(conf, C_SRV, C_LISTEN);
	conf_val_t lisxdp_val = conf_get(conf, C_XDP, C_LISTEN);
	if (lisxdp_val.code != KNOT_EOK) {
		lisxdp_val = conf_get(conf, C_SRV, C_LISTEN_XDP);
	}
	conf_val_t rundir_val = conf_get(conf, C_SRV, C_RUNDIR);

	if (listen_val.code == KNOT_EOK) {
		log_sock_conf(conf);
	} else if (lisxdp_val.code != KNOT_EOK) {
		log_warning("no network interface configured");
		return KNOT_EOK;
	}

#ifdef ENABLE_XDP
	if (lisxdp_val.code == KNOT_EOK && !linux_at_least(5, 11)) {
		struct rlimit min_limit = { RLIM_INFINITY, RLIM_INFINITY };
		struct rlimit cur_limit = { 0 };
		if (getrlimit(RLIMIT_MEMLOCK, &cur_limit) != 0 ||
		    cur_limit.rlim_cur != min_limit.rlim_cur ||
		    cur_limit.rlim_max != min_limit.rlim_max) {
			int ret = setrlimit(RLIMIT_MEMLOCK, &min_limit);
			if (ret != 0) {
				log_error("failed to increase RLIMIT_MEMLOCK (%s)",
				          knot_strerror(errno));
				return KNOT_ESYSTEM;
			}
		}
	}
#endif

	size_t real_nifs = 0;
	size_t nifs = conf_val_count(&listen_val) + conf_val_count(&lisxdp_val);
	iface_t *newlist = calloc(nifs, sizeof(*newlist));
	if (newlist == NULL) {
		log_error("failed to allocate memory for network sockets");
		return KNOT_ENOMEM;
	}

	/* Normal UDP and TCP sockets. */
	unsigned size_udp = s->handlers[IO_UDP].handler.unit->size;
	unsigned size_tcp = s->handlers[IO_TCP].handler.unit->size;
	bool tcp_reuseport = conf->cache.srv_tcp_reuseport;
	bool socket_affinity = conf->cache.srv_socket_affinity;
	char *rundir = conf_abs_path(&rundir_val, NULL);
	while (listen_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&listen_val, rundir);
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
		log_info("binding to interface %s", addr_str);

		iface_t *new_if = server_init_iface(&addr, size_udp, size_tcp,
		                                    tcp_reuseport, socket_affinity);
		if (new_if == NULL) {
			server_deinit_iface_list(newlist, nifs);
			free(rundir);
			return KNOT_ERROR;
		}
		memcpy(&newlist[real_nifs++], new_if, sizeof(*newlist));
		free(new_if);

		conf_val_next(&listen_val);
	}
	free(rundir);

	/* XDP sockets. */
	bool xdp_udp = conf->cache.xdp_udp;
	bool xdp_tcp = conf->cache.xdp_tcp;
	bool route_check = conf->cache.xdp_route_check;
	unsigned thread_id = s->handlers[IO_UDP].handler.unit->size +
	                     s->handlers[IO_TCP].handler.unit->size;
	while (lisxdp_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&lisxdp_val, NULL);
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
		log_info("binding to XDP interface %s", addr_str);

		iface_t *new_if = server_init_xdp_iface(&addr, route_check, xdp_udp,
		                                        xdp_tcp, &thread_id);
		if (new_if == NULL) {
			server_deinit_iface_list(newlist, nifs);
			return KNOT_ERROR;
		}
		memcpy(&newlist[real_nifs++], new_if, sizeof(*newlist));
		free(new_if);

		conf_val_next(&lisxdp_val);
	}
	assert(real_nifs <= nifs);
	nifs = real_nifs;

	/* Publish new list. */
	s->ifaces = newlist;
	s->n_ifaces = nifs;

	/* Assign thread identifiers unique per all handlers. */
	unsigned thread_count = 0;
	for (unsigned proto = IO_UDP; proto <= IO_XDP; ++proto) {
		dt_unit_t *tu = s->handlers[proto].handler.unit;
		for (unsigned i = 0; tu != NULL && i < tu->size; ++i) {
			s->handlers[proto].handler.thread_id[i] = thread_count++;
		}
	}

	return KNOT_EOK;
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

	int ret = catalog_update_init(&server->catalog_upd);
	if (ret != KNOT_EOK) {
		worker_pool_destroy(server->workers);
		evsched_deinit(&server->sched);
		return ret;
	}

	zone_backups_init(&server->backup_ctxs);

	char *catalog_dir = conf_db(conf(), C_CATALOG_DB);
	conf_val_t catalog_size = conf_db_param(conf(), C_CATALOG_DB_MAX_SIZE);
	catalog_init(&server->catalog, catalog_dir, conf_int(&catalog_size));
	free(catalog_dir);
	conf()->catalog = &server->catalog;

	char *journal_dir = conf_db(conf(), C_JOURNAL_DB);
	conf_val_t journal_size = conf_db_param(conf(), C_JOURNAL_DB_MAX_SIZE);
	conf_val_t journal_mode = conf_db_param(conf(), C_JOURNAL_DB_MODE);
	knot_lmdb_init(&server->journaldb, journal_dir, conf_int(&journal_size), journal_env_flags(conf_opt(&journal_mode), false), NULL);
	free(journal_dir);

	kasp_db_ensure_init(&server->kaspdb, conf());

	char *timer_dir = conf_db(conf(), C_TIMER_DB);
	conf_val_t timer_size = conf_db_param(conf(), C_TIMER_DB_MAX_SIZE);
	knot_lmdb_init(&server->timerdb, timer_dir, conf_int(&timer_size), 0, NULL);
	free(timer_dir);

	return KNOT_EOK;
}

void server_deinit(server_t *server)
{
	if (server == NULL) {
		return;
	}

	zone_backups_deinit(&server->backup_ctxs);

	/* Save zone timers. */
	if (server->zone_db != NULL) {
		log_info("updating persistent timer DB");
		int ret = zone_timers_write_all(&server->timerdb, server->zone_db);
		if (ret != KNOT_EOK) {
			log_warning("failed to update persistent timer DB (%s)",
				    knot_strerror(ret));
		}
	}

	/* Free remaining interfaces. */
	server_deinit_iface_list(server->ifaces, server->n_ifaces);

	/* Free threads and event handlers. */
	worker_pool_destroy(server->workers);

	/* Free zone database. */
	knot_zonedb_deep_free(&server->zone_db, true);

	/* Free remaining events. */
	evsched_deinit(&server->sched);

	/* Free catalog zone context. */
	catalog_update_clear(&server->catalog_upd);
	catalog_update_deinit(&server->catalog_upd);
	catalog_deinit(&server->catalog);

	/* Close persistent timers DB. */
	knot_lmdb_deinit(&server->timerdb);

	/* Close kasp_db. */
	knot_lmdb_deinit(&server->kaspdb);

	/* Close journal database if open. */
	knot_lmdb_deinit(&server->journaldb);

	/* Close and deinit connection pool. */
	conn_pool_deinit(global_conn_pool);
	global_conn_pool = NULL;
	knot_unreachables_deinit(&global_unreachables);
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
}

static void worker_wait_cb(worker_pool_t *pool)
{
	systemd_zone_load_timeout_notify();

	static uint64_t last_ns = 0;
	struct timespec now = time_now();
	uint64_t now_ns = 1000000000 * now.tv_sec + now.tv_nsec;
	/* Too frequent worker_pool_status() call with many zones is expensive. */
	if (now_ns - last_ns > 1000000000) {
		int running, queued;
		worker_pool_status(pool, true, &running, &queued);
		systemd_tasks_status_notify(running + queued);
		last_ns = now_ns;
	}
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
		worker_pool_wait_cb(server->workers, worker_wait_cb);
		systemd_tasks_status_notify(0);
	}

	/* Start evsched handler. */
	evsched_start(&server->sched);

	/* Start I/O handlers. */
	server->state |= ServerRunning;
	for (int proto = IO_UDP; proto <= IO_XDP; ++proto) {
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

	for (int proto = IO_UDP; proto <= IO_XDP; ++proto) {
		if (server->handlers[proto].size > 0) {
			server_free_handler(&server->handlers[proto].handler);
		}
	}
}

static int reload_conf(conf_t *new_conf)
{
	yp_schema_purge_dynamic(new_conf->schema);

	/* Re-load common modules. */
	int ret = conf_mod_load_common(new_conf);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Re-import config file if specified. */
	const char *filename = conf()->filename;
	if (filename != NULL) {
		log_info("reloading configuration file '%s'", filename);

		/* Import the configuration file. */
		ret = conf_import(new_conf, filename, true, false);
		if (ret != KNOT_EOK) {
			log_error("failed to load configuration file (%s)",
			          knot_strerror(ret));
			return ret;
		}
	} else {
		log_info("reloading configuration database '%s'",
		         knot_db_lmdb_get_path(new_conf->db));

		/* Re-load extra modules. */
		for (conf_iter_t iter = conf_iter(new_conf, C_MODULE);
		     iter.code == KNOT_EOK; conf_iter_next(new_conf, &iter)) {
			conf_val_t id = conf_iter_id(new_conf, &iter);
			conf_val_t file = conf_id_get(new_conf, C_MODULE, C_FILE, &id);
			ret = conf_mod_load_extra(new_conf, conf_str(&id), conf_str(&file), false);
			if (ret != KNOT_EOK) {
				conf_iter_finish(new_conf, &iter);
				return ret;
			}
		}
	}

	conf_mod_load_purge(new_conf, false);

	// Migrate from old schema.
	ret = conf_migrate(new_conf);
	if (ret != KNOT_EOK) {
		log_error("failed to migrate configuration (%s)", knot_strerror(ret));
	}

	return KNOT_EOK;
}

/*! \brief Check if parameter listen(-xdp) has been changed since knotd started. */
static bool listen_changed(conf_t *conf, server_t *server)
{
	assert(server->ifaces);

	conf_val_t listen_val = conf_get(conf, C_SRV, C_LISTEN);
	conf_val_t lisxdp_val = conf_get(conf, C_XDP, C_LISTEN);
	if (lisxdp_val.code != KNOT_EOK) {
		lisxdp_val = conf_get(conf, C_SRV, C_LISTEN_XDP);
	}
	size_t new_count = conf_val_count(&listen_val) + conf_val_count(&lisxdp_val);
	size_t old_count = server->n_ifaces;
	if (new_count != old_count) {
		return true;
	}

	conf_val_t rundir_val = conf_get(conf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);
	size_t matches = 0;

	/* Find matching interfaces. */
	while (listen_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&listen_val, rundir);
		bool found = false;
		for (size_t i = 0; i < server->n_ifaces; i++) {
			if (sockaddr_cmp(&addr, &server->ifaces[i].addr, false) == 0) {
				matches++;
				found = true;
				break;
			}
		}
		if (!found) {
			break;
		}
		conf_val_next(&listen_val);
	}
	free(rundir);

	while (lisxdp_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&lisxdp_val, NULL);
		bool found = false;
		for (size_t i = 0; i < server->n_ifaces; i++) {
			if (sockaddr_cmp(&addr, &server->ifaces[i].addr, false) == 0) {
				matches++;
				found = true;
				break;
			}
		}
		if (!found) {
			break;
		}
		conf_val_next(&lisxdp_val);
	}

	return matches != old_count;
}

/*! \brief Log warnings if config change requires a restart. */
static void warn_server_reconfigure(conf_t *conf, server_t *server)
{
	const char *msg = "changes of %s require restart to take effect";

	static bool warn_tcp_reuseport = true;
	static bool warn_socket_affinity = true;
	static bool warn_udp = true;
	static bool warn_tcp = true;
	static bool warn_bg = true;
	static bool warn_listen = true;
	static bool warn_xdp_udp = true;
	static bool warn_xdp_tcp = true;
	static bool warn_route_check = true;
	static bool warn_rmt_pool_limit = true;

	if (warn_tcp_reuseport && conf->cache.srv_tcp_reuseport != conf_get_bool(conf, C_SRV, C_TCP_REUSEPORT)) {
		log_warning(msg, &C_TCP_REUSEPORT[1]);
		warn_tcp_reuseport = false;
	}

	if (warn_socket_affinity && conf->cache.srv_socket_affinity != conf_get_bool(conf, C_SRV, C_SOCKET_AFFINITY)) {
		log_warning(msg, &C_SOCKET_AFFINITY[1]);
		warn_socket_affinity = false;
	}

	if (warn_udp && server->handlers[IO_UDP].size != conf_udp_threads(conf)) {
		log_warning(msg, &C_UDP_WORKERS[1]);
		warn_udp = false;
	}

	if (warn_tcp && server->handlers[IO_TCP].size != conf_tcp_threads(conf)) {
		log_warning(msg, &C_TCP_WORKERS[1]);
		warn_tcp = false;
	}

	if (warn_bg && conf->cache.srv_bg_threads != conf_bg_threads(conf)) {
		log_warning(msg, &C_BG_WORKERS[1]);
		warn_bg = false;
	}

	if (warn_listen && server->ifaces != NULL && listen_changed(conf, server)) {
		log_warning(msg, "listen(-xdp)");
		warn_listen = false;
	}

	if (warn_xdp_udp && conf->cache.xdp_udp != conf_get_bool(conf, C_XDP, C_UDP)) {
		log_warning(msg, &C_UDP[1]);
		warn_xdp_udp = false;
	}

	if (warn_xdp_tcp && conf->cache.xdp_tcp != conf_get_bool(conf, C_XDP, C_TCP)) {
		log_warning(msg, &C_TCP[1]);
		warn_xdp_tcp = false;
	}

	if (warn_route_check && conf->cache.xdp_route_check != conf_get_bool(conf, C_XDP, C_ROUTE_CHECK)) {
		log_warning(msg, &C_ROUTE_CHECK[1]);
		warn_route_check = false;
	}

	if (warn_rmt_pool_limit && global_conn_pool != NULL &&
	    global_conn_pool->capacity != conf_get_int(conf, C_SRV, C_RMT_POOL_LIMIT)) {
		log_warning(msg, &C_RMT_POOL_LIMIT[1]);
		warn_rmt_pool_limit = false;
	}
}

int server_reload(server_t *server)
{
	if (server == NULL) {
		return KNOT_EINVAL;
	}

	systemd_reloading_notify();

	/* Check for no edit mode. */
	if (conf()->io.txn != NULL) {
		log_warning("reload aborted due to active configuration transaction");
		systemd_ready_notify();
		return KNOT_TXN_EEXISTS;
	}

	conf_t *new_conf = NULL;
	int ret = conf_clone(&new_conf);
	if (ret != KNOT_EOK) {
		log_error("failed to initialize configuration (%s)",
		          knot_strerror(ret));
		systemd_ready_notify();
		return ret;
	}

	yp_flag_t flags = conf()->io.flags;
	bool full = !(flags & CONF_IO_FACTIVE);
	bool reuse_modules = !full && !(flags & CONF_IO_FRLD_MOD);

	/* Reload configuration and modules if full reload or a module change. */
	if (full || !reuse_modules) {
		ret = reload_conf(new_conf);
		if (ret != KNOT_EOK) {
			conf_free(new_conf);
			systemd_ready_notify();
			return ret;
		}

		conf_activate_modules(new_conf, server, NULL, new_conf->query_modules,
		                      &new_conf->query_plan);
	}

	conf_update_flag_t upd_flags = CONF_UPD_FNOFREE;
	if (!full) {
		upd_flags |= CONF_UPD_FCONFIO;
	}
	if (reuse_modules) {
		upd_flags |= CONF_UPD_FMODULES;
	}

	/* Update to the new config. */
	conf_t *old_conf = conf_update(new_conf, upd_flags);

	/* Reload each component if full reload or a specific one if required. */
	if (full || (flags & CONF_IO_FRLD_LOG)) {
		log_reconfigure(conf());
	}
	if (full || (flags & CONF_IO_FRLD_SRV)) {
		(void)server_reconfigure(conf(), server);
		warn_server_reconfigure(conf(), server);
		stats_reconfigure(conf(), server);
	}
	if (full || (flags & (CONF_IO_FRLD_ZONES | CONF_IO_FRLD_ZONE))) {
		server_update_zones(conf(), server);
	}

	/* Free old config needed for module unload in zone reload. */
	conf_free(old_conf);

	if (full) {
		log_info("configuration reloaded");
	} else {
		// Reset confio reload context.
		conf()->io.flags = YP_FNONE;
		if (conf()->io.zones != NULL) {
			trie_clear(conf()->io.zones);
		}
	}

	systemd_ready_notify();

	return KNOT_EOK;
}

void server_stop(server_t *server)
{
	log_info("stopping server");
	systemd_stopping_notify();

	/* Stop scheduler. */
	evsched_stop(&server->sched);
	/* Interrupt background workers. */
	worker_pool_stop(server->workers);

	/* Clear 'running' flag. */
	server->state &= ~ServerRunning;
}

static int set_handler(server_t *server, int index, unsigned size, runnable_t run)
{
	/* Initialize I/O handlers. */
	int ret = server_init_handler(server, index, size, run, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	server->handlers[index].size = size;

	return KNOT_EOK;
}

static int configure_threads(conf_t *conf, server_t *server)
{
	int ret = set_handler(server, IO_UDP, conf->cache.srv_udp_threads, udp_master);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (conf->cache.srv_xdp_threads > 0) {
		ret = set_handler(server, IO_XDP, conf->cache.srv_xdp_threads, udp_master);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return set_handler(server, IO_TCP, conf->cache.srv_tcp_threads, tcp_master);
}

static int reconfigure_journal_db(conf_t *conf, server_t *server)
{
	char *journal_dir = conf_db(conf, C_JOURNAL_DB);
	conf_val_t journal_size = conf_db_param(conf, C_JOURNAL_DB_MAX_SIZE);
	conf_val_t journal_mode = conf_db_param(conf, C_JOURNAL_DB_MODE);
	int ret = knot_lmdb_reinit(&server->journaldb, journal_dir, conf_int(&journal_size),
	                           journal_env_flags(conf_opt(&journal_mode), false));
	if (ret != KNOT_EOK) {
		log_warning("ignored reconfiguration of journal DB (%s)", knot_strerror(ret));
	}
	free(journal_dir);

	return KNOT_EOK; // not "ret"
}

static int reconfigure_kasp_db(conf_t *conf, server_t *server)
{
	char *kasp_dir = conf_db(conf, C_KASP_DB);
	conf_val_t kasp_size = conf_db_param(conf, C_KASP_DB_MAX_SIZE);
	int ret = knot_lmdb_reinit(&server->kaspdb, kasp_dir, conf_int(&kasp_size), 0);
	if (ret != KNOT_EOK) {
		log_warning("ignored reconfiguration of KASP DB (%s)", knot_strerror(ret));
	}
	free(kasp_dir);

	return KNOT_EOK; // not "ret"
}

static int reconfigure_timer_db(conf_t *conf, server_t *server)
{
	char *timer_dir = conf_db(conf, C_TIMER_DB);
	conf_val_t timer_size = conf_db_param(conf, C_TIMER_DB_MAX_SIZE);
	int ret = knot_lmdb_reconfigure(&server->timerdb, timer_dir, conf_int(&timer_size), 0);
	free(timer_dir);
	return ret;
}

static int reconfigure_remote_pool(conf_t *conf)
{
	conf_val_t val = conf_get(conf, C_SRV, C_RMT_POOL_LIMIT);
	size_t limit = conf_int(&val);
	val = conf_get(conf, C_SRV, C_RMT_POOL_TIMEOUT);
	knot_timediff_t timeout = conf_int(&val);
	if (global_conn_pool == NULL && limit > 0) {
		conn_pool_t *new_pool = conn_pool_init(limit, timeout);
		if (new_pool == NULL) {
			return KNOT_ENOMEM;
		}
		global_conn_pool = new_pool;
	} else {
		(void)conn_pool_timeout(global_conn_pool, timeout);
	}

	val = conf_get(conf, C_SRV, C_RMT_RETRY_DELAY);
	int delay_ms = conf_int(&val);
	if (global_unreachables == NULL && delay_ms > 0) {
		global_unreachables = knot_unreachables_init(delay_ms);
	} else {
		(void)knot_unreachables_ttl(global_unreachables, delay_ms);
	}

	return KNOT_EOK;
}

int server_reconfigure(conf_t *conf, server_t *server)
{
	if (conf == NULL || server == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	/* First reconfiguration. */
	if (!(server->state & ServerRunning)) {
		log_info("Knot DNS %s starting", PACKAGE_VERSION);

		size_t mapsize = conf->mapsize / (1024 * 1024);
		if (conf->filename != NULL) {
			log_info("loaded configuration file '%s', mapsize %zu MiB",
			         conf->filename, mapsize);
		} else {
			log_info("loaded configuration database '%s', mapsize %zu MiB",
			         knot_db_lmdb_get_path(conf->db), mapsize);
		}

		/* Configure server threads. */
		if ((ret = configure_threads(conf, server)) != KNOT_EOK) {
			log_error("failed to configure server threads (%s)",
			          knot_strerror(ret));
			return ret;
		}

		/* Configure sockets. */
		if ((ret = configure_sockets(conf, server)) != KNOT_EOK) {
			return ret;
		}

		if (conf_lmdb_readers(conf) > CONF_MAX_DB_READERS) {
			log_warning("config, exceeded number of database readers");
		}
	}

	/* Reconfigure journal DB. */
	if ((ret = reconfigure_journal_db(conf, server)) != KNOT_EOK) {
		log_error("failed to reconfigure journal DB (%s)",
		          knot_strerror(ret));
	}

	/* Reconfigure KASP DB. */
	if ((ret = reconfigure_kasp_db(conf, server)) != KNOT_EOK) {
		log_error("failed to reconfigure KASP DB (%s)",
		          knot_strerror(ret));
	}

	/* Reconfigure Timer DB. */
	if ((ret = reconfigure_timer_db(conf, server)) != KNOT_EOK) {
		log_error("failed to reconfigure Timer DB (%s)",
		          knot_strerror(ret));
	}

	/* Reconfigure connection pool. */
	if ((ret = reconfigure_remote_pool(conf)) != KNOT_EOK) {
		log_error("failed to reconfigure remote pool (%s)",
		          knot_strerror(ret));
	}

	return KNOT_EOK;
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

	/* Suspend adding events to worker pool queue, wait for queued events. */
	evsched_pause(&server->sched);
	worker_pool_wait(server->workers);

	/* Reload zone database and free old zones. */
	zonedb_reload(conf, server);

	/* Trim extra heap. */
	mem_trim();

	/* Resume processing events on new zones. */
	evsched_resume(&server->sched);
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_start);
	}
}
