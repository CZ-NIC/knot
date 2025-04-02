/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 // IPV6_PKTINFO
#endif

#include <assert.h>
#include <gnutls/x509.h>
#include <sys/types.h>   // OpenBSD
#include <netinet/tcp.h> // TCP_FASTOPEN
#include <sys/resource.h>

#include "libknot/libknot.h"
#include "libknot/yparser/ypschema.h"
#include "libknot/xdp.h"
#include "libknot/quic/tls.h"
#ifdef ENABLE_QUIC
#include "libknot/quic/quic.h" // knot_quic_session_*
#endif // ENABLE_QUIC
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
#include "knot/updates/acl.h"
#include "knot/zone/timers.h"
#include "knot/zone/zonedb-load.h"
#include "knot/worker/pool.h"
#include "contrib/base64.h"
#include "contrib/conn_pool.h"
#include "contrib/files.h"
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

#define SESSION_TICKET_POOL_TIMEOUT (24 * 3600)

#define QUIC_LOG "QUIC/TLS, "

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
		option = IPV6_RECVPKTINFO; /* Multiplatform */
		break;
	default:
		assert(0);
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

static size_t quic_rmt_count(conf_t *conf, const yp_name_t *proto)
{
	size_t count = 0;

	for (conf_iter_t iter = conf_iter(conf, C_RMT);
	     iter.code == KNOT_EOK; conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		conf_val_t rmt_quic = conf_id_get(conf, C_RMT, proto, &id);
		if (conf_bool(&rmt_quic)) {
			count++;
		}
	}

	return count;
}

#ifdef ENABLE_XDP
static iface_t *server_init_xdp_iface(struct sockaddr_storage *addr, bool route_check,
                                      bool udp, bool tcp, uint16_t quic, unsigned *thread_id_start,
                                      const knot_xdp_config_t *xdp_config)
{
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
	if (quic > 0) {
		xdp_flags |= KNOT_XDP_FILTER_QUIC;
	}
	if (route_check) {
		xdp_flags |= KNOT_XDP_FILTER_ROUTE;
	}

	for (int i = 0; i < iface.queues; i++) {
		knot_xdp_load_bpf_t mode =
			(i == 0 ? KNOT_XDP_LOAD_BPF_ALWAYS : KNOT_XDP_LOAD_BPF_NEVER);
		ret = knot_xdp_init(new_if->xdp_sockets + i, iface.name, i,
		                    xdp_flags, iface.port, quic, mode, xdp_config);
		if (ret == -EBUSY && i == 0) {
			log_notice("XDP interface %s@%u is busy, retrying initialization",
			           iface.name, iface.port);
			ret = knot_xdp_init(new_if->xdp_sockets + i, iface.name, i,
			                    xdp_flags, iface.port, quic,
			                    KNOT_XDP_LOAD_BPF_ALWAYS_UNLOAD, xdp_config);
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
		char msg[128];
		(void)snprintf(msg, sizeof(msg), "initialized XDP interface %s", iface.name);
		if (udp || tcp) {
			char buf[32] = "";
			(void)snprintf(buf, sizeof(buf), ", %s%s%s port %u",
			               (udp ? "UDP" : ""),
			               (udp && tcp ? "/" : ""),
			               (tcp ? "TCP" : ""),
			               iface.port);
			strlcat(msg, buf, sizeof(msg));
		}
		if (quic) {
			char buf[32] = "";
			(void)snprintf(buf, sizeof(buf), ", QUIC port %u", quic);
			strlcat(msg, buf, sizeof(msg));
		}

		knot_xdp_mode_t mode = knot_eth_xdp_mode(if_nametoindex(iface.name));
		log_info("%s, queues %d, %s mode%s", msg, iface.queues,
		         (mode == KNOT_XDP_MODE_FULL ? "native" : "emulated"),
		         route_check ? ", route check" : "");
	}

	return new_if;
}
#endif

/*!
 * \brief Create and initialize new interface.
 *
 * Both TCP and UDP sockets will be created for the interface.
 *
 * \param addr              Socket address.
 * \param quic              QUIC interface indication.
 * \param udp_thread_count  Number of created UDP workers.
 * \param tcp_thread_count  Number of created TCP workers.
 * \param tcp_reuseport     Indication if reuseport on TCP is enabled.
 * \param socket_affinity   Indication if CBPF should be attached.
 *
 * \retval Pointer to a new initialized interface.
 * \retval NULL if error.
 */
static iface_t *server_init_iface(struct sockaddr_storage *addr, bool tls,
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
	int tcp_socket_count = tcp_thread_count > 0 ? 1 : 0;
	int tcp_bind_flags = 0;

#ifdef ENABLE_REUSEPORT
	if (addr->ss_family != AF_UNIX) {
		udp_socket_count = udp_thread_count;
		udp_bind_flags |= NET_BIND_MULTIPLE;

		if (tcp_reuseport) {
			tcp_socket_count = tcp_thread_count;
			tcp_bind_flags |= NET_BIND_MULTIPLE;
		}
	}
#endif

	new_if->fd_udp = calloc(udp_socket_count, sizeof(int));
	new_if->fd_tcp = calloc(tcp_socket_count, sizeof(int));
	if (new_if->fd_udp == NULL || new_if->fd_tcp == NULL) {
		log_error("failed to initialize interface");
		server_deinit_iface(new_if, true);
		return NULL;
	}

	const mode_t unix_mode = S_IWUSR | S_IWGRP | S_IWOTH;

	bool warn_bind = true;
	bool warn_cbpf = true;
	bool warn_bufsize = true;
	bool warn_pktinfo = true;
	bool warn_ecn = true;
	bool warn_flag_misc = true;

	/* Create bound UDP sockets. */
	for (int i = 0; i < udp_socket_count; i++) {
		int sock = net_bound_socket(SOCK_DGRAM, addr, udp_bind_flags, unix_mode);
		if (sock == KNOT_EADDRNOTAVAIL) {
			udp_bind_flags |= NET_BIND_NONLOCAL;
			sock = net_bound_socket(SOCK_DGRAM, addr, udp_bind_flags, unix_mode);
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
			assert(addr->ss_family != AF_UNIX);
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

		if (sockaddr_is_any(addr)) {
			new_if->anyaddr = true;
			if (!enable_pktinfo(sock, addr->ss_family) && warn_pktinfo) {
				log_warning("failed to enable PKTINFO for ANY address interface");
				warn_pktinfo = false;
			}
		}

		int ret = disable_pmtudisc(sock, addr->ss_family);
		if (ret != KNOT_EOK && warn_flag_misc) {
			log_warning("failed to disable Path MTU discovery for IPv4/UDP (%s)",
			            knot_strerror(ret));
			warn_flag_misc = false;
		}

		if (tls) {
			ret = net_cmsg_ecn_enable(sock, addr->ss_family);
			if (ret != KNOT_EOK && ret != KNOT_ENOTSUP && warn_ecn) {
				log_warning("failed to enable ECN for QUIC");
				warn_ecn = false;
			}
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
		int sock = net_bound_socket(SOCK_STREAM, addr, tcp_bind_flags, unix_mode);
		if (sock == KNOT_EADDRNOTAVAIL) {
			tcp_bind_flags |= NET_BIND_NONLOCAL;
			sock = net_bound_socket(SOCK_STREAM, addr, tcp_bind_flags, unix_mode);
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
			assert(addr->ss_family != AF_UNIX);
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

static int check_file(char *path, char *role)
{
	if (path == NULL) {
		return KNOT_EOK;
	}

	char *err_str;

	struct stat st;
	int ret = stat(path, &st);
	if (ret != 0) {
		err_str = "invalid file";
	} else if (!S_ISREG(st.st_mode)) {
		err_str = "not a file";
	} else if ((st.st_mode & S_IRUSR) == 0) {
		err_str = "not readable";
	} else {
		return KNOT_EOK;
	}

	log_error(QUIC_LOG "%s file '%s' (%s)", role, path, err_str);
	return KNOT_EINVAL;
}

static int init_creds(conf_t *conf, server_t *server)
{
	char *cert_file = conf_tls(conf, C_CERT_FILE);
	char *key_file = conf_tls(conf, C_KEY_FILE);

	int ret = check_file(cert_file, "certificate");
	if (ret != KNOT_EOK) {
		goto failed;
	}

	ret = check_file(key_file, "key");
	if (ret != KNOT_EOK) {
		goto failed;
	}

	if (cert_file == NULL) {
		assert(key_file == NULL);
		char *kasp_dir = conf_db(conf, C_KASP_DB);
		ret = make_dir(kasp_dir, S_IRWXU | S_IRWXG, true);
		if (ret != KNOT_EOK) {
			log_error(QUIC_LOG "failed to create directory '%s'", kasp_dir);
			free(kasp_dir);
			goto failed;
		}
		key_file = abs_path(DFLT_QUIC_KEY_FILE, kasp_dir);
		free(kasp_dir);
		log_debug(QUIC_LOG "using self-generated key '%s' with "
		          "one-time certificate", key_file);
	}

	uint8_t prev_pin[128];
	size_t prev_pin_len = server_cert_pin(server, prev_pin, sizeof(prev_pin));

	int uid, gid;
	if (conf_user(conf, &uid, &gid) != KNOT_EOK) {
		log_error(QUIC_LOG "failed to get UID or GID");
		ret = KNOT_ERROR;
		goto failed;
	}

	if (server->quic_creds == NULL) {
		server->quic_creds = knot_creds_init(key_file, cert_file, uid, gid);
		if (server->quic_creds == NULL) {
			log_error(QUIC_LOG "failed to initialize server credentials");
			ret = KNOT_ERROR;
			goto failed;
		}
	} else {
		ret = knot_creds_update(server->quic_creds, key_file, cert_file, uid, gid);
		if (ret != KNOT_EOK) {
			goto failed;
		}
	}

	uint8_t pin[128];
	size_t pin_len = server_cert_pin(server, pin, sizeof(pin));
	if (pin_len > 0 && (pin_len != prev_pin_len || memcmp(pin, prev_pin, pin_len) != 0)) {
		log_info(QUIC_LOG "certificate public key %.*s", (int)pin_len, pin);
	}

	ret = KNOT_EOK;
failed:
	free(key_file);
	free(cert_file);

	return ret;
}

/*! \brief Initialize bound sockets according to configuration. */
static int configure_sockets(conf_t *conf, server_t *s)
{
	if (s->state & ServerRunning) {
		return KNOT_EOK;
	}

	conf_val_t listen_val = conf_get(conf, C_SRV, C_LISTEN);
	conf_val_t liquic_val = conf_get(conf, C_SRV, C_LISTEN_QUIC);
	conf_val_t listls_val = conf_get(conf, C_SRV, C_LISTEN_TLS);
	conf_val_t lisxdp_val = conf_get(conf, C_XDP, C_LISTEN);
	conf_val_t rundir_val = conf_get(conf, C_SRV, C_RUNDIR);
	uint16_t convent_quic = conf_val_count(&liquic_val);
	uint16_t convent_tls = conf_val_count(&listls_val);

	if (listen_val.code == KNOT_EOK || liquic_val.code == KNOT_EOK || listls_val.code == KNOT_EOK) {
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
	size_t nifs = conf_val_count(&listen_val) + conf_val_count(&liquic_val) +
	              conf_val_count(&listls_val) + conf_val_count(&lisxdp_val);
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

		iface_t *new_if = server_init_iface(&addr, false, size_udp, size_tcp,
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
	while (liquic_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&liquic_val, rundir);
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
		log_info("binding to QUIC interface %s", addr_str);

		iface_t *new_if = server_init_iface(&addr, true, size_udp, 0,
		                                    false, socket_affinity);
		if (new_if == NULL) {
			server_deinit_iface_list(newlist, nifs);
			free(rundir);
			return KNOT_ERROR;
		}
		new_if->tls = true;
		memcpy(&newlist[real_nifs++], new_if, sizeof(*newlist));
		free(new_if);

		conf_val_next(&liquic_val);
	}
	while (listls_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&listls_val, rundir);
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
		log_info("binding to TLS interface %s", addr_str);

		iface_t *new_if = server_init_iface(&addr, true, 0, size_tcp,
		                                    tcp_reuseport, socket_affinity);
		if (new_if == NULL) {
			server_deinit_iface_list(newlist, nifs);
			free(rundir);
			return KNOT_ERROR;
		}
		new_if->tls = true;
		memcpy(&newlist[real_nifs++], new_if, sizeof(*newlist));
		free(new_if);

		conf_val_next(&listls_val);
	}
	free(rundir);

	/* XDP sockets. */
#ifdef ENABLE_XDP
	knot_xdp_config_t xdp_config = {
		.ring_size = conf->cache.xdp_ring_size,
		.busy_poll_budget = conf->cache.xdp_busypoll_budget,
		.busy_poll_timeout = conf->cache.xdp_busypoll_timeout,
	};
	unsigned thread_id = s->handlers[IO_UDP].handler.unit->size +
	                     s->handlers[IO_TCP].handler.unit->size;
	while (lisxdp_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&lisxdp_val, NULL);
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), &addr);
		log_info("binding to XDP interface %s", addr_str);

		iface_t *new_if = server_init_xdp_iface(&addr, conf->cache.xdp_route_check,
		                                        conf->cache.xdp_udp, conf->cache.xdp_tcp,
		                                        conf->cache.xdp_quic, &thread_id,
		                                        &xdp_config);
		if (new_if == NULL) {
			server_deinit_iface_list(newlist, nifs);
			return KNOT_ERROR;
		}
		memcpy(&newlist[real_nifs++], new_if, sizeof(*newlist));
		free(new_if);

		conf_val_next(&lisxdp_val);
	}
#endif

	assert(real_nifs <= nifs);
	nifs = real_nifs;

	/* QUIC credentials initialization. */
	s->quic_active = conf->cache.xdp_quic > 0 || convent_quic > 0 || quic_rmt_count(conf, C_QUIC) > 0;
	s->tls_active = convent_tls > 0 || quic_rmt_count(conf, C_TLS) > 0;
	if (s->quic_active || s->tls_active) {
		if (init_creds(conf, s) != KNOT_EOK) {
			server_deinit_iface_list(newlist, nifs);
			return KNOT_ERROR;
		}
	}

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


#include "knot/common/hiredis.h"
#include "redis/knot.h"

#ifdef ENABLE_REDIS

#define RDB_TIMESTAMP_SIZE 42

static void rdb_process_event(char *since, redisReply *reply, knot_zonedb_t *zone_db)
{
	redisReply *ev_timestamp = reply->element[0];
	redisReply *ev_data = reply->element[1];
	if (ev_data->type != REDIS_REPLY_ARRAY) {
		log_error("Redis: unexpected response");
		return;
	}

	if (ev_timestamp->len > RDB_TIMESTAMP_SIZE) {
		log_error("Redis: wrong timestamp");
		return;
	}
	strncpy(since, ev_timestamp->str, RDB_TIMESTAMP_SIZE);
	int ev_type = atoi(ev_data->element[1]->str);
	knot_dname_t *dname = (knot_dname_t *)ev_data->element[3]->str;
	switch (ev_type) {
	case ZONE_UPDATED:
		uint32_t serial = atoi(ev_data->element[5]->str);
		zone_t *zone = knot_zonedb_find(zone_db, dname);
		if (zone == NULL) {
			break;
		}
		if (serial > zone_contents_serial(zone->contents)) {
			zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
		}
		break;
	default:
		break;
	}
}

static void rdb_process_events(char *since, redisReply *reply, knot_zonedb_t *zone_db)
{
	if(reply->type != REDIS_REPLY_ARRAY) {
		log_error("Redis: unexpected response");
		return;
	}

	for (int idx = 0; idx < reply->elements; ++idx) {
		if (reply->element[idx]->type != REDIS_REPLY_ARRAY ||
		    reply->element[idx]->elements != 2) {
			log_error("Redis: unexpected response");
			continue;
		}
		redisReply *events = reply->element[idx]->element[1];
		for (int event_idx = 0; event_idx < events->elements; ++event_idx) {
			rdb_process_event(since, events->element[event_idx], zone_db);
		}
	}
}
#endif

static int rdb_listener_run(struct dthread *thread)
{
#ifdef ENABLE_REDIS
	server_t *s = thread->data;
	knot_zonedb_t *zone_db = s->zone_db;
	if (zone_db == NULL) {
		return -1;
	}
	redisContext *ctx = rdb_connect(conf());
	if (ctx == NULL) {
		return KNOT_ECONN;
	}

	static const uint8_t STREAM_KEY = '\x00';
	char since[RDB_TIMESTAMP_SIZE] = "$"; // NOTE size computed as 2 times unsigned 64bit number as string (2x20) plus zero byte and dash between

	// TODO Need blocking time (eg. 1s), otherwice TLS connection timeout
	// NOTE: BLOCK 0 means block indefinetly, use time in ms (milliseconds)
	while(thread->state == ThreadActive) {
		redisReply *reply = redisCommand(ctx,"XREAD BLOCK %d STREAMS %b %s", 1000, &STREAM_KEY, sizeof(STREAM_KEY), since);
		if (reply == NULL) {
			log_error("Redis: connection lost");
			return -1;
		}
		if(reply->type == REDIS_REPLY_NIL) {
			continue;
		}

		rdb_process_events(since, reply, zone_db);

		freeReplyObject(reply);
	}

	return KNOT_EOK;
#endif
	return KNOT_ENOTSUP;
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

	server->rdb_events = dt_create(1, rdb_listener_run, NULL, server);
	if (server->rdb_events == NULL) {
		worker_pool_destroy(server->workers);
		evsched_deinit(&server->sched);
		return KNOT_ENOMEM;
	}

	int ret = catalog_update_init(&server->catalog_upd);
	if (ret != KNOT_EOK) {
		dt_stop(server->rdb_events);
		dt_delete(&server->rdb_events);
		worker_pool_destroy(server->workers);
		evsched_deinit(&server->sched);
		return ret;
	}
	ATOMIC_INIT(server->catalog_upd_signal, false);

	pthread_rwlock_init(&server->ctl_lock, NULL);

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

	/* Deinit locks. */
	pthread_rwlock_destroy(&server->ctl_lock);

	/* Free catalog zone context. */
	catalog_update_clear(&server->catalog_upd);
	catalog_update_deinit(&server->catalog_upd);
	catalog_deinit(&server->catalog);
	ATOMIC_DEINIT(server->catalog_upd_signal);

	/* Close persistent timers DB. */
	knot_lmdb_deinit(&server->timerdb);

	/* Close kasp_db. */
	knot_lmdb_deinit(&server->kaspdb);

	/* Close journal database if open. */
	knot_lmdb_deinit(&server->journaldb);

	/* Close and deinit connection pool. */
	conn_pool_deinit(global_conn_pool);
	global_conn_pool = NULL;
	conn_pool_deinit(global_sessticket_pool);
	global_sessticket_pool = NULL;
	knot_unreachables_deinit(&global_unreachables);

	knot_creds_free(server->quic_creds);
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

	/* Start RDB event listening */
	dt_start(server->rdb_events);

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
		ret = conf_import(new_conf, filename, IMPORT_FILE);
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
			ret = conf_mod_load_extra(new_conf, conf_str(&id), conf_str(&file),
			                          MOD_EXPLICIT);
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

/*! \brief Check if parameter listen(-xdp,-quic) has been changed since knotd started. */
static bool listen_changed(conf_t *conf, server_t *server)
{
	assert(server->ifaces);

	conf_val_t listen_val = conf_get(conf, C_SRV, C_LISTEN);
	conf_val_t liquic_val = conf_get(conf, C_SRV, C_LISTEN_QUIC);
	conf_val_t listls_val = conf_get(conf, C_SRV, C_LISTEN_TLS);
	conf_val_t lisxdp_val = conf_get(conf, C_XDP, C_LISTEN);
	size_t new_count = conf_val_count(&listen_val) + conf_val_count(&liquic_val) +
	                   conf_val_count(&listls_val) + conf_val_count(&lisxdp_val);
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
			iface_t *iface = &server->ifaces[i];
			if (sockaddr_cmp(&addr, &iface->addr, false) == 0 &&
			    !iface->tls && iface->fd_xdp_count == 0) {
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
	while (liquic_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&liquic_val, rundir);
		bool found = false;
		for (size_t i = 0; i < server->n_ifaces; i++) {
			iface_t *iface = &server->ifaces[i];
			if (sockaddr_cmp(&addr, &iface->addr, false) == 0 &&
			    iface->tls && iface->fd_udp_count > 0) {
				matches++;
				found = true;
				break;
			}
		}
		if (!found) {
			break;
		}
		conf_val_next(&liquic_val);
	}
	while (listls_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&listls_val, rundir);
		bool found = false;
		for (size_t i = 0; i < server->n_ifaces; i++) {
			iface_t *iface = &server->ifaces[i];
			if (sockaddr_cmp(&addr, &iface->addr, false) == 0 &&
			    iface->tls && iface->fd_tcp_count > 0) {
				matches++;
				found = true;
				break;
			}
		}
		if (!found) {
			break;
		}
		conf_val_next(&listls_val);
	}
	free(rundir);

	while (lisxdp_val.code == KNOT_EOK) {
		struct sockaddr_storage addr = conf_addr(&lisxdp_val, NULL);
		bool found = false;
		for (size_t i = 0; i < server->n_ifaces; i++) {
			iface_t *iface = &server->ifaces[i];
			if (sockaddr_cmp(&addr, &iface->addr, false) == 0 &&
			    iface->fd_xdp_count > 0) {
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
	static bool warn_xdp_quic = true;
	static bool warn_route_check = true;
	static bool warn_ring_size = true;
	static bool warn_busypoll_budget = true;
	static bool warn_busypoll_timeout = true;
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
		log_warning(msg, "listen(-xdp,-quic,-tls)");
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

	if (warn_xdp_quic && (bool)conf->cache.xdp_quic != conf_get_bool(conf, C_XDP, C_QUIC)) {
		log_warning(msg, &C_QUIC[1]);
		warn_xdp_quic = false;
	}

	if (warn_xdp_quic && conf->cache.xdp_quic > 0 &&
	    conf->cache.xdp_quic != conf_get_int(conf, C_XDP, C_QUIC_PORT)) {
		log_warning(msg, &C_QUIC_PORT[1]);
		warn_xdp_quic = false;
	}

	if (warn_route_check && conf->cache.xdp_route_check != conf_get_bool(conf, C_XDP, C_ROUTE_CHECK)) {
		log_warning(msg, &C_ROUTE_CHECK[1]);
		warn_route_check = false;
	}

	if (warn_ring_size && conf->cache.xdp_ring_size != conf_get_int(conf, C_XDP, C_RING_SIZE)) {
		log_warning(msg, &C_RING_SIZE[1]);
		warn_ring_size = false;
	}

	if (warn_busypoll_budget && conf->cache.xdp_busypoll_budget != conf_get_int(conf, C_XDP, C_BUSYPOLL_BUDGET)) {
		log_warning(msg, &C_BUSYPOLL_BUDGET[1]);
		warn_busypoll_budget = false;
	}

	if (warn_busypoll_timeout && conf->cache.xdp_busypoll_timeout != conf_get_int(conf, C_XDP, C_BUSYPOLL_TIMEOUT)) {
		log_warning(msg, &C_BUSYPOLL_TIMEOUT[1]);
		warn_busypoll_timeout = false;
	}

	if (warn_rmt_pool_limit && global_conn_pool != NULL &&
	    global_conn_pool->capacity != conf_get_int(conf, C_SRV, C_RMT_POOL_LIMIT)) {
		log_warning(msg, &C_RMT_POOL_LIMIT[1]);
		warn_rmt_pool_limit = false;
	}
}

int server_reload(server_t *server, reload_t mode)
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

		ret = conf_activate_modules(new_conf, server, NULL, new_conf->query_modules,
		                            &new_conf->query_plan);
		if (ret != KNOT_EOK) {
			conf_free(new_conf);
			systemd_ready_notify();
			return ret;
		}

		ATOMIC_SET(server->stats.tcp_io_timeout, 0);
		ATOMIC_SET(server->stats.tcp_idle_timeout, 0);
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
		server_update_zones(conf(), server, mode);
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

static void free_sess_ticket(intptr_t ptr)
{
	if (ptr != CONN_POOL_FD_INVALID) {
		knot_tls_session_load(NULL, (void *)ptr);
	}
}

static int reconfigure_remote_pool(conf_t *conf, server_t *server)
{
	conf_val_t val = conf_get(conf, C_SRV, C_RMT_POOL_LIMIT);
	size_t limit = conf_int(&val);
	val = conf_get(conf, C_SRV, C_RMT_POOL_TIMEOUT);
	knot_timediff_t timeout = conf_int(&val);
	if (global_conn_pool == NULL && limit > 0) {
		conn_pool_t *new_pool = conn_pool_init(limit, timeout,
		                                       conn_pool_close_cb_dflt,
		                                       conn_pool_invalid_cb_dflt);
		if (new_pool == NULL) {
			return KNOT_ENOMEM;
		}
		global_conn_pool = new_pool;
	} else {
		(void)conn_pool_timeout(global_conn_pool, timeout);
	}

	if (global_sessticket_pool == NULL && (server->quic_active || server->tls_active)) {
		size_t rmt_count = quic_rmt_count(conf, C_QUIC) + quic_rmt_count(conf, C_TLS);
		if (rmt_count > 0) {
			size_t max_tickets = conf_bg_threads(conf) * rmt_count * 2; // Two addresses per remote.
			conn_pool_t *new_pool =
				conn_pool_init(max_tickets, SESSION_TICKET_POOL_TIMEOUT,
				               free_sess_ticket, conn_pool_invalid_cb_allvalid);
			if (new_pool == NULL) {
				return KNOT_ENOMEM;
			}
			global_sessticket_pool = new_pool;
		}
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
	} else {
		/* Reconfigure QUIC/TLS credentials. */
		if ((server->quic_active || server->tls_active) &&
		    (ret = init_creds(conf, server)) != KNOT_EOK) {
			log_error("failed to reconfigure server credentials (%s)",
			          knot_strerror(ret));
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
	if ((ret = reconfigure_remote_pool(conf, server)) != KNOT_EOK) {
		log_error("failed to reconfigure remote pool (%s)",
		          knot_strerror(ret));
	}

	return KNOT_EOK;
}

void server_update_zones(conf_t *conf, server_t *server, reload_t mode)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	/* Prevent emitting of new zone events. */
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_freeze);
	}

	/* Suspend adding events to worker pool queue, wait for queued events. */
	log_debug("suspending zone events");
	evsched_pause(&server->sched);
	worker_pool_wait(server->workers);
	log_debug("suspended zone events");

	/* Reload zone database and free old zones. */
	zonedb_reload(conf, server, mode);

	/* Trim extra heap. */
	mem_trim();

	/* Resume processing events on new zones. */
	evsched_resume(&server->sched);
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_start);
	}
	log_debug("resumed zone events");
}

size_t server_cert_pin(server_t *server, uint8_t *out, size_t out_size)
{
	int pin_size = 0;

	uint8_t bin_pin[KNOT_TLS_PIN_LEN];
	size_t bin_pin_size = sizeof(bin_pin);
	gnutls_x509_crt_t cert = NULL;
	if (server->quic_creds != NULL &&
	    knot_creds_cert(server->quic_creds, &cert) == KNOT_EOK &&
	    gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256,
	                               bin_pin, &bin_pin_size) == GNUTLS_E_SUCCESS) {
		pin_size = knot_base64_encode(bin_pin, bin_pin_size, out, out_size);
	}
	gnutls_x509_crt_deinit(cert);

	return (pin_size >= 0) ? pin_size : 0;
}
