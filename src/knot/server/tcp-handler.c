/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H

#include "knot/server/handler.h"
#include "knot/server/server.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/log.h"
#include "knot/common/fdset.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "libknot/quic/tls.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	knot_layer_t layer;              /*!< Query processing layer. */
	server_t *server;                /*!< Name server structure. */
	struct iovec iov[2];             /*!< TX/RX buffers. */
	unsigned client_threshold;       /*!< Index of first TCP client. */
	struct timespec last_poll_time;  /*!< Time of the last socket poll. */
	bool is_throttled;               /*!< TCP connections throttling switch. */
	fdset_t set;                     /*!< Set of server/client sockets. */
	unsigned thread_id;              /*!< Thread identifier. */
	unsigned max_worker_fds;         /*!< Max TCP clients per worker configuration + no. of ifaces. */
	int idle_timeout;                /*!< [s] TCP idle timeout configuration. */
	int io_timeout;                  /*!< [ms] TCP send/recv timeout configuration. */
	struct knot_tls_ctx *tls_ctx;    /*!< DoT answering context. */
} tcp_context_t;

#define TCP_SWEEP_INTERVAL 2 /*!< [secs] granularity of connection sweeping. */

static void update_sweep_timer(struct timespec *timer)
{
	*timer = time_now();
	timer->tv_sec += TCP_SWEEP_INTERVAL;
}

static void update_tcp_conf(tcp_context_t *tcp)
{
	rcu_read_lock();
	conf_t *pconf = conf();
	tcp->max_worker_fds = tcp->client_threshold + \
		MAX(pconf->cache.srv_tcp_max_clients / pconf->cache.srv_tcp_threads, 1);
	tcp->idle_timeout = pconf->cache.srv_tcp_idle_timeout;
	tcp->io_timeout = pconf->cache.srv_tcp_io_timeout;
	rcu_read_unlock();

	if (tcp->tls_ctx != NULL) {
		tcp->tls_ctx->io_timeout = tcp->io_timeout;
	}
}

static void free_tls_ctx(fdset_t *set, int idx)
{
	void **tls_conn = fdset_ctx2(set, idx);
	if (*tls_conn != NULL) {
		knot_tls_conn_del(*tls_conn);
		*tls_conn = NULL;
	}
}

static fdset_sweep_state_t tcp_sweep(fdset_t *set, int idx, void *data)
{
	const int fd = fdset_get_fd(set, idx);
	assert(set && fd >= 0);

	server_t *server = data;
	ATOMIC_ADD(server->stats.tcp_idle_timeout, 1);

	if (log_enabled_debug()) {
		/* Best-effort, name and shame. */
		struct sockaddr_storage ss = { 0 };
		socklen_t len = sizeof(struct sockaddr_storage);
		if (getpeername(fd, (struct sockaddr *)&ss, &len) == 0) {
			char addr_str[SOCKADDR_STRLEN];
			sockaddr_tostr(addr_str, sizeof(addr_str), &ss);
			log_debug("TCP, terminated inactive client, address %s", addr_str);
		}
	}

	free_tls_ctx(set, idx);

	return FDSET_SWEEP;
}

static void tcp_log_error(const struct sockaddr_storage *ss, const char *operation,
                          int ret, server_t *server)
{
	/* Don't log ECONN as it usually means client closed the connection. */
	if (ret != KNOT_ETIMEOUT) {
		return;
	}

	ATOMIC_ADD(server->stats.tcp_io_timeout, 1);

	if (log_enabled_debug()) {
		char addr_str[SOCKADDR_STRLEN];
		sockaddr_tostr(addr_str, sizeof(addr_str), ss);
		log_debug("TCP, failed to %s due to IO timeout, closing connection, address %s",
		          operation, addr_str);
	}
}

static unsigned tcp_set_ifaces(const iface_t *ifaces, size_t n_ifaces,
                               fdset_t *fds, int thread_id, bool *tls)
{
	if (n_ifaces == 0) {
		return 0;
	}

	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
		if (i->fd_xdp_count > 0 || i->fd_tcp_count == 0) { // Ignore XDP and QUIC interfaces.
			continue;
		}

		int tcp_id = 0;
#ifdef ENABLE_REUSEPORT
		if (conf()->cache.srv_tcp_reuseport && i->addr.ss_family != AF_UNIX) {
			/* Note: thread_ids start with UDP threads, TCP threads follow. */
			assert((i->fd_udp_count <= thread_id) &&
			       (thread_id < i->fd_tcp_count + i->fd_udp_count));

			tcp_id = thread_id - i->fd_udp_count;
		}
#endif
		int ret = fdset_add(fds, i->fd_tcp[tcp_id], FDSET_POLLIN, (void *)i);
		if (ret < 0) {
			return 0;
		}
		if (i->tls) {
			*tls = true;
		}
	}

	return fdset_get_length(fds);
}

static int tcp_handle(tcp_context_t *tcp, knotd_qdata_params_t *params,
                      struct iovec *rx, struct iovec *tx)
{
	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive data. */
	int recv;
	if (params->tls_conn != NULL) {
		int ret = knot_tls_handshake(params->tls_conn, true);
		switch (ret) {
		case KNOT_NET_EAGAIN: // Unfinished handshake, continue later.
			return KNOT_EOK;
		case KNOT_EOK:        // Finished handshake, continue with receiving message.
			recv = knot_tls_recv_dns(params->tls_conn, rx->iov_base, rx->iov_len);
			break;
		default:              // E.g. handshake timeout.
			assert(ret < 0);
			recv = ret;
			break;
		}
	} else {
		recv = net_dns_tcp_recv(params->socket, rx->iov_base, rx->iov_len, tcp->io_timeout);
	}
	if (recv > 0) {
		rx->iov_len = recv;
	} else {
		tcp_log_error(params->remote, "receive", recv, tcp->server);
		return KNOT_EOF;
	}

	handle_query(params, &tcp->layer, rx, NULL);

	/* Resolve until NOOP or finished. */
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, tcp->layer.mm);
	while (active_state(tcp->layer.state)) {
		knot_layer_produce(&tcp->layer, ans);
		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && send_state(tcp->layer.state)) {
			int sent;
			if (params->tls_conn != NULL) {
				sent = knot_tls_send_dns(params->tls_conn, ans->wire, ans->size);
			} else {
				sent = net_dns_tcp_send(params->socket, ans->wire, ans->size,
				                        tcp->io_timeout, NULL);
			}
			if (sent != ans->size) {
				tcp_log_error(params->remote, "send", sent, tcp->server);
				handle_finish(&tcp->layer);
				return KNOT_EOF;
			}
		}
	}

	handle_finish(&tcp->layer);

	if (params->tls_conn != NULL) {
		// Store the qdata params AUTH flag to the connection.
		if (params->flags & KNOTD_QUERY_FLAG_AUTHORIZED) {
			params->tls_conn->flags |= KNOT_TLS_CONN_AUTHORIZED;
		} else {
			params->tls_conn->flags &= ~KNOT_TLS_CONN_AUTHORIZED;
		}
	}

	return KNOT_EOK;
}

static void tcp_event_accept(tcp_context_t *tcp, unsigned i, const iface_t *iface)
{
	/* Accept client. */
	int fd = fdset_get_fd(&tcp->set, i);
	int client = net_accept(fd, NULL);
	if (client >= 0) {
		/* Assign to fdset. */
		int idx = fdset_add(&tcp->set, client, FDSET_POLLIN, (void *)iface);
		if (idx < 0) {
			close(client);
			return;
		}

		/* Update watchdog timer. */
		(void)fdset_set_watchdog(&tcp->set, idx, tcp->idle_timeout);
	}
}

static int tcp_event_serve(tcp_context_t *tcp, unsigned i, const iface_t *iface)
{
	int fd = fdset_get_fd(&tcp->set, i);

	/* Get local address. */
	sockaddr_t *local = (sockaddr_t *)&iface->addr;
	sockaddr_t local_buf;
	if (iface->anyaddr) {
		socklen_t local_len = sizeof(local_buf);
		if (getsockname(fd, &local_buf.ip, &local_len) == 0) {
			local = &local_buf;
		}
	}

	/* Get remote address. */
	sockaddr_t *remote = (sockaddr_t *)&iface->addr;
	sockaddr_t remote_buf;
	if (iface->addr.ss_family != AF_UNIX) {
		socklen_t remote_len = sizeof(remote_buf);
		if (getpeername(fd, &remote_buf.ip, &remote_len) == 0) {
			remote = &remote_buf;
		}
	}

	knotd_qdata_params_t params = params_init(iface->tls ? KNOTD_QUERY_PROTO_TLS
	                                                     : KNOTD_QUERY_PROTO_TCP,
	                                          remote, local, fd, tcp->server,
	                                          tcp->thread_id);

	// NOTE there is no way to avoid calling accept() on unwanted connections:
	// - it's not possible to read out the remote IP beforehand
	// - there is no way to pull it out of the queue
	// So we just accept() those connection (possibly going ahead with the handshake)
	// and close it immediately.
	if (process_query_proto(&params, KNOTD_STAGE_PROTO_BEGIN) == KNOTD_PROTO_STATE_BLOCK) {
		return KNOT_EDENIED; // results in closing connection
	}

	/* Establish a TLS session. */
	if (iface->tls) {
		assert(tcp->tls_ctx != NULL);
		knot_tls_conn_t *tls_conn = *fdset_ctx2(&tcp->set, i);
		if (tls_conn == NULL) {
			tls_conn = knot_tls_conn_new(tcp->tls_ctx, fd);
			if (tls_conn == NULL) {
				return KNOT_ENOMEM;
			}
			*fdset_ctx2(&tcp->set, i) = tls_conn;
		}
		params_update_tls(&params, tls_conn);
	}

	int ret = tcp_handle(tcp, &params, &tcp->iov[0], &tcp->iov[1]);
	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		(void)fdset_set_watchdog(&tcp->set, i, tcp->idle_timeout);
	}

	(void)process_query_proto(&params, KNOTD_STAGE_PROTO_END);

	return ret;
}

static void tcp_wait_for_events(tcp_context_t *tcp)
{
	fdset_t *set = &tcp->set;

	/* Check if throttled with many open TCP connections. */
	assert(fdset_get_length(set) <= tcp->max_worker_fds);
	tcp->is_throttled = fdset_get_length(set) == tcp->max_worker_fds;

	/* If throttled, temporarily ignore new TCP connections. */
	unsigned offset = tcp->is_throttled ? tcp->client_threshold : 0;

	/* Wait for events. */
	fdset_it_t it;
	(void)fdset_poll(set, &it, offset, TCP_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	tcp->last_poll_time = time_now();

	/* Process events. */
	for (; !fdset_it_is_done(&it); fdset_it_next(&it)) {
		bool should_close = false;
		unsigned int idx = fdset_it_get_idx(&it);
		if (fdset_it_is_error(&it)) {
			should_close = (idx >= tcp->client_threshold);
		} else if (fdset_it_is_pollin(&it)) {
			const iface_t *iface = fdset_it_get_ctx(&it);
			assert(iface);
			/* Master sockets - new connection to accept. */
			if (idx < tcp->client_threshold) {
				/* Don't accept more clients than configured. */
				if (fdset_get_length(set) < tcp->max_worker_fds) {
					tcp_event_accept(tcp, idx, iface);
				}
			/* Client sockets - already accepted connection or
			   closed connection :-( */
			} else if (tcp_event_serve(tcp, idx, iface) != KNOT_EOK) {
				should_close = true;
			}
		}

		/* Evaluate. */
		if (should_close) {
			free_tls_ctx(set, idx);
			fdset_it_remove(&it);
		}
	}
	fdset_it_commit(&it);
}

int tcp_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int thread_id = handler->thread_id[dt_get_id(thread)];

#ifdef ENABLE_REUSEPORT
	/* Set thread affinity to CPU core (overlaps with UDP/XDP). */
	if (conf()->cache.srv_tcp_reuseport) {
		unsigned cpu = dt_online_cpus();
		if (cpu > 1) {
			unsigned cpu_mask = (dt_get_id(thread) % cpu);
			dt_setaffinity(thread, &cpu_mask, 1);
		}
	}
#endif

	int ret = KNOT_EOK;

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create TCP answering context. */
	tcp_context_t tcp = {
		.server = handler->server,
		.is_throttled = false,
		.thread_id = thread_id,
	};
	knot_layer_init(&tcp.layer, &mm, process_query_layer());

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tcp.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tcp.iov[i].iov_base = malloc(tcp.iov[i].iov_len);
		if (tcp.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Prepare initial buffer for listening and bound sockets. */
	if (fdset_init(&tcp.set, FDSET_RESIZE_STEP) != KNOT_EOK) {
		ret = KNOT_ENOMEM;
		goto finish;
	}

	/* Set descriptors for the configured interfaces. */
	bool tls = false;
	tcp.client_threshold = tcp_set_ifaces(handler->server->ifaces,
	                                      handler->server->n_ifaces,
	                                      &tcp.set, thread_id, &tls);
	if (tcp.client_threshold == 0) {
		goto finish; /* Terminate on zero interfaces. */
	}

	/* Initialize sweep interval and TCP configuration. */
	struct timespec next_sweep;
	update_sweep_timer(&next_sweep);
	update_tcp_conf(&tcp);

	/* Initialize TLS context. */
	if (tls) {
		// Set the HS timeout to 8x the RMT IO one as the HS duration can be up to 4*roundtrip.
		tcp.tls_ctx = knot_tls_ctx_new(handler->server->quic_creds,
		                               tcp.io_timeout, 8 * tcp.io_timeout, true);
		if (tcp.tls_ctx == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	for (;;) {
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Serve client requests. */
		tcp_wait_for_events(&tcp);

		/* Sweep inactive clients and refresh TCP configuration. */
		if (tcp.last_poll_time.tv_sec >= next_sweep.tv_sec) {
			fdset_sweep(&tcp.set, &tcp_sweep, handler->server);
			update_sweep_timer(&next_sweep);
			update_tcp_conf(&tcp);
		}
	}

finish:
	knot_tls_ctx_free(tcp.tls_ctx);
	free(tcp.iov[0].iov_base);
	free(tcp.iov[1].iov_base);
	mp_delete(mm.ctx);

	for (int i = 0; i < tcp.set.n; i++) {
		free_tls_ctx(&tcp.set, i);
	}
	fdset_clear(&tcp.set);

	return ret;
}
