/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#include <unistd.h>
#include <urcu.h>

#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/common/stats.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/dns-handler.h"
#include "knot/server/handler.h"
#include "knot/server/network_req_manager.h"
#include "knot/server/server.h"
#include "knot/server/tcp-handler.h"
#include "libknot/quic/tls.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"

/*! \brief TCP context data. */
typedef struct {
	dns_request_handler_context_t dns_handler; /*!< DNS request handler context. */
	network_dns_request_manager_t *req_mgr;    /*!< DNS request manager. */
	network_dns_request_t *tcp_req;            /*!< DNS request. */
	unsigned client_threshold;       /*!< Index of first TCP client. */
	struct timespec last_poll_time;  /*!< Time of the last socket poll. */
	bool is_throttled;               /*!< TCP connections throttling switch. */
	fdset_t set;                     /*!< Set of server/client sockets. */
	unsigned max_worker_fds;         /*!< Max TCP clients per worker configuration + no. of ifaces. */
	int idle_timeout;                /*!< [s] TCP idle timeout configuration. */
	int io_timeout;                  /*!< [ms] TCP send/recv timeout configuration. */
	struct knot_tls_ctx *tls_ctx;    /*!< DoT answering context. */
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	int async_fd;                    /*!< Async notification file descriptor. */
#endif
} tcp_context_t;

#define TCP_SWEEP_INTERVAL 2 /*!< [secs] granularity of connection sweeping. */

enum {
	CTX_IFACE = 0,
	CTX_TLS   = 1,
	CTX_REQ   = 2,
};

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
	void **tls_conn = fdset_ctx(set, idx, CTX_TLS);
	if (*tls_conn != NULL) {
		knot_tls_conn_del(*tls_conn);
		*tls_conn = NULL;
	}
}

static fdset_sweep_state_t tcp_sweep(fdset_t *set, int idx, _unused_ void *data)
{
	const int fd = fdset_get_fd(set, idx);
	assert(set && fd >= 0 && data != NULL);

	stats_server_increment(stats_server_tcp_idle_timeout);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	network_dns_request_t *req = *fdset_ctx(set, idx, CTX_REQ);
	if (req != NULL) {
		dns_handler_cancel_request(req->dns_req);
	}
#endif
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

	stats_server_increment(stats_server_tcp_io_timeout);

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

static int tcp_handle(tcp_context_t *tcp, _unused_ unsigned idx)
{
	network_dns_request_t *tcp_req = tcp->tcp_req;
	knotd_qdata_params_t *params = &tcp_req->dns_req.req_data.params;

	tcp->req_mgr->restore_network_request_func(tcp->req_mgr, tcp_req);

	/* Receive data. */
	int recv;
	if (params->tls_conn != NULL) {
		int ret = knot_tls_handshake(params->tls_conn, true);
		switch (ret) {
		case KNOT_NET_EAGAIN: // Unfinished handshake, continue later.
			return KNOT_EOK;
		case KNOT_EOK:        // Finished handshake, continue with receiving message.
			recv = knot_tls_recv(params->tls_conn, tcp_req->dns_req.req_data.rx->iov_base,
			                     tcp_req->dns_req.req_data.rx->iov_len);
			break;
		default:              // E.g. handshake timeout.
			assert(ret < 0);
			recv = ret;
			break;
		}
	} else {
		recv = net_dns_tcp_recv(params->socket, tcp_req->dns_req.req_data.rx->iov_base,
		                        tcp_req->dns_req.req_data.rx->iov_len, tcp->io_timeout);
	}
	if (recv > 0) {
		tcp_req->dns_req.req_data.rx->iov_len = recv;
	} else {
		tcp_log_error(params->remote, "receive", recv, params->server);
		return KNOT_EOF;
	}

	int ret = handle_dns_request(&tcp->dns_handler, &tcp_req->dns_req);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (dns_handler_request_is_async(tcp_req->dns_req)) {
		// Save the request on tcp connection context
		*fdset_ctx(&tcp->set, idx, CTX_REQ) = tcp->tcp_req;

		// Release it
		tcp->tcp_req = NULL;
	}
#endif
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (params->tls_conn != NULL) {
		// Store the qdata params AUTH flag to the connection.
		if (params->flags & KNOTD_QUERY_FLAG_AUTHORIZED) {
			params->tls_conn->flags |= KNOT_TLS_CONN_AUTHORIZED;
		} else {
			params->tls_conn->flags &= ~KNOT_TLS_CONN_AUTHORIZED;
		}
	}

	return ret;
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
	if (tcp->tcp_req == NULL) {
		// Previous tcp req is asynced and now we need a new request structure to process the request.
		tcp->tcp_req = tcp->req_mgr->allocate_network_request_func(tcp->req_mgr);

		if (tcp->tcp_req == NULL) {
			stats_server_increment(server_stats_tcp_no_req_obj);
			return KNOT_EOK; // ignore processing now
		}
	}

	network_dns_request_t *tcp_req = tcp->tcp_req;

	int fd = fdset_get_fd(&tcp->set, i);

	/* Get local address. */
	socklen_t sock_len = sizeof(struct sockaddr_storage);
	if (!iface->anyaddr ||
	    getsockname(fd, (struct sockaddr *)&tcp_req->dns_req.req_data.target_addr, &sock_len) != 0) {
		tcp_req->dns_req.req_data.target_addr = iface->addr;
	}

	/* Get remote address. */
	sock_len = sizeof(struct sockaddr_storage);
	if (iface->addr.ss_family == AF_UNIX ||
	    getpeername(fd, (struct sockaddr *)&tcp_req->dns_req.req_data.source_addr, &sock_len) != 0) {
		tcp_req->dns_req.req_data.source_addr = iface->addr;
	}

	initialize_dns_request(&tcp->dns_handler, &tcp_req->dns_req, fd,
	                       iface->tls ? KNOTD_QUERY_PROTO_TLS : KNOTD_QUERY_PROTO_TCP);
	knotd_qdata_params_t *params = &tcp_req->dns_req.req_data.params;

	// NOTE there is no way to avoid calling accept() on unwanted connections:
	// - it's not possible to read out the remote IP beforehand
	// - there is no way to pull it out of the queue
	// So we just accept() those connection (possibly going ahead with the handshake)
	// and close it immediately.
	if (process_query_proto(params, KNOTD_STAGE_PROTO_BEGIN) == KNOTD_PROTO_STATE_BLOCK) {
		return KNOT_EDENIED; // results in closing connection
	}

	/* Establish a TLS session. */
	if (iface->tls) {
		assert(tcp->tls_ctx != NULL);
		knot_tls_conn_t *tls_conn = *fdset_ctx(&tcp->set, i, CTX_TLS);
		if (tls_conn == NULL) {
			tls_conn = knot_tls_conn_new(tcp->tls_ctx, fd);
			if (tls_conn == NULL) {
				return KNOT_ENOMEM;
			}
			*fdset_ctx(&tcp->set, i, CTX_TLS) = tls_conn;
		}
		params_update_tls(params, tls_conn);
	}

	int ret = tcp_handle(tcp, i);
	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		(void)fdset_set_watchdog(&tcp->set, i, tcp->idle_timeout);
	}

	(void)process_query_proto(params, KNOTD_STAGE_PROTO_END);

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
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		} else if (idx == tcp->client_threshold - 1) {
			// Async completion notification
			stats_server_increment(server_stats_tcp_async_done);
			handle_dns_request_async_completed_queries(&tcp->dns_handler);
#endif
		} else if (fdset_it_is_pollin(&it)) {
			const iface_t *iface = fdset_it_get_ctx(&it, CTX_IFACE);
			assert(iface);
			/* Master sockets - new connection to accept. */
			if (idx < tcp->client_threshold) {
				/* Don't accept more clients than configured. */
				if (fdset_get_length(set) < tcp->max_worker_fds) {
					stats_server_increment(server_stats_tcp_accept);
					tcp_event_accept(tcp, idx, iface);
				}
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			} else if (fdset_it_get_ctx(&it, CTX_REQ) != NULL) {
				// Received another request before completing the current one, ignore for now
				// Implement more async handling
				stats_server_increment(server_stats_tcp_multiple_req);
#endif
			} else {
				stats_server_increment(server_stats_tcp_received);
				/* Client sockets - already accepted connection or
				   closed connection :-( */
				if (tcp_event_serve(tcp, idx, iface) != KNOT_EOK) {
					should_close = true;
				}
			}
		}

		/* Evaluate. */
		if (should_close) {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			network_dns_request_t *req = (network_dns_request_t *)fdset_it_get_ctx(&it, CTX_REQ);
			if (req != NULL) {
				dns_handler_cancel_request(req->dns_req);
			}
#endif
			free_tls_ctx(set, idx);
			fdset_it_remove(&it);
		}
	}
	fdset_it_commit(&it);
}

static int tcp_send_produced_result(dns_request_handler_context_t *dns_handler,
                                    dns_handler_request_t *req, size_t size)
{
	tcp_context_t *tcp = caa_container_of(dns_handler, tcp_context_t, dns_handler);
	knot_tls_conn_t *tls_conn = req->req_data.params.tls_conn;

	int sent;
	if (tls_conn != NULL) {
		sent = knot_tls_send(tls_conn, req->req_data.tx->iov_base, size);
	} else {
		sent = net_dns_tcp_send(req->req_data.params.socket, req->req_data.tx->iov_base,
		                        size, tcp->io_timeout);
	}
	if (sent != size) {
		tcp_log_error(&req->req_data.source_addr, "send", sent, tcp->dns_handler.server);
	}

	return sent;
}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
static bool use_numa = false;
static bool tcp_use_async = false;
static atomic_shared_dns_request_manager_t tcp_shared_req_mgr[KNOT_MAX_NUMA];
static size_t tcp_req_pool_size;

int init_tcp_async(size_t pool_size, bool numa_enabled)
{
	for (int i = 0; i < KNOT_MAX_NUMA; i++) {
		init_shared_req_mgr(tcp_shared_req_mgr[i]);
	}
	tcp_req_pool_size = pool_size;
	tcp_use_async = true;
	use_numa = numa_enabled;
	return KNOT_EOK;
}

static void tcp_async_query_completed_callback(dns_request_handler_context_t *net,
                                               dns_handler_request_t *req)
{
	tcp_context_t *tcp = caa_container_of(net, tcp_context_t, dns_handler);
	network_dns_request_t *tcp_req = caa_container_of(req, network_dns_request_t, dns_req);
	knot_tls_conn_t *tls_conn = req->req_data.params.tls_conn;

	if (!dns_handler_request_is_cancelled(tcp_req->dns_req)) {
		bool err = false;
		// Send the response
		if (req->req_data.tx->iov_len > 0) {
			int size = req->req_data.tx->iov_len;
			int sent;
			if (tls_conn != NULL) {
				sent = knot_tls_send(tls_conn, req->req_data.tx->iov_base, size);
			} else {
				sent = net_dns_tcp_send(req->req_data.params.socket, req->req_data.tx->iov_base,
				                        size, tcp->io_timeout);
			}
			if (sent != size) {
				tcp_log_error(&req->req_data.source_addr, "send", sent, tcp->dns_handler.server);
				err = true;
			}
		}

		// Cleanup async req from fd to allow fd receive more request
		int idx = fdset_get_index_for_fd(&tcp->set, req->req_data.params.socket);
		*fdset_ctx(&tcp->set, idx, CTX_REQ) = NULL;

		if (!err) {
			fdset_set_watchdog(&tcp->set, idx, tcp->idle_timeout);
		}
	}

	// Free the request
	tcp->req_mgr->free_network_request_func(tcp->req_mgr, tcp_req);
}
#endif

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

	_unused_ int numa_node = 0;
#ifdef KNOT_ENABLE_NUMA
	if (use_numa) {
		unsigned cpu = dt_online_cpus();
		if (cpu > 1) {
			unsigned cpu_mask = (dt_get_id(thread) % cpu);
			dt_setaffinity(thread, &cpu_mask, 1);
			int cpu_numa_node = numa_node_of_cpu(cpu_mask);
			numa_node =  cpu_numa_node % KNOT_MAX_NUMA;
			log_info("TCP thread %d using numa %d, original %d", thread_id, numa_node, cpu_numa_node);
		}
	}
#endif

	int ret = KNOT_EOK;

	/* Create TCP answering context. */
	tcp_context_t tcp = { 0 };
	tcp.req_mgr =
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		tcp_use_async ?
			network_dns_request_pool_manager_create(&tcp_shared_req_mgr[numa_node],
				KNOT_WIRE_MAX_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE, tcp_req_pool_size) :
#endif
			network_dns_request_manager_basic_create(
				KNOT_WIRE_MAX_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE);
	if (tcp.req_mgr == NULL) {
		ret = KNOT_ENOMEM;
		goto finish;
	}

	tcp.tcp_req = tcp.req_mgr->allocate_network_request_func(tcp.req_mgr);
	if (tcp.tcp_req == NULL) {
		ret = KNOT_ENOMEM;
		goto finish;
	}

	/* Initialize descriptors for the configured interfaces and bound sockets. */
	ret = fdset_init(&tcp.set, FDSET_RESIZE_STEP, 3);
	if (ret != KNOT_EOK) {
		goto finish;
	}

	bool tls = false;
	tcp.client_threshold = tcp_set_ifaces(handler->server->ifaces,
	                                      handler->server->n_ifaces,
	                                      &tcp.set, thread_id, &tls);
	if (tcp.client_threshold == 0) {
		goto finish; /* Terminate on zero interfaces. */
	}

	/* Initialize TLS context. */
	if (tls) {
		// Set the HS timeout to 8x the RMT IO one as the HS duration can be up to 4*roundtrip.
		tcp.tls_ctx = knot_tls_ctx_new(handler->server->quic_creds,
		                               tcp.io_timeout, 8 * tcp.io_timeout,
		                               KNOT_TLS_SERVER | KNOT_TLS_DNS | KNOT_TLS_EARLY_DATA);
		if (tcp.tls_ctx == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize TCP answering context. */
	ret = initialize_dns_handle(&tcp.dns_handler, handler->server,
	                            thread_id, tcp_send_produced_result
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	                           ,tcp_async_query_completed_callback
#endif
	                           );
	if (ret != KNOT_EOK) {
		goto finish;
	}

	/* Initialize sweep interval and TCP configuration. */
	struct timespec next_sweep;
	update_sweep_timer(&next_sweep);
	update_tcp_conf(&tcp);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	tcp.async_fd = dns_request_handler_context_get_async_notify_handle(&tcp.dns_handler);
	if (fdset_add(&tcp.set, tcp.async_fd, FDSET_POLLIN, NULL) < 0) {
		goto finish;
	}

	tcp.client_threshold++;
#endif

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
#ifdef ENABLE_ASYNC_QUERY_HANDLING
#ifndef ENABLE_TESTING
	{
		struct timespec five_sec = { 5, 0 };
		nanosleep(&five_sec, &five_sec);
	}
#endif
#endif

	if (tcp.tcp_req != NULL) {
		tcp.req_mgr->free_network_request_func(tcp.req_mgr, tcp.tcp_req);
	}
	if (tcp.req_mgr != NULL) {
		tcp.req_mgr->delete_req_manager(tcp.req_mgr);
	}
	cleanup_dns_handle(&tcp.dns_handler);

	knot_tls_ctx_free(tcp.tls_ctx);
	for (int i = 0; i < tcp.set.n; i++) {
		free_tls_ctx(&tcp.set, i);
	}
	fdset_clear(&tcp.set);

	return ret;
}
