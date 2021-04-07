/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/server/server.h"
#include "knot/server/network-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	network_context_t network_ctx;   /*!< Network context to handle query. */
	network_request_t *req;          /*!< Request currently in progress. */
	unsigned client_threshold;       /*!< Index of first TCP client. */
	struct timespec last_poll_time;  /*!< Time of the last socket poll. */
	bool is_throttled;               /*!< TCP connections throttling switch. */
	fdset_t set;                     /*!< Set of server/client sockets. */
	unsigned max_worker_fds;         /*!< Max TCP clients per worker configuration + no. of ifaces. */
	int idle_timeout;                /*!< [s] TCP idle timeout configuration. */
	int io_timeout;                  /*!< [ms] TCP send/recv timeout configuration. */
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
	tcp->max_worker_fds = tcp->client_threshold + \
		MAX(conf()->cache.srv_tcp_max_clients / conf()->cache.srv_tcp_threads, 1);
	tcp->idle_timeout = conf()->cache.srv_tcp_idle_timeout;
	tcp->io_timeout = conf()->cache.srv_tcp_io_timeout;
	rcu_read_unlock();
}

/*! \brief Sweep TCP connection. */
static enum fdset_sweep_state tcp_sweep(fdset_t *set, int i, void *data)
{
	UNUSED(data);
	assert(set && i < set->n && i >= 0);
	int fd = set->pfd[i].fd;

	/* Best-effort, name and shame. */
	struct sockaddr_storage ss;
	socklen_t len = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr*)&ss, &len) == 0) {
		char addr_str[SOCKADDR_STRLEN] = {0};
		sockaddr_tostr(addr_str, sizeof(addr_str), &ss);
		log_notice("TCP, terminated inactive client, address %s", addr_str);
	}

	close(fd);

	return FDSET_SWEEP;
}

static void tcp_log_error(struct sockaddr_storage *ss, const char *operation, int ret)
{
	/* Don't log ECONN as it usually means client closed the connection. */
	if (ret == KNOT_ETIMEOUT) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), ss);
		log_debug("TCP, %s, address %s (%s)", operation, addr_str,
		          knot_strerror(ret));
	}
}

static unsigned tcp_set_ifaces(const iface_t *ifaces, size_t n_ifaces,
                               fdset_t *fds, int thread_id)
{
	if (n_ifaces == 0) {
		return 0;
	}

	fdset_clear(fds);
	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
		if (i->fd_tcp_count == 0) { // Ignore XDP interface.
			assert(i->fd_xdp_count > 0);
			continue;
		}

		int tcp_id = 0;
#ifdef ENABLE_REUSEPORT
		if (conf()->cache.srv_tcp_reuseport) {
			/* Note: thread_ids start with UDP threads, TCP threads follow. */
			assert((i->fd_udp_count <= thread_id) &&
			       (thread_id < i->fd_tcp_count + i->fd_udp_count));

			tcp_id = thread_id - i->fd_udp_count;
		}
#endif
		fdset_add(fds, i->fd_tcp[tcp_id], POLLIN, NULL);
	}

	return fds->n;
}

static void tcp_event_accept(tcp_context_t *tcp, unsigned i)
{
	/* Accept client. */
	int fd = tcp->set.pfd[i].fd;
	int client = net_accept(fd, NULL);
	if (client >= 0) {
		/* Assign to fdset. */
		int next_id = fdset_add(&tcp->set, client, POLLIN, NULL);
		if (next_id < 0) {
			close(client);
			return;
		}

		/* Update watchdog timer. */
		fdset_set_watchdog(&tcp->set, next_id, tcp->idle_timeout);
	}
}

static int tcp_event_serve(tcp_context_t *tcp, unsigned i)
{
	struct iovec *in = request_get_iovec(tcp->req, RX);
	struct iovec *out = request_get_iovec(tcp->req, TX);
	in->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	out->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	int fd = tcp->set.pfd[i].fd;
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	network_request_tcp_t *tcp_req = tcp_req_from_req(tcp->req);
	if (getpeername(fd, (struct sockaddr *)&tcp_req->addr, &addrlen) != 0) {
		return KNOT_EADDRNOTAVAIL;
	}

	int recv = net_dns_tcp_recv(fd, in->iov_base, in->iov_len, tcp->io_timeout);
	if (recv > 0) {
		in->iov_len = recv;
	} else {
		tcp_log_error(&tcp_req->addr, "receive", recv);
		return KNOT_EOF;
	}

	tcp->req->fd = fd;
	int ret = network_handle(&tcp->network_ctx, tcp->req, NULL);
	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		fdset_set_watchdog(&tcp->set, i, tcp->idle_timeout);
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (tcp->req->flag & network_request_flag_is_async) {
		/* Save the current request in fd's context and allocate new request for others */
		fdset_set_ctx(&tcp->set, i, tcp->req);
		tcp->req = network_allocate_request(&tcp->network_ctx, NULL, network_request_flag_tcp_buff);
	}
#endif

	return ret;
}

static void tcp_wait_for_events(tcp_context_t *tcp)
{
	fdset_t *set = &tcp->set;

	/* Check if throttled with many open TCP connections. */
	assert(set->n <= tcp->max_worker_fds);
	tcp->is_throttled = set->n == tcp->max_worker_fds;

	/* If throttled, temporarily ignore new TCP connections. */
	unsigned i = tcp->is_throttled ? tcp->client_threshold : 0;

	/* Wait for events. */
	int nfds = poll(&(set->pfd[i]), set->n - i, TCP_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	tcp->last_poll_time = time_now();

	if (tcp->req == NULL) {
		/* Previous req went async and we could not allocate new.
		 * try allocating now, in case any req is freed by others */
		tcp->req = network_allocate_request(&tcp->network_ctx, NULL, network_request_flag_tcp_buff);
	}

	/* Process events. */
	while (nfds > 0 && i < set->n) {
		bool should_close = false;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (set->pfd[i].fd == network_context_get_async_notify_handle(&tcp->network_ctx)) {
			if (set->pfd[i].revents & POLLIN) {
				network_handle_async_completed_queries(&tcp->network_ctx);
				set->pfd[i].revents = 0;
			}
		} else
#endif
		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			should_close = (i >= tcp->client_threshold);
			--nfds;
		} else if (set->pfd[i].revents & (POLLIN)) {
			/* Master sockets - new connection to accept. */
			if (i < tcp->client_threshold) {
				/* Don't accept more clients than configured. */
				if (set->n < tcp->max_worker_fds) {
					tcp_event_accept(tcp, i);
				}
			/* Client sockets - already accepted connection or
			   closed connection :-( */

			} else if (tcp->req  /* if request is not allocated, we can't handle incoming request, so skip and try next time around */
				&& (fdset_get_ctx(set, i) == NULL) /* we are not async processing other request from same client */
				&& tcp_event_serve(tcp, i) != KNOT_EOK) {

				should_close = true;
			}
			--nfds;
		}

		/* Evaluate. */
		if (should_close) {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			network_request_t *pending_req = fdset_get_ctx(set, i);
			if (pending_req) {
				pending_req->flag |= network_request_flag_is_cancelled;
				pending_req->fd = -1;
			}
#endif
			close(set->pfd[i].fd);
			fdset_remove(set, i);
		} else {
			++i;
		}
	}
}

static int tcp_send_response(struct network_context *ctx, network_request_t *req)
{
	struct iovec *out = request_get_iovec(req, TX);
	tcp_context_t *tcp_ctx = container_of(ctx, tcp_context_t, network_ctx);
	int sent = net_dns_tcp_send(req->fd, out->iov_base, req->ans->size,
							tcp_ctx->io_timeout);

	if (sent != req->ans->size) {
		network_request_tcp_t *tcp_req = tcp_req_from_req(req);
		tcp_log_error(&tcp_req->addr, "send", sent);
	} else {
		/* Reset watchdog so connection gets new idle timeout */
		fdset_set_watchdog_on_fd(&tcp_ctx->set, req->fd, tcp_ctx->idle_timeout);
	}
	return sent;
}

static int tcp_async_complete(struct network_context *ctx, network_request_t *req)
{
	int ret = KNOT_EOK;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (! (req->flag & network_request_flag_is_cancelled) ) { /* if a request is cancelled, the fdset context is cleaned up as part of cancellation */
		tcp_context_t *tcp_ctx = container_of(ctx, tcp_context_t, network_ctx);
		fdset_set_ctx_on_fd(&tcp_ctx->set, req->fd, NULL);
	}

	network_free_request(ctx, NULL, req);
#endif

	return ret;
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

	/* Create TCP answering context. */
	tcp_context_t tcp = {
		.is_throttled = false,
	};

	if (network_context_initialize(&tcp.network_ctx, handler->server, thread_id,
									0, response_handler_type_intermediate, tcp_send_response, tcp_async_complete) != KNOT_EOK) {
		goto finish;
	}

	tcp.req = network_allocate_request(&tcp.network_ctx, NULL, network_request_flag_tcp_buff);
	if (tcp.req == NULL) {
		goto finish;
	}

	/* Prepare initial buffer for listening and bound sockets. */
	fdset_init(&tcp.set, FDSET_INIT_SIZE);

	/* Initialize sweep interval and TCP configuration. */
	struct timespec next_sweep;
	update_sweep_timer(&next_sweep);
	update_tcp_conf(&tcp);

	/* Set descriptors for the configured interfaces. */
	tcp.client_threshold = tcp_set_ifaces(handler->server->ifaces,
	                                      handler->server->n_ifaces,
	                                      &tcp.set, thread_id);
	if (tcp.client_threshold == 0) {
		goto finish; /* Terminate on zero interfaces. */
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	fdset_add(&tcp.set, network_context_get_async_notify_handle(&tcp.network_ctx), POLLIN, NULL);
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
			fdset_sweep(&tcp.set, &tcp_sweep, NULL);
			update_sweep_timer(&next_sweep);
			update_tcp_conf(&tcp);
		}
	}

finish:
	if (tcp.req == NULL) {
		network_free_request(&tcp.network_ctx, NULL, tcp.req);
	}

	fdset_clear(&tcp.set);

	return ret;
}
