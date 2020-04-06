/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

static bool tcp_active_state(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static bool tcp_send_state(int state)
{
	return (state != KNOT_STATE_FAIL && state != KNOT_STATE_NOOP);
}

static void tcp_log_error(struct sockaddr_storage *ss, const char *operation, int ret)
{
	/* Don't log ECONN as it usually means client closed the connection. */
	if (ret == KNOT_ETIMEOUT) {
		char addr_str[SOCKADDR_STRLEN] = { 0 };
		sockaddr_tostr(addr_str, sizeof(addr_str), ss);
		log_debug("TCP, %s, address %s (%s)", operation, addr_str, knot_strerror(ret));
	}
}

/*!
 * \brief Make a TCP fdset from current interfaces list.
 *
 * \param  ifaces    Interface list.
 * \param  fds       File descriptor set.
 * \param  thread_id Thread ID used for geting an ID.
 *
 * \return Number of watched descriptors.
 */
static unsigned tcp_set_ifaces(const iface_t *ifaces, size_t n_ifaces, fdset_t *fds, int thread_id)
{
	if (ifaces == NULL) {
		return 0;
	}

	fdset_clear(fds);
	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
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

static int tcp_handle(tcp_context_t *tcp, int fd, struct iovec *rx, struct iovec *tx)
{
	/* Get peer name. */
	struct sockaddr_storage ss;
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr *)&ss, &addrlen) != 0) {
		return KNOT_EADDRNOTAVAIL;
	}

	/* Create query processing parameter. */
	knotd_qdata_params_t params = {
		.remote = &ss,
		.socket = fd,
		.server = tcp->server,
		.thread_id = tcp->thread_id
	};

	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive data. */
	int recv = net_dns_tcp_recv(fd, rx->iov_base, rx->iov_len, tcp->io_timeout);
	if (recv > 0) {
		rx->iov_len = recv;
	} else {
		tcp_log_error(&ss, "receive", recv);
		return KNOT_EOF;
	}

	/* Initialize processing layer. */
	knot_layer_begin(&tcp->layer, &params);

	/* Create packets. */
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, tcp->layer.mm);
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, tcp->layer.mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	knot_layer_consume(&tcp->layer, query);

	int ret = KNOT_EOK;

	/* Resolve until NOOP or finished. */
	while (tcp_active_state(tcp->layer.state)) {
		knot_layer_produce(&tcp->layer, ans);
		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && tcp_send_state(tcp->layer.state)) {
			int sent = net_dns_tcp_send(fd, ans->wire, ans->size, tcp->io_timeout);
			if (sent != ans->size) {
				tcp_log_error(&ss, "send", sent);
				ret = KNOT_EOF;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_layer_finish(&tcp->layer);

	/* Flush per-query memory (including query and answer packets). */
	mp_flush(tcp->layer.mm->ctx);

	return ret;
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
	int fd = tcp->set.pfd[i].fd;
	int ret = tcp_handle(tcp, fd, &tcp->iov[0], &tcp->iov[1]);
	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		fdset_set_watchdog(&tcp->set, i, tcp->idle_timeout);
	}

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

	/* Process events. */
	while (nfds > 0 && i < set->n) {
		bool should_close = false;
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
			} else if (tcp_event_serve(tcp, i) != KNOT_EOK) {
				should_close = true;
			}
			--nfds;
		}

		/* Evaluate. */
		if (should_close) {
			close(set->pfd[i].fd);
			fdset_remove(set, i);
		} else {
			++i;
		}
	}
}

int tcp_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;

	int ret = KNOT_EOK;

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create TCP answering context. */
	tcp_context_t tcp = {
		.server = handler->server,
		.is_throttled = false,
		.thread_id = handler->thread_id[dt_get_id(thread)]
	};
	knot_layer_init(&tcp.layer, &mm, process_query_layer());

	/* Prepare initial buffer for listening and bound sockets. */
	fdset_init(&tcp.set, FDSET_INIT_SIZE);

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tcp.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tcp.iov[i].iov_base = malloc(tcp.iov[i].iov_len);
		if (tcp.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize sweep interval and TCP configuration. */
	struct timespec next_sweep;
	update_sweep_timer(&next_sweep);
	update_tcp_conf(&tcp);

	/* Set descriptors for the configured interfaces. */
	tcp.client_threshold = tcp_set_ifaces(handler->server->ifaces, handler->server->n_ifaces, &tcp.set, tcp.thread_id);
	if (tcp.client_threshold == 0) {
		goto finish; /* Terminate on zero interfaces. */
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
			fdset_sweep(&tcp.set, &tcp_sweep, NULL);
			update_sweep_timer(&next_sweep);
			update_tcp_conf(&tcp);
		}
	}

finish:
	free(tcp.iov[0].iov_base);
	free(tcp.iov[1].iov_base);
	mp_delete(mm.ctx);
	fdset_clear(&tcp.set);

	return ret;
}
