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
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "dnssec/random.h"
#include "knot/server/tcp-handler.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "libknot/processing/overlay.h"
#include "contrib/macros.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/time.h"
#include "contrib/ucw/mempool.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	struct knot_overlay overlay;/*!< Query processing overlay. */
	server_t *server;           /*!< Name server structure. */
	struct iovec iov[2];        /*!< TX/RX buffers. */
	unsigned client_threshold;  /*!< Index of first TCP client. */
	timev_t last_poll_time;     /*!< Time of the last socket poll. */
	timev_t throttle_end;       /*!< End of accept() throttling. */
	fdset_t set;                /*!< Set of server/client sockets. */
	unsigned thread_id;         /*!< Thread identifier. */
} tcp_context_t;

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 0 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 2 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	return TCP_THROTTLE_LO + (dnssec_random_uint16_t() % TCP_THROTTLE_HI);
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
		log_notice("TCP, terminated inactive client, address '%s'", addr_str);
	}

	close(fd);

	return FDSET_SWEEP;
}

/*!
 * \brief TCP event handler function.
 */
static int tcp_handle(tcp_context_t *tcp, int fd,
                      struct iovec *rx, struct iovec *tx)
{
	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	struct process_query_param param = {0};
	param.socket = fd;
	param.remote = &ss;
	param.server = tcp->server;
	param.thread_id = tcp->thread_id;
	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive peer name. */
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr *)&ss, &addrlen) < 0) {
		;
	}

	/* Timeout. */
	rcu_read_lock();
	conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
	const int timeout = conf_int(val) * 1000;
	rcu_read_unlock();

	/* Receive data. */
	int ret = net_dns_tcp_recv(fd, rx->iov_base, rx->iov_len, timeout);
	if (ret <= 0) {
		if (ret == KNOT_EAGAIN) {
			char addr_str[SOCKADDR_STRLEN] = {0};
			sockaddr_tostr(addr_str, sizeof(addr_str), &ss);
			log_warning("TCP, connection timed out, address '%s'",
			            addr_str);
		}
		return KNOT_ECONNREFUSED;
	} else {
		rx->iov_len = ret;
	}

	knot_mm_t *mm = tcp->overlay.mm;

	/* Initialize processing overlay. */
	ret = knot_overlay_init(&tcp->overlay, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ret = knot_overlay_add(&tcp->overlay, NS_PROC_QUERY, &param);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Create packets. */
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, mm);
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	int state = knot_overlay_consume(&tcp->overlay, query);

	/* Resolve until NOOP or finished. */
	ret = KNOT_EOK;
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_overlay_produce(&tcp->overlay, ans);

		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && !(state & (KNOT_STATE_FAIL|KNOT_STATE_NOOP))) {
			if (net_dns_tcp_send(fd, ans->wire, ans->size, timeout) != ans->size) {
				ret = KNOT_ECONNREFUSED;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_overlay_finish(&tcp->overlay);
	knot_overlay_deinit(&tcp->overlay);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);

	return ret;
}

int tcp_accept(int fd)
{
	/* Accept incoming connection. */
	int incoming = net_accept(fd, NULL);

	/* Evaluate connection. */
	if (incoming >= 0) {
#ifdef SO_RCVTIMEO
		struct timeval tv;
		rcu_read_lock();
		conf_val_t *val = &conf()->cache.srv_tcp_idle_timeout;
		tv.tv_sec = conf_int(val);
		rcu_read_unlock();
		tv.tv_usec = 0;
		if (setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			log_warning("TCP, failed to set up watchdog timer"
			            ", fd %d", incoming);
		}
#endif
	}

	return incoming;
}

static int tcp_event_accept(tcp_context_t *tcp, unsigned i)
{
	/* Accept client. */
	int fd = tcp->set.pfd[i].fd;
	int client = tcp_accept(fd);
	if (client >= 0) {
		/* Assign to fdset. */
		int next_id = fdset_add(&tcp->set, client, POLLIN, NULL);
		if (next_id < 0) {
			close(client);
			return next_id; /* Contains errno. */
		}

		/* Update watchdog timer. */
		rcu_read_lock();
		conf_val_t *val = &conf()->cache.srv_tcp_hshake_timeout;
		fdset_set_watchdog(&tcp->set, next_id, conf_int(val));
		rcu_read_unlock();

		return KNOT_EOK;
	}

	return client;
}

static int tcp_event_serve(tcp_context_t *tcp, unsigned i)
{
	int fd = tcp->set.pfd[i].fd;
	int ret = tcp_handle(tcp, fd, &tcp->iov[0], &tcp->iov[1]);

	/* Flush per-query memory. */
	mp_flush(tcp->overlay.mm->ctx);

	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		rcu_read_lock();
		conf_val_t *val = &conf()->cache.srv_tcp_idle_timeout;
		fdset_set_watchdog(&tcp->set, i, conf_int(val));
		rcu_read_unlock();
	}

	return ret;
}

static int tcp_wait_for_events(tcp_context_t *tcp)
{
	/* Wait for events. */
	fdset_t *set = &tcp->set;
	int nfds = poll(set->pfd, set->n, TCP_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	time_now(&tcp->last_poll_time);
	bool is_throttled = (tcp->last_poll_time.tv_sec < tcp->throttle_end.tv_sec);
	if (!is_throttled) {
		/* Configuration limit, infer maximal pool size. */
		rcu_read_lock();
		conf_val_t *val = &conf()->cache.srv_max_tcp_clients;
		unsigned max_per_set = MAX(conf_int(val) / conf_tcp_threads(conf()), 1);
		rcu_read_unlock();
		/* Subtract master sockets check limits. */
		is_throttled = (set->n - tcp->client_threshold) >= max_per_set;
	}

	/* Process events. */
	unsigned i = 0;
	while (nfds > 0 && i < set->n) {
		bool should_close = false;
		int fd = set->pfd[i].fd;
		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			should_close = (i >= tcp->client_threshold);
			--nfds;
		} else if (set->pfd[i].revents & (POLLIN)) {
			/* Master sockets */
			if (i < tcp->client_threshold) {
				if (!is_throttled && tcp_event_accept(tcp, i) == KNOT_EBUSY) {
					time_now(&tcp->throttle_end);
					tcp->throttle_end.tv_sec += tcp_throttle();
				}
			/* Client sockets */
			} else {
				if (tcp_event_serve(tcp, i) != KNOT_EOK) {
					should_close = true;
				}
			}
			--nfds;
		}

		/* Evaluate */
		if (should_close) {
			fdset_remove(set, i);
			close(fd);
		} else {
			++i;
		}
	}

	return nfds;
}

int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	unsigned *iostate = &handler->thread_state[dt_get_id(thread)];

	int ret = KNOT_EOK;
	ref_t *ref = NULL;
	tcp_context_t tcp;
	memset(&tcp, 0, sizeof(tcp_context_t));

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create TCP answering context. */
	tcp.server = handler->server;
	tcp.thread_id = handler->thread_id[dt_get_id(thread)];
	tcp.overlay.mm = &mm;

	/* Prepare structures for bound sockets. */
	conf_val_t val = conf_get(conf(), C_SRV, C_LISTEN);
	fdset_init(&tcp.set, conf_val_count(&val) + CONF_XFERS);

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tcp.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tcp.iov[i].iov_base = malloc(tcp.iov[i].iov_len);
		if (tcp.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize sweep interval. */
	timev_t next_sweep = {0};
	time_now(&next_sweep);
	next_sweep.tv_sec += TCP_SWEEP_INTERVAL;

	for(;;) {

		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;

			/* Cancel client connections. */
			for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				close(tcp.set.pfd[i].fd);
			}

			ref_release(ref);
			ref = server_set_ifaces(handler->server, &tcp.set, IO_TCP, tcp.thread_id);
			if (tcp.set.n == 0) {
				break; /* Terminate on zero interfaces. */
			}

			tcp.client_threshold = tcp.set.n;
		}

		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Serve client requests. */
		tcp_wait_for_events(&tcp);

		/* Sweep inactive clients. */
		if (tcp.last_poll_time.tv_sec >= next_sweep.tv_sec) {
			fdset_sweep(&tcp.set, &tcp_sweep, NULL);
			time_now(&next_sweep);
			next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
		}
	}

finish:
	free(tcp.iov[0].iov_base);
	free(tcp.iov[1].iov_base);
	mp_delete(mm.ctx);
	fdset_clear(&tcp.set);
	ref_release(ref);

	return ret;
}
