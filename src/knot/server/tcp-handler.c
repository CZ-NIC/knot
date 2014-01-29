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
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common/sockaddr.h"
#include "common/fdset.h"
#include "common/mempool.h"
#include "knot/knot.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zones.h"
#include "knot/nameserver/name-server.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_query.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	knot_process_t query_ctx;    /*!< Query processing context. */
	knot_nameserver_t *ns;       /*!< Name server structure. */
	struct iovec iov[2];         /*!< TX/RX buffers. */
	unsigned client_threshold;   /*!< Index of first TCP client. */
	timev_t last_poll_time;      /*!< Time of the last socket poll. */
	fdset_t set;                 /*!< Set of server/client sockets. */
} tcp_context_t;

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 5 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 50 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	return TCP_THROTTLE_LO + (knot_random_uint16_t() % TCP_THROTTLE_HI);
}

/*! \brief Sweep TCP connection. */
static enum fdset_sweep_state tcp_sweep(fdset_t *set, int i, void *data)
{
	UNUSED(data);
	assert(set && i < set->n && i >= 0);

	int fd = set->pfd[i].fd;
	char r_addr[SOCKADDR_STRLEN] = { '\0' };
	int r_port = 0;
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	memset(&addr, 0, len);
	if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0) {
		dbg_net("tcp: sweep getpeername() on invalid socket=%d\n", fd);
		return FDSET_SWEEP;
	}

	/* Translate */
	if (addr.ss_family == AF_INET) {
	    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
	    r_port = ntohs(s->sin_port);
	    inet_ntop(AF_INET, &s->sin_addr, r_addr, sizeof(r_addr));
	} else {
#ifndef DISABLE_IPV6
	    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
	    r_port = ntohs(s->sin6_port);
	    inet_ntop(AF_INET6, &s->sin6_addr, r_addr, sizeof(r_addr));
#endif
	}

	log_server_notice("Connection with '%s@%d' was terminated due to "
	                  "inactivity.\n", r_addr, r_port);
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
	struct process_query_param param = {0};
	sockaddr_prep(&param.query_source);
	param.ns = tcp->ns;
	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive data. */
	int ret = tcp_recv(fd, rx->iov_base, rx->iov_len, &param.query_source);
	if (ret <= 0) {
		dbg_net("tcp: client on fd=%d disconnected\n", fd);
		if (ret == KNOT_EAGAIN) {
			char r_addr[SOCKADDR_STRLEN];
			sockaddr_tostr(&param.query_source, r_addr, sizeof(r_addr));
			int r_port = sockaddr_portnum(&param.query_source);
			rcu_read_lock();
			log_server_warning("Couldn't receive query from '%s@%d'"
			                  " within the time limit of %ds.\n",
			                   r_addr, r_port, conf()->max_conn_idle);
			rcu_read_unlock();
		}
		return KNOT_ECONNREFUSED;
	} else {
		rx->iov_len = ret;
	}

	/* Create query processing context. */
	knot_process_begin(&tcp->query_ctx, &param, NS_PROC_QUERY);

	/* Input packet. */
	int state = knot_process_in(rx->iov_base, rx->iov_len, &tcp->query_ctx);

	/* Resolve until NOOP or finished. */
	ret = KNOT_EOK;
	while (state & (NS_PROC_FULL|NS_PROC_FAIL)) {
		uint16_t tx_len = tx->iov_len;
		state = knot_process_out(tx->iov_base, &tx_len, &tcp->query_ctx);

		/* If it has response, send it. */
		if (tx_len > 0) {
			if (tcp_send(fd, tx->iov_base, tx_len) != tx_len) {
				ret = KNOT_ECONNREFUSED;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_process_finish(&tcp->query_ctx);

	return ret;
}

int tcp_accept(int fd)
{
	/* Accept incoming connection. */
	int incoming = accept(fd, 0, 0);

	/* Evaluate connection. */
	if (incoming < 0) {
		int en = errno;
		if (en != EINTR) {
			log_server_error("Cannot accept connection "
					 "(%d).\n", errno);
			if (en == EMFILE || en == ENFILE ||
			    en == ENOBUFS || en == ENOMEM) {
				int throttle = tcp_throttle();
				log_server_error("Throttling TCP connection pool"
				                 " for %d seconds because of "
				                 "too many open descriptors "
				                 "or lack of memory.\n",
				                 throttle);
				sleep(throttle);
			}

		}
	} else {
		dbg_net("tcp: accepted connection fd=%d\n", incoming);
		/* Set recv() timeout. */
#ifdef SO_RCVTIMEO
		struct timeval tv;
		rcu_read_lock();
		tv.tv_sec = conf()->max_conn_idle;
		rcu_read_unlock();
		tv.tv_usec = 0;
		if (setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			log_server_warning("Couldn't set up TCP connection "
			                   "watchdog timer for fd=%d.\n",
			                   incoming);
		}
#endif
	}

	return incoming;
}

int tcp_send(int fd, uint8_t *msg, size_t msglen)
{
	/* Create iovec for gathered write. */
	struct iovec iov[2];
	uint16_t pktsize = htons(msglen);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = msg;
	iov[1].iov_len = msglen;

	/* Send. */
	int total_len = iov[0].iov_len + iov[1].iov_len;
	int sent = writev(fd, iov, 2);
	if (sent != total_len) {
		return KNOT_ERROR;
	}

	return msglen; /* Do not count the size prefix. */
}

int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr)
{
	/* Flags. */
	int flags = MSG_WAITALL;
#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif

	/* Receive size. */
	unsigned short pktsize = 0;
	int n = recv(fd, &pktsize, sizeof(unsigned short), flags);
	if (n < 0) {
		if (errno == EAGAIN) {
			return KNOT_EAGAIN;
		} else {
			return KNOT_ERROR;
		}
	}

	pktsize = ntohs(pktsize);

	dbg_net("tcp: incoming packet size=%hu on fd=%d\n",
		  pktsize, fd);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Get peer name. */
	if (addr) {
		if (getpeername(fd, (struct sockaddr *)addr, &addr->len) < 0) {
			return KNOT_EMALF;
		}
	}

	/* Receive payload. */
	n = recv(fd, buf, pktsize, flags);
	if (n < 0) {
		if (errno == EAGAIN) {
			return KNOT_EAGAIN;
		} else {
			return KNOT_ERROR;
		}
	}
	dbg_net("tcp: received packet size=%d on fd=%d\n",
		  n, fd);

	return n;
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
			socket_close(client);
			return next_id; /* Contains errno. */
		}

		/* Update watchdog timer. */
		rcu_read_lock();
		fdset_set_watchdog(&tcp->set, next_id, conf()->max_conn_hs);
		rcu_read_unlock();
	}

	return KNOT_EOK;
}

static int tcp_event_serve(tcp_context_t *tcp, unsigned i)
{
	int fd = tcp->set.pfd[i].fd;
	int ret = tcp_handle(tcp, fd, &tcp->iov[0], &tcp->iov[1]);

	/* Flush per-query memory. */
	mp_flush(tcp->query_ctx.mm.ctx);

	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		rcu_read_lock();
		fdset_set_watchdog(&tcp->set, i, conf()->max_conn_idle);
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

	/* Process events. */
	unsigned i = 0;
	while (nfds > 0 && i < set->n) {

		/* Terminate faulty connections. */
		int fd = set->pfd[i].fd;

		/* Active sockets. */
		if (set->pfd[i].revents & POLLIN) {
			--nfds; /* One less active event. */

			/* Indexes <0, client_threshold) are master sockets. */
			if (i < tcp->client_threshold) {
				/* Faulty master sockets shall be sorted later. */
				(void) tcp_event_accept(tcp, i);
			} else {
				if (tcp_event_serve(tcp, i) != KNOT_EOK) {
					fdset_remove(set, i);
					close(fd);
					continue; /* Stay on the same index. */
				}
			}

		}

		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fdset_remove(set, i);
			socket_close(fd);
			continue; /* Stay on the same index. */
		}

		/* Next socket. */
		++i;
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

	/* Create TCP answering context. */
	tcp.ns = handler->server->nameserver;

	/* Create big enough memory cushion. */
	mm_ctx_mempool(&tcp.query_ctx.mm, 4 * sizeof(knot_pkt_t));

	/* Prepare structures for bound sockets. */
	fdset_init(&tcp.set, conf()->ifaces_count + CONFIG_XFERS);

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
		if (knot_unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;

			/* Cancel client connections. */
			for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				socket_close(tcp.set.pfd[i].fd);
			}

			ref_release(ref);
			ref = server_set_ifaces(handler->server, &tcp.set, IO_TCP);
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
	mp_delete(tcp.query_ctx.mm.ctx);
	fdset_clear(&tcp.set);
	ref_release(ref);

	return ret;
}

int tcp_master_destruct(dthread_t *thread)
{
	knot_crypto_cleanup_thread();
	return KNOT_EOK;
}
