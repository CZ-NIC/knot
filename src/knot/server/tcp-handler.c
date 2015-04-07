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
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common-knot/sockaddr.h"
#include "common-knot/fdset.h"
#include "common/mempool.h"
#include "knot/knot.h"
#include "knot/server/tcp-handler.h"
#include "libknot/packet/wire.h"
#include "knot/nameserver/process_query.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	knot_process_t query_ctx;   /*!< Query processing context. */
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
	return TCP_THROTTLE_LO + (knot_random_uint16_t() % TCP_THROTTLE_HI);
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
		sockaddr_tostr(&ss, addr_str, sizeof(addr_str));
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
	struct timeval tmout = { conf()->max_conn_reply, 0 };
	rcu_read_unlock();

	/* Receive data. */
	struct timeval recv_tmout = tmout;
	int ret = tcp_recv_msg(fd, rx->iov_base, rx->iov_len, &recv_tmout);
	if (ret <= 0) {
		dbg_net("tcp: client on fd=%d disconnected\n", fd);
		if (ret == KNOT_EAGAIN) {
			rcu_read_lock();
			char addr_str[SOCKADDR_STRLEN] = {0};
			sockaddr_tostr(&ss, addr_str, sizeof(addr_str));
			log_warning("TCP, connection timed out, address '%s'",
			            addr_str);
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
			struct timeval send_tmout = tmout;
			if (tcp_send_msg(fd, tx->iov_base, tx_len, &send_tmout) != tx_len) {
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
		if (en != EINTR && en != EAGAIN) {
			return KNOT_EBUSY;
		}
		return KNOT_ERROR;
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
			log_warning("TCP, failed to set up watchdog timer"
			            ", fd %d", incoming);
		}
#endif
	}

	return incoming;
}

static int select_read(int fd, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);
	return select(fd + 1, &set, NULL, NULL, timeout);
}

static int select_write(int fd, struct timeval *timeout)
{
	fd_set set;
	FD_ZERO(&set);
	FD_SET(fd, &set);

	return select(fd + 1, NULL, &set, NULL, timeout);
}

int tcp_recv_data(int fd, uint8_t *buf, int len, struct timeval *timeout)
{
	int ret = 0;
	int rcvd = 0;
	int flags = 0;

#ifdef MSG_NOSIGNAL
	flags |= MSG_NOSIGNAL;
#endif

	while (rcvd < len) {
		/* Receive data. */
		ret = recv(fd, buf + rcvd, len - rcvd, flags);
		if (ret > 0) {
			rcvd += ret;
			continue;
		}
		/* Check for disconnected socket. */
		if (ret == 0) {
			return KNOT_ECONNREFUSED;
		}

		/* Check for no data available. */
		if (errno == EAGAIN || errno == EINTR) {
			/* Continue only if timeout didn't expire. */
			ret = select_read(fd, timeout);
			if (ret > 0) {
				continue;
			} else {
				return KNOT_ETIMEOUT;
			}
		} else {
			return KNOT_ECONN;
		}
	}

	return rcvd;
}

/*!
 * \brief Shift processed data out of iovec structure.
 */
static void iovec_shift(struct iovec **iov_ptr, int *iovcnt_ptr, size_t done)
{
	struct iovec *iov = *iov_ptr;
	int iovcnt = *iovcnt_ptr;

	for (int i = 0; i < iovcnt && done > 0; i++) {
		if (iov[i].iov_len > done) {
			iov[i].iov_base += done;
			iov[i].iov_len -= done;
			done = 0;
		} else {
			done -= iov[i].iov_len;
			*iov_ptr += 1;
			*iovcnt_ptr -= 1;
		}
	}

	assert(done == 0);
}

/*!
 * \brief Send out TCP data with timeout in case the output buffer is full.
 */
static int send_data(int fd, struct iovec iov[], int iovcnt, struct timeval *timeout)
{
	size_t total = 0;
	for (int i = 0; i < iovcnt; i++) {
		total += iov[i].iov_len;
	}

	for (size_t avail = total; avail > 0; /* nop */) {
		ssize_t sent = writev(fd, iov, iovcnt);
		if (sent == avail) {
			break;
		}

		/* Short write. */
		if (sent > 0) {
			avail -= sent;
			iovec_shift(&iov, &iovcnt, sent);
			continue;
		}

		/* Error. */
		if (sent == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				int ret = select_write(fd, timeout);
				if (ret > 0) {
					continue;
				} else if (ret == 0) {
					return KNOT_ETIMEOUT;
				}
			}

			return KNOT_ECONN;
		}

		/* Unreachable. */
		assert(0);
	}

	return total;
}

int tcp_send_msg(int fd, const uint8_t *msg, size_t msglen, struct timeval *timeout)
{
	/* Create iovec for gathered write. */
	struct iovec iov[2];
	uint16_t pktsize = htons(msglen);
	iov[0].iov_base = &pktsize;
	iov[0].iov_len = sizeof(uint16_t);
	iov[1].iov_base = (void *)msg;
	iov[1].iov_len = msglen;

	/* Send. */
	ssize_t ret = send_data(fd, iov, 2, timeout);
	if (ret < 0) {
		return ret;
	}

	return msglen; /* Do not count the size prefix. */
}

int tcp_recv_msg(int fd, uint8_t *buf, size_t len, struct timeval *timeout)
{
	if (buf == NULL || fd < 0) {
		return KNOT_EINVAL;
	}

	/* Receive size. */
	unsigned short pktsize = 0;
	int ret = tcp_recv_data(fd, (uint8_t *)&pktsize, sizeof(pktsize), timeout);
	if (ret != sizeof(pktsize)) {
		return ret;
	}

	pktsize = ntohs(pktsize);
	dbg_net("tcp: incoming packet size=%hu on fd=%d\n", pktsize, fd);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}

	/* Receive payload. */
	ret = tcp_recv_data(fd, buf, pktsize, timeout);
	if (ret != pktsize) {
		return ret;
	}

	dbg_net("tcp: received packet size=%d on fd=%d\n", ret, fd);
	return ret;
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
		fdset_set_watchdog(&tcp->set, next_id, conf()->max_conn_hs);
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
	bool is_throttled = (tcp->last_poll_time.tv_sec < tcp->throttle_end.tv_sec);
	if (!is_throttled) {
		/* Configuration limit, infer maximal pool size. */
		rcu_read_lock();
		unsigned max_per_set = MAX(conf()->max_tcp_clients / conf_tcp_threads(conf()), 1);
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

	/* Create TCP answering context. */
	tcp.server = handler->server;
	tcp.thread_id = handler->thread_id[dt_get_id(thread)];

	/* Create big enough memory cushion. */
	mm_ctx_mempool(&tcp.query_ctx.mm, 4 * sizeof(knot_pkt_t));

	/* Prepare structures for bound sockets. */
	fdset_init(&tcp.set, list_size(&conf()->ifaces) + CONFIG_XFERS);

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
				close(tcp.set.pfd[i].fd);
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
