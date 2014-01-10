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
#include "knot/knot.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zones.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/util/wire.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"

/*! \brief TCP worker data. */
typedef struct tcp_worker_t {
	iohandler_t *ioh; /*!< Shortcut to I/O handler. */
	fdset_t set;      /*!< File descriptor set. */
	int pipe[2];      /*!< Master-worker signalization pipes. */
} tcp_worker_t;

/*! \brief Buffers .*/
enum {
	QBUF   = 0, /* Query buffer ID. */
	QRBUF  = 1, /* Response buffer ID. */
	NBUFS  = 2  /* Buffer count. */
};

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 5 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 50 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	return TCP_THROTTLE_LO + (knot_random_int() % TCP_THROTTLE_HI);
}

/*! \brief Send reply. */
static int tcp_reply(int fd, uint8_t *qbuf, size_t resp_len)
{
	dbg_net("tcp: got answer of size %zd.\n",
		resp_len);

	int res = 0;
	if (resp_len > 0) {
		res = tcp_send(fd, qbuf, resp_len);
	}

	/* Check result. */
	if (res < 0 || (size_t)res != resp_len) {
		dbg_net("tcp: %s: failed: %d - %d.\n",
			  "socket_send()",
			  res, errno);
	}

	return res;
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
 *
 * Handle single TCP event.
 *
 * \param w Associated I/O event.
 * \param revents Returned events.
 *
 * \note We do not know if the packet makes sense or if it is
 *       a bunch of random bytes. There is no way to find out
 *       without parsing. However, it is irrelevant if we copy
 *       these random bytes to the response, so we may do it
 *       and ensure that in case of good packet the response
 *       is proper.
 */
static int tcp_handle(tcp_worker_t *w, int fd, uint8_t *buf[], size_t qbuf_maxlen)
{
	if (fd < 0 || !w || !w->ioh) {
		dbg_net("tcp: tcp_handle(%p, %d) - invalid parameters\n", w, fd);
		return KNOT_EINVAL;
	}

	dbg_net("tcp: handling TCP event on fd=%d in thread %p.\n",
	        fd, (void*)pthread_self());

	knot_nameserver_t *ns = w->ioh->server->nameserver;

	/* Check address type. */
	sockaddr_t addr;
	sockaddr_prep(&addr);

	/* Receive data. */
	int n = tcp_recv(fd, buf[QBUF], qbuf_maxlen, &addr);
	if (n <= 0) {
		dbg_net("tcp: client on fd=%d disconnected\n", fd);
		if (n == KNOT_EAGAIN) {
			char r_addr[SOCKADDR_STRLEN];
			sockaddr_tostr(&addr, r_addr, sizeof(r_addr));
			int r_port = sockaddr_portnum(&addr);
			rcu_read_lock();
			log_server_warning("Couldn't receive query from '%s@%d'"
			                  " within the time limit of %ds.\n",
			                   r_addr, r_port, conf()->max_conn_idle);
			rcu_read_unlock();
		}
		return KNOT_ECONNREFUSED;
	}

	/* Parse query. */
	size_t resp_len = qbuf_maxlen; // 64K
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	knot_packet_t *packet = knot_packet_new();
	if (packet == NULL) {
		int ret = knot_ns_error_response_from_query_wire(ns, buf[QBUF], n,
		                                            KNOT_RCODE_SERVFAIL,
		                                            buf[QRBUF], &resp_len);

		if (ret == KNOT_EOK) {
			tcp_reply(fd, buf[QRBUF], resp_len);
		}

		return KNOT_EOK;
	}

	int parse_res = knot_ns_parse_packet(buf[QBUF], n, packet, &qtype);
	if (knot_unlikely(parse_res != KNOT_EOK)) {
		if (parse_res > 0) { /* Returned RCODE */
			int ret = knot_ns_error_response_from_query(ns, packet,
			                          parse_res, buf[QRBUF], &resp_len);

			if (ret == KNOT_EOK) {
				tcp_reply(fd, buf[QRBUF], resp_len);
			}
		}
		knot_packet_free(&packet);
		return KNOT_EOK;
	}

	/* Handle query. */
	int xfrt = -1;
	knot_ns_xfr_t *xfr = NULL;
	int res = KNOT_ERROR;
	switch(qtype) {

	/* Query types. */
	case KNOT_QUERY_NORMAL:
		//res = knot_ns_answer_normal(ns, packet, qbuf, &resp_len);
		if (zones_normal_query_answer(ns, packet, &addr,
		                              buf[QRBUF], &resp_len,
		                              NS_TRANSPORT_TCP) == KNOT_EOK) {
			res = KNOT_EOK;
		}
		break;
	case KNOT_QUERY_AXFR:
	case KNOT_QUERY_IXFR:
		if (qtype == KNOT_QUERY_IXFR) {
			xfrt = XFR_TYPE_IOUT;
		} else {
			xfrt = XFR_TYPE_AOUT;
		}

		/* Answer from query. */
		xfr = xfr_task_create(NULL, xfrt, XFR_FLAG_TCP);
		if (xfr == NULL) {
			knot_ns_error_response_from_query(ns, packet,
			                                  KNOT_RCODE_SERVFAIL,
			                                  buf[QRBUF], &resp_len);
			res = KNOT_EOK;
			break;
		}
		xfr->session = fd;
		xfr->wire = buf[QRBUF];
		xfr->wire_size = qbuf_maxlen;
		xfr->query = packet;
		xfr_task_setaddr(xfr, &addr, NULL);
		res = xfr_answer(ns, xfr);
		knot_packet_free(&packet);
		return res;

	case KNOT_QUERY_UPDATE:
		res = zones_process_update(ns, packet, &addr, buf[QRBUF], &resp_len,
		                           fd, NS_TRANSPORT_TCP);
		break;

	case KNOT_QUERY_NOTIFY:
		res = notify_process_request(ns, packet, &addr,
					     buf[QRBUF], &resp_len);
		break;

	/* Unhandled opcodes. */
	case KNOT_RESPONSE_NOTIFY: /*!< Only in UDP. */
	case KNOT_RESPONSE_NORMAL: /*!< TCP handler doesn't send queries. */
	case KNOT_RESPONSE_AXFR:   /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_IXFR:   /*!< Processed in XFR handler. */
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_REFUSED,
		                                  buf[QRBUF], &resp_len);
		res = KNOT_EOK;
		break;

	/* Unknown opcodes. */
	default:
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_FORMERR,
		                                  buf[QRBUF], &resp_len);
		res = KNOT_EOK;
		break;
	}

	/* Send answer. */
	if (res == KNOT_EOK) {
		tcp_reply(fd, buf[QRBUF], resp_len);
	} else {
		dbg_net("tcp: failed to respond to query type=%d on fd=%d - %s\n",
		        qtype, fd, knot_strerror(res));;
	}

	knot_packet_free(&packet);

	return res;
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

/*! \brief Read a descriptor from the pipe and assign it to given fdset. */
static int tcp_loop_assign(int pipe, fdset_t *set)
{
	/* Read socket descriptor from pipe. */
	int client, next_id;
	if (read(pipe, &client, sizeof(int)) != sizeof(int)) {
		return KNOT_ENOENT;
	}

	/* Assign to fdset. */
	next_id = fdset_add(set, client, POLLIN, NULL);
	if (next_id < 0) {
		socket_close(client);
		return next_id; /* Contains errno. */
	}

	/* Update watchdog timer. */
	rcu_read_lock();
	fdset_set_watchdog(set, next_id, conf()->max_conn_hs);
	rcu_read_unlock();
	return next_id;
}

tcp_worker_t* tcp_worker_create()
{
	tcp_worker_t *w = malloc(sizeof(tcp_worker_t));
	if (w == NULL)
		return NULL;

	/* Create signal pipes. */
	memset(w, 0, sizeof(tcp_worker_t));
	if (pipe(w->pipe) < 0) {
		free(w);
		return NULL;
	}

	/* Create fdset. */
	if (fdset_init(&w->set, FDSET_INIT_SIZE) != KNOT_EOK) {
		close(w->pipe[0]);
		close(w->pipe[1]);
		free(w);
		return NULL;
	}

	fdset_add(&w->set, w->pipe[0], POLLIN, NULL);
	return w;
}

void tcp_worker_free(tcp_worker_t* w)
{
	if (!w) {
		return;
	}

	/* Clear fdset. */
	fdset_clear(&w->set);

	/* Close pipe write end and worker. */
	close(w->pipe[0]);
	close(w->pipe[1]);
	free(w);
}

/* Free workers and associated data. */
static void tcp_loop_free(void *data)
{
	tcp_worker_t **worker = (tcp_worker_t **)data;
	iohandler_t *ioh = worker[0]->ioh;
	for (unsigned i = 0; i < ioh->unit->size - 1; ++i)
		tcp_worker_free(worker[i]);

	free(worker);
}

/*
 * Public APIs.
 */

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

	/* The packet MUST contain at least DNS header.
	 * If it doesn't, it's not a DNS packet and we should discard it.
	 */
	if (pktsize < KNOT_WIRE_HEADER_SIZE) {
		return KNOT_EFEWDATA;
	}

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

int tcp_loop_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	iostate_t *st = (iostate_t *)thread->data;
	iohandler_t *h = st->h;
	dt_unit_t *unit = thread->unit;
	tcp_worker_t **workers = h->data;

	/* Prepare structures for bound sockets. */
	ref_t *ref = NULL;
	fdset_t set;
	fdset_init(&set, conf()->ifaces_count);

	/* Accept connections. */
	int id = 0, ret = 0;
	dbg_net("tcp: created 1 master with %d workers\n", unit->size - 1);
	for(;;) {

		/* Check handler state. */
		if (knot_unlikely(st->s & ServerReload)) {
			st->s &= ~ServerReload;
			ref_release(ref);
			ref = server_set_ifaces(h->server, &set, IO_TCP);
			if (set.n == 0) /* Terminate on zero interfaces. */
				break;
		}

		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		int nfds = poll(set.pfd, set.n, -1);
		if (nfds <= 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		unsigned i = 0;
		while (nfds > 0 && i < set.n && !dt_is_cancelled(thread)) {

			/* Error events. */
			if (set.pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				socket_close(set.pfd[i].fd);
				fdset_remove(&set, i);
				--nfds;   /* Treat error event as activity. */
				continue; /* Stay on the same index. */
			} else if (!(set.pfd[i].revents & POLLIN)) {
				/* Inactive sockets. */
				++i;
				continue;
			}

			/* Accept client. */
			--nfds; /* One less active event. */
			int client = tcp_accept(set.pfd[i].fd);
			if (client >= 0) {
				/* Add to worker in RR fashion. */
				id = get_next_rr(id, unit->size - 1);
				ret = write(workers[id]->pipe[1], &client,
				            sizeof(int));
				if (ret < 0) {
					close(client);
				}
			}

			/* Next socket. */
			++i;
		}
	}

	dbg_net("tcp: master thread finished\n");
	fdset_clear(&set);
	ref_release(ref);

	return KNOT_EOK;
}

int tcp_loop_worker(dthread_t *thread)
{
	/* Drop all capabilities on workers. */
#ifdef HAVE_CAP_NG_H
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);
		capng_apply(CAPNG_SELECT_BOTH);
	}
#endif /* HAVE_CAP_NG_H */

	uint8_t *buf[NBUFS];
	for (unsigned i = 0; i < NBUFS; ++i) {
		buf[i] = malloc(SOCKET_MTU_SZ);
	}

	tcp_worker_t *w = thread->data;
	if (w == NULL || buf[QBUF] == NULL || buf[QRBUF] == NULL) {
		for (unsigned i = 0; i < NBUFS; ++i) {
			free(buf[i]);
		}
		return KNOT_EINVAL;
	}

	/* Accept clients. */
	dbg_net("tcp: worker %p started\n", w);
	fdset_t *set = &w->set;
	timev_t next_sweep;
	time_now(&next_sweep);
	next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
	for (;;) {

		/* Cancellation point. */
		if (dt_is_cancelled(thread))
			break;

		/* Wait for events. */
		int nfds = poll(set->pfd, set->n, TCP_SWEEP_INTERVAL * 1000);
		if (nfds < 0)
			continue;

		/* Establish timeouts. */
		rcu_read_lock();
		int max_idle = conf()->max_conn_idle;
		rcu_read_unlock();

		/* Process incoming events. */
		unsigned i = 0;
		while (nfds > 0 && i < set->n && !dt_is_cancelled(thread)) {

			/* Terminate faulty connections. */
			int fd = set->pfd[i].fd;
			if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				fdset_remove(set, i);
				close(fd);
				--nfds;   /* Treat error event as activity. */
				continue; /* Stay on the same index. */
			} else if (!(set->pfd[i].revents & set->pfd[i].events)) {
				/* Skip inactive. */
				++i;
				continue;
			}

			/* One less active event. */
			--nfds;

			/* Register new TCP client or process a query. */
			if (fd == w->pipe[0]) {
				tcp_loop_assign(fd, set);
			} else {
				int ret = tcp_handle(w, fd, buf, SOCKET_MTU_SZ);
				if (ret == KNOT_EOK) {
					/* Update socket activity timer. */
					fdset_set_watchdog(set, i, max_idle);
				}
				if (ret == KNOT_ECONNREFUSED) {
					fdset_remove(set, i);
					close(fd);
					continue; /* Stay on the same index. */
				}
			}

			/* Next active. */
			++i;
		}

		/* Sweep inactive. */
		timev_t now;
		if (time_now(&now) == 0) {
			if (now.tv_sec >= next_sweep.tv_sec) {
				fdset_sweep(set, &tcp_sweep, NULL);
				memcpy(&next_sweep, &now, sizeof(next_sweep));
				next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
			}
		}
	}

	/* Stop whole unit. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		free(buf[i]);
	}
	dbg_net("tcp: worker %p finished\n", w);
	return KNOT_EOK;
}

int tcp_handler_destruct(dthread_t *thread)
{
	knot_crypto_cleanup_thread();
	return KNOT_EOK;
}

int tcp_loop_unit(iohandler_t *ioh, dt_unit_t *unit)
{
	if (unit->size < 1) {
		return KNOT_EINVAL;
	}

	/* Create unit data. */
	tcp_worker_t **workers = malloc((unit->size - 1) *
	                                sizeof(tcp_worker_t *));
	if (!workers) {
		dbg_net("tcp: cannot allocate list of workers\n");
		return KNOT_EINVAL;
	}

	/* Prepare worker data. */
	unsigned allocated = 0;
	for (unsigned i = 0; i < unit->size - 1; ++i) {
		workers[i] = tcp_worker_create();
		if (workers[i] == 0) {
			break;
		}
		workers[i]->ioh = ioh;
		++allocated;
	}

	/* Check allocated workers. */
	if (allocated != unit->size - 1) {
		for (unsigned i = 0; i < allocated; ++i) {
			tcp_worker_free(workers[i]);
		}

		free(workers);
		dbg_net("tcp: cannot create workers\n");
		return KNOT_EINVAL;
	}

	/* Store worker data. */
	ioh->data = workers;

	/* Repurpose workers. */
	for (unsigned i = 0; i < allocated; ++i) {
		dthread_t *thread = unit->threads[i + 1];
		dt_repurpose(thread, tcp_loop_worker, workers[i]);
		dt_set_desctructor(thread, tcp_handler_destruct);
	}

	/* Repurpose first thread as master (unit controller). */
	dt_repurpose(unit->threads[0], tcp_loop_master, ioh->state + 0);
	dt_set_desctructor(unit->threads[0], tcp_handler_destruct);

	/* Create data destructor. */
	ioh->dtor = tcp_loop_free;

	return KNOT_EOK;
}
