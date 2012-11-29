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
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common/sockaddr.h"
#include "common/skip-list.h"
#include "common/fdset.h"
#include "knot/common.h"
#include "knot/server/tcp-handler.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zones.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/util/wire.h"

/* Defines */
#define TCP_BUFFER_SIZE 65535 /*! Do not change, as it is used for maximum DNS/TCP packet size. */

/*! \brief TCP worker data. */
typedef struct tcp_worker_t {
	iohandler_t *ioh; /*!< Shortcut to I/O handler. */
	fdset_t *fdset;   /*!< File descriptor set. */ 
	int pipe[2];      /*!< Master-worker signalization pipes. */
} tcp_worker_t;

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 5 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 50 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	//(TCP_THROTTLE_LO + (int)(tls_rand() * TCP_THROTTLE_HI));
	return (rand() % TCP_THROTTLE_HI) + TCP_THROTTLE_LO; 
}

/*! \brief Wrapper for TCP send. */
static int xfr_send_cb(int session, sockaddr_t *addr, uint8_t *msg, size_t msglen)
{
	UNUSED(addr);
	int ret = tcp_send(session, msg, msglen);
	if (ret < 0) {
		return KNOT_ECONN;
	}
	
	return ret;
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
static void tcp_sweep(fdset_t *set, int fd, void* data)
{
	UNUSED(data);
	
	char r_addr[SOCKADDR_STRLEN] = { '\0' };
	int r_port = 0;
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr*)&addr, &len) < 0) {
		dbg_net("tcp: sweep getpeername() on invalid socket=%d\n", fd);
		return;
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
	fdset_remove(set, fd);
	close(fd);
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
static int tcp_handle(tcp_worker_t *w, int fd, uint8_t *qbuf, size_t qbuf_maxlen)
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
	if (sockaddr_init(&addr, w->ioh->type) != KNOT_EOK) {
		log_server_error("Socket type %d is not supported, "
				 "IPv6 support is probably disabled.\n",
				 w->ioh->type);
		return KNOT_EINVAL;
	}

	/* Receive data. */
	int n = tcp_recv(fd, qbuf, qbuf_maxlen, &addr);
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
	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		int ret = knot_ns_error_response_from_query_wire(ns, qbuf, n,
		                                            KNOT_RCODE_SERVFAIL,
		                                            qbuf, &resp_len);

		if (ret == KNOT_EOK) {
			tcp_reply(fd, qbuf, resp_len);
		}

		return KNOT_EOK;
	}

	int parse_res = knot_ns_parse_packet(qbuf, n, packet, &qtype);
	if (knot_unlikely(parse_res != KNOT_EOK)) {
		if (parse_res > 0) { /* Returned RCODE */
			int ret = knot_ns_error_response_from_query(ns, packet,
			                            parse_res, qbuf, &resp_len);

			if (ret == KNOT_EOK) {
				tcp_reply(fd, qbuf, resp_len);
			}
		}
		knot_packet_free(&packet);
		return KNOT_EOK;
	}

	/* Handle query. */
	int xfrt = -1;
	knot_ns_xfr_t xfr;
	int res = KNOT_ERROR;
	switch(qtype) {

	/* Query types. */
	case KNOT_QUERY_NORMAL:
		//res = knot_ns_answer_normal(ns, packet, qbuf, &resp_len);
		if (zones_normal_query_answer(ns, packet, &addr,
		                              qbuf, &resp_len,
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
		
		/* Prepare context. */
		res = xfr_request_init(&xfr, xfrt, XFR_FLAG_TCP, packet);
		if (res != KNOT_EOK) {
			knot_ns_error_response_from_query(ns, packet,
			                                  KNOT_RCODE_SERVFAIL,
			                                  qbuf, &resp_len);
			res = KNOT_EOK;
			break;
		}
		xfr.send = xfr_send_cb;
		xfr.session = fd;
		xfr.wire = qbuf;
		xfr.wire_size = qbuf_maxlen;
		memcpy(&xfr.addr, &addr, sizeof(sockaddr_t));
		
		/* Answer. */
		return xfr_answer(ns, &xfr);
		
	case KNOT_QUERY_UPDATE:
//		knot_ns_error_response_from_query(ns, packet,
//		                                  KNOT_RCODE_NOTIMPL,
//		                                  qbuf, &resp_len);
		res = zones_process_update(ns, packet, &addr, qbuf, &resp_len,
		                           fd, NS_TRANSPORT_TCP);
//		res = KNOT_EOK;
		break;
		
	case KNOT_QUERY_NOTIFY:
		res = notify_process_request(ns, packet, &addr,
					     qbuf, &resp_len);
		break;
		
	/* Unhandled opcodes. */
	case KNOT_RESPONSE_NOTIFY: /*!< Only in UDP. */
	case KNOT_RESPONSE_NORMAL: /*!< TCP handler doesn't send queries. */
	case KNOT_RESPONSE_AXFR:   /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_IXFR:   /*!< Processed in XFR handler. */
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_REFUSED,
		                                  qbuf, &resp_len);
		res = KNOT_EOK;
		break;
		
	/* Unknown opcodes. */
	default:
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_FORMERR,
		                                  qbuf, &resp_len);
		res = KNOT_EOK;
		break;
	}

	knot_packet_free(&packet);

	/* Send answer. */
	if (res == KNOT_EOK) {
		tcp_reply(fd, qbuf, resp_len);
	} else {
		dbg_net("tcp: failed to respond to query type=%d on fd=%d - %s\n",
		        qtype, fd, knot_strerror(res));;
	}

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

tcp_worker_t* tcp_worker_create()
{
	tcp_worker_t *w = malloc(sizeof(tcp_worker_t));
	if (w == NULL) {
		dbg_net("tcp: out of memory when creating worker\n");
		return NULL;
	}
	
	/* Create signal pipes. */
	memset(w, 0, sizeof(tcp_worker_t));
	if (pipe(w->pipe) < 0) {
		free(w);
		return NULL;
	}
	
	/* Create fdset. */
	w->fdset = fdset_new();
	if (!w->fdset) {
		close(w->pipe[0]);
		close(w->pipe[1]);
		free(w);
		return NULL;
	}
	
	fdset_add(w->fdset, w->pipe[0], OS_EV_READ);
	
	return w;
}

void tcp_worker_free(tcp_worker_t* w)
{
	if (!w) {
		return;
	}
	
	/* Destroy fdset. */
	fdset_destroy(w->fdset);
	
	/* Close pipe write end and worker. */
	close(w->pipe[0]);
	close(w->pipe[1]);
	free(w);
}

/*
 * Public APIs.
 */

int tcp_send(int fd, uint8_t *msg, size_t msglen)
{

	/*! \brief TCP corking.
	 *  \see http://vger.kernel.org/~acme/unbehaved.txt
	 */
#ifdef TCP_CORK
	int cork = 1;
	int uncork = setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
#endif

	/* Send message size. */
	unsigned short pktsize = htons(msglen);
	int sent = send(fd, &pktsize, sizeof(pktsize), 0);
	if (sent < 0) {
		return KNOT_ERROR;
	}

	/* Send message data. */
	sent = send(fd, msg, msglen, 0);
	if (sent < 0) {
		return KNOT_ERROR;
	}

#ifdef TCP_CORK
	/* Uncork only if corked successfuly. */
	if (uncork == 0) {
		cork = 0;
		setsockopt(fd, SOL_TCP, TCP_CORK, &cork, sizeof(cork));
	}
#endif
	return sent;
}

int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr)
{
	/* Receive size. */
	unsigned short pktsize = 0;
	int n = recv(fd, &pktsize, sizeof(unsigned short), MSG_WAITALL);
	if (n < 0) {
		if (errno == EAGAIN) {
			return KNOT_EAGAIN;
		} else {
			return KNOT_ERROR;
		}
	}

	pktsize = ntohs(pktsize);

	// Check packet size for NULL
	if (pktsize == 0) {
		return KNOT_ERROR;
	}

	dbg_net("tcp: incoming packet size=%hu on fd=%d\n",
		  pktsize, fd);

	// Check packet size
	if (len < pktsize) {
		return KNOT_ENOMEM;
	}
	
	/* Get peer name. */
	if (addr) {
		socklen_t alen = addr->len;
		if (getpeername(fd, addr->ptr, &alen) < 0) {
			return KNOT_EMALF;
		}
	}

	/* Receive payload. */
	n = recv(fd, buf, pktsize, MSG_WAITALL);
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
	iohandler_t *handler = (iohandler_t *)thread->data;
	dt_unit_t *unit = thread->unit;

	/* Check socket. */
	if (!handler || handler->fd < 0 || handler->data == NULL) {
		dbg_net("tcp: failed to initialize master thread\n");
		return KNOT_EINVAL;
	}
	
	tcp_worker_t **workers = handler->data;

	/* Accept connections. */
	int id = 0;
	dbg_net("tcp: created 1 master with %d workers, backend is '%s' \n",
	        unit->size - 1, fdset_method());
	while(1) {
		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Accept client. */
		int client = tcp_accept(handler->fd);
		if (client < 0) {
			continue;
		}

		/* Add to worker in RR fashion. */
		if (write(workers[id]->pipe[1], &client, sizeof(int)) < 0) {
			dbg_net("tcp: failed to register fd=%d to worker=%d\n",
			        client, id);
			close(client);
			continue;
		}
		id = get_next_rr(id, unit->size - 1);
	}

	dbg_net("tcp: master thread finished\n");
	free(workers);
	
	return KNOT_EOK;
}

int tcp_loop_worker(dthread_t *thread)
{
	tcp_worker_t *w = thread->data;
	if (!w) {
		return KNOT_EINVAL;
	}
	
	/* Allocate buffer for requests. */
	uint8_t *qbuf = malloc(TCP_BUFFER_SIZE);
	if (qbuf == NULL) {
		dbg_net("tcp: failed to allocate buffers for TCP worker\n");
		return KNOT_EINVAL;
	}
	
	/* Drop all capabilities on workers. */
#ifdef HAVE_CAP_NG_H
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);
		capng_apply(CAPNG_SELECT_BOTH);
	}
#endif /* HAVE_CAP_NG_H */
	
	/* Next sweep time. */
	timev_t next_sweep;
	time_now(&next_sweep);
	next_sweep.tv_sec += TCP_SWEEP_INTERVAL;

	/* Accept clients. */
	dbg_net_verb("tcp: worker %p started\n", w);
	for (;;) {

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		int nfds = fdset_wait(w->fdset, (TCP_SWEEP_INTERVAL * 1000)/2);
		if (nfds < 0) {
			continue;
		}
		
		/* Establish timeouts. */
		rcu_read_lock();
		int max_idle = conf()->max_conn_idle;
		int max_hs = conf()->max_conn_hs;
		rcu_read_unlock();

		/* Process incoming events. */
		dbg_net_verb("tcp: worker %p registered %d events\n",
		             w, nfds);
		fdset_it_t it;
		fdset_begin(w->fdset, &it);
		while(nfds > 0) {
			
			/* Handle incoming clients. */
			if (it.fd == w->pipe[0]) {
				int client = 0;
				if (read(it.fd, &client, sizeof(int)) < 0) {
					continue;
				}

				dbg_net_verb("tcp: worker %p registered "
				             "client %d\n",
				             w, client);
				fdset_add(w->fdset, client, OS_EV_READ);
				fdset_set_watchdog(w->fdset, client,
				                   max_hs);
				dbg_net("tcp: watchdog for fd=%d set to %ds\n",
				        client, max_hs);
			} else {
				/* Handle other events. */
				int ret = tcp_handle(w, it.fd, qbuf,
				                     TCP_BUFFER_SIZE);
				if (ret == KNOT_EOK) {
					fdset_set_watchdog(w->fdset, it.fd,
					                   max_idle);
					dbg_net("tcp: watchdog for fd=%d "
					        "set to %ds\n",
					        it.fd, max_idle);
				}
				/*! \todo Refactor to allow erase on iterator.*/
				if (ret == KNOT_ECONNREFUSED) {
					fdset_remove(w->fdset, it.fd);
					close(it.fd);
					break;
				}
				
			}
			
			/* Check if next exists. */
			if (fdset_next(w->fdset, &it) != 0) {
				break;
			}
		}
		
		/* Sweep inactive. */
		timev_t now;
		if (time_now(&now) == 0) {
			if (now.tv_sec >= next_sweep.tv_sec) {
				fdset_sweep(w->fdset, &tcp_sweep, NULL);
				memcpy(&next_sweep, &now, sizeof(next_sweep));
				next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
			}
		}
	}

	/* Stop whole unit. */
	free(qbuf);
	dbg_net_verb("tcp: worker %p finished\n", w);
	tcp_worker_free(w);
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
		dt_repurpose(unit->threads[i + 1], tcp_loop_worker, workers[i]);
	}

	/* Repurpose first thread as master (unit controller). */
	dt_repurpose(unit->threads[0], tcp_loop_master, ioh);

	return KNOT_EOK;
}
