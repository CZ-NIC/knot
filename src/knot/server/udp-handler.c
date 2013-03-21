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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Required for RTLD_DEFAULT. */
#endif

#include <dlfcn.h>
#include <config.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/syscall.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common/sockaddr.h"
#include "knot/common.h"
#include "knot/server/udp-handler.h"
#include "libknot/nameserver/name-server.h"
#include "knot/stat/stat.h"
#include "knot/server/server.h"
#include "libknot/util/wire.h"
#include "libknot/consts.h"
#include "libknot/packet/packet.h"
#include "knot/server/zones.h"
#include "knot/server/notify.h"

/*! \brief RRL reject procedure. */
static size_t udp_rrl_reject(const knot_nameserver_t *ns,
                             const knot_packet_t *packet,
                             uint8_t* resp, size_t rlen,
                             uint8_t rcode, unsigned *slip)
{
	int n_slip = conf()->rrl_slip; /* Check SLIP. */
	if (n_slip > 0 && n_slip == ++*slip) {
		knot_ns_error_response_from_query(ns, packet, rcode, resp, &rlen);
		switch(rcode) { /* Do not set TC=1 to some RCODEs. */
		case KNOT_RCODE_FORMERR:
		case KNOT_RCODE_REFUSED:
		case KNOT_RCODE_SERVFAIL:
		case KNOT_RCODE_NOTIMPL:
			break;
		default:
			knot_wire_set_tc(resp); /* Set TC=1 */
			break;
		}
		
		*slip = 0; /* Restart SLIP interval. */
		return rlen;
	}
	
	return 0; /* Discard response. */
}

int udp_handle(int fd, uint8_t *qbuf, size_t qbuflen, size_t *resp_len,
	       sockaddr_t* addr, knot_nameserver_t *ns, rrl_table_t *rrl, unsigned *slip)
{
#ifdef DEBUG_ENABLE_BRIEF
	char strfrom[SOCKADDR_STRLEN];
	memset(strfrom, 0, sizeof(strfrom));
	sockaddr_tostr(addr, strfrom, sizeof(strfrom));
	dbg_net("udp: fd=%d received %zd bytes from '%s@%d'.\n", fd, qbuflen,
	        strfrom, sockaddr_portnum(addr));
#endif
	
	knot_packet_type_t qtype = KNOT_QUERY_NORMAL;
	*resp_len = SOCKET_MTU_SZ;

	knot_packet_t *packet =
		knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		dbg_net("udp: failed to create packet on fd=%d\n", fd);

		int ret = knot_ns_error_response_from_query_wire(ns, qbuf, qbuflen,
		                                            KNOT_RCODE_SERVFAIL,
		                                            qbuf, resp_len);

		if (ret != KNOT_EOK) {
			return KNOT_EMALF;
		}

		return KNOT_EOK; /* Created error response. */
	}
	
	/* Prepare RRL structs. */
	rrl_req_t rrl_rq;
	memset(&rrl_rq, 0, sizeof(rrl_req_t));
	rrl_rq.w = qbuf; /* Wire */
	
	/* Parse query. */
	int res = knot_ns_parse_packet(qbuf, qbuflen, packet, &qtype);
	if (rrl) rrl_rq.qst = &packet->question;
	if (knot_unlikely(res != KNOT_EOK)) {
		dbg_net("udp: failed to parse packet on fd=%d\n", fd);
		if (res > 0) { /* Returned RCODE */
			res = knot_ns_error_response_from_query(
			       ns, packet, res, qbuf, resp_len);
			if (res != KNOT_EOK) {
				knot_packet_free(&packet);
				return KNOT_EMALF;
			}
		} else {
			res = knot_ns_error_response_from_query_wire(
			       ns, qbuf, qbuflen, KNOT_RCODE_SERVFAIL, qbuf, 
			       resp_len);
			if (res != KNOT_EOK) {
				knot_packet_free(&packet);
				return res;
			}
		}
	}
	
	/* Handle query. */
	switch(qtype) {
	case KNOT_QUERY_NORMAL:
		res = zones_normal_query_answer(ns, packet, addr, qbuf,
		                                resp_len, NS_TRANSPORT_UDP);
		break;
	case KNOT_QUERY_AXFR:
		/* RFC1034, p.28 requires reliable transfer protocol.
		 * Bind responds with FORMERR.
 		 */
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_FORMERR, qbuf,
		                                  resp_len);
		res = KNOT_EOK;
		break;
	case KNOT_QUERY_IXFR:
		/* According to RFC1035, respond with SOA. */
		res = zones_normal_query_answer(ns, packet, addr,
		                                qbuf, resp_len, 
		                                NS_TRANSPORT_UDP);
		break;
	case KNOT_QUERY_NOTIFY:
		res = notify_process_request(ns, packet, addr,
		                             qbuf, resp_len);
		break;
		
	case KNOT_QUERY_UPDATE:
		res = zones_process_update(ns, packet, addr, qbuf, resp_len,
		                           fd, NS_TRANSPORT_UDP);
		break;
		
	/* Unhandled opcodes. */
	case KNOT_RESPONSE_AXFR: /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_IXFR: /*!< Processed in XFR handler. */
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_REFUSED, qbuf,
		                                  resp_len);
		res = KNOT_EOK;
		break;
			
	/* Unknown opcodes */
	default:
		knot_ns_error_response_from_query(ns, packet,
		                                  KNOT_RCODE_FORMERR, qbuf,
		                                  resp_len);
		res = KNOT_EOK;
		break;
	}
	
	/* Process RRL. */
	if (rrl) {
		rcu_read_lock();
		rrl_rq.flags = packet->flags;
		if (rrl_query(rrl, addr, &rrl_rq, packet->zone) != KNOT_EOK) {
			*resp_len = udp_rrl_reject(ns, packet, qbuf,
			                           SOCKET_MTU_SZ,
			                           knot_wire_get_rcode(qbuf),
			                           slip);
		}
		rcu_read_unlock();
	}
	

	knot_packet_free(&packet);

	return res;
}

/* Check for sendmmsg syscall. */
#ifdef HAVE_SENDMMSG
  #define ENABLE_SENDMMSG 1
#else
  #ifdef SYS_sendmmsg
    #define ENABLE_SENDMMSG 1
  #endif
#endif

/*! \brief Pointer to selected UDP master implementation. */
static void* (*_udp_init)(void) = 0;
static int (*_udp_deinit)(void *) = 0;
static int (*_udp_handle)(server_t *, int, void *) = 0;

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	sockaddr_t addr;
	uint8_t *buf;
	size_t buflen;
	unsigned slip;
};

static void *udp_recvfrom_init(void)
{
	struct udp_recvfrom *rq = malloc(sizeof(struct udp_recvfrom));
	if (rq) {
		rq->buflen = SOCKET_MTU_SZ;
		rq->buf = malloc(rq->buflen);
		rq->slip = 0;
	}
	return rq;
}

static int udp_recvfrom_deinit(void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	if (rq) {
		free(rq->buf);
		free(rq);
	}
	return 0;
}

static int udp_recvfrom_handle(server_t *s, int fd, void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	sockaddr_prep(&rq->addr);
	
	/* Receive packet. */
	int rc = 0;
	for (;;) {
		int n = recvfrom(fd, rq->buf, rq->buflen, MSG_DONTWAIT,
		                 (struct sockaddr *)&rq->addr, &rq->addr.len);
	
		/* Error and interrupt handling. */
		if (knot_unlikely(n <= 0)) {
			break;
		}

		/* Handle received pkt. */
		size_t resp_len = 0;
		rc = udp_handle(fd, rq->buf, n, &resp_len, &rq->addr,
		                s->nameserver, s->rrl, &rq->slip);
		
		/* Send response. */
		if (rc == KNOT_EOK && resp_len > 0) {
			
			dbg_net("udp: on fd=%d, sending answer size=%zd.\n",
			        fd, resp_len);
			
			// Send datagram
			rc = sendto(fd, rq->buf, resp_len, 0,
			            (struct sockaddr *)&rq->addr, rq->addr.len);
			if (rc != (int)resp_len) {
				dbg_net("udp: sendto(): failed: %d - %d.\n",
				        rc, errno);
			}
		}
	}
	
	return rc;
}

#ifdef ENABLE_RECVMMSG

/*! \brief Pointer to selected UDP send implementation. */
static int (*_send_mmsg)(int, sockaddr_t *, struct mmsghdr *, size_t) = 0;

/*!
 * \brief Send multiple packets.
 * 
 * Basic, sendto() based implementation.
 */
int udp_sendto(int sock, sockaddr_t * addrs, struct mmsghdr *msgs, size_t count)
{
	for (unsigned i = 0; i < count; ++i) {
		
		const size_t resp_len = msgs[i].msg_len;
		if (resp_len > 0) {
			dbg_net("udp: on fd=%d, sending answer size=%zd.\n",
			        sock, resp_len);

			// Send datagram
			sockaddr_t *addr = addrs + i;
			struct iovec *cvec = msgs[i].msg_hdr.msg_iov;
			int res = sendto(sock, cvec->iov_base, resp_len,
					 0, (struct sockaddr*)addr, addr->len);

			// Check result
			if (res != (int)resp_len) {
				dbg_net("udp: sendto(): failed: %d - %d.\n",
				        res, errno);
			}
		}
	}
	
	return KNOT_EOK;
}

#ifdef ENABLE_SENDMMSG
/*! \brief sendmmsg() syscall interface. */
#ifndef HAVE_SENDMMSG
static inline int sendmmsg(int fd, struct mmsghdr *mmsg, unsigned vlen,
                           unsigned flags)
{
	return syscall(SYS_sendmmsg, fd, mmsg, vlen, flags, NULL);
}
#endif

/*!
 * \brief Send multiple packets.
 * 
 * sendmmsg() implementation.
 */
int udp_sendmmsg(int sock, sockaddr_t *_, struct mmsghdr *msgs, size_t count)
{
	UNUSED(_);
	dbg_net("udp: sending multiple responses\n");
	if (sendmmsg(sock, msgs, count, 0) < 0) {
		return KNOT_ERROR;
	}
	
	return KNOT_EOK;
}
#endif

/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	char *iobuf;
	sockaddr_t *addrs;
	struct iovec *iov;
	struct mmsghdr *msgs;
	unsigned slip;
};

static void *udp_recvmmsg_init(void)
{
	struct udp_recvmmsg *rq = malloc(sizeof(struct udp_recvmmsg));
	if (rq) {
		rq->iobuf = malloc(SOCKET_MTU_SZ * RECVMMSG_BATCHLEN);
		rq->addrs = malloc(sizeof(sockaddr_t) * RECVMMSG_BATCHLEN);
		rq->iov = malloc(sizeof(struct iovec) * RECVMMSG_BATCHLEN);
		rq->msgs = malloc(sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		if (!rq->iobuf || !rq->addrs || !rq->iov || !rq->msgs) {
			free(rq->iobuf);
			free(rq->addrs);
			free(rq->iov);
			free(rq->msgs);
			free(rq);
			return NULL;
		}
		memset(rq->msgs, 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		for (unsigned i = 0; i < RECVMMSG_BATCHLEN; ++i) {
			sockaddr_prep(rq->addrs + i);
			rq->iov[i].iov_base = rq->iobuf + i * SOCKET_MTU_SZ;
			rq->iov[i].iov_len = SOCKET_MTU_SZ;
			rq->msgs[i].msg_hdr.msg_iov = rq->iov + i;
			rq->msgs[i].msg_hdr.msg_iovlen = 1;
			rq->msgs[i].msg_hdr.msg_name = rq->addrs + i;
			rq->msgs[i].msg_hdr.msg_namelen = rq->addrs[i].len;
		}
		rq->slip = 0;
	}
	return rq;
}

static int udp_recvmmsg_deinit(void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	if (rq) {
		free(rq->iobuf);
		free(rq->addrs);
		free(rq->iov);
		free(rq->msgs);
		free(rq);
	}
	return 0;
}

static int udp_recvmmsg_handle(server_t *s, int fd, void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;

	/* Loop until all data is read. */
	int rc = 0;
	ssize_t n = 0;
	while (n >= 0) {

		/* Receive multiple messages. */
		n = recvmmsg(fd, rq->msgs, RECVMMSG_BATCHLEN, MSG_DONTWAIT, 0);

		/* Error and interrupt handling. */
		if (knot_unlikely(n <= 0)) {
			break;
		}

		/* Handle each received msg. */
		int ret = 0;
		for (unsigned i = 0; i < n; ++i) {
			struct iovec *cvec = rq->msgs[i].msg_hdr.msg_iov;
			size_t resp_len = rq->msgs[i].msg_len;
			ret = udp_handle(fd, cvec->iov_base, resp_len, &resp_len,
			                 rq->addrs + i, s->nameserver, s->rrl, &rq->slip);
			if (ret == KNOT_EOK) {
				rq->msgs[i].msg_len = resp_len;
				rq->iov[i].iov_len = resp_len;
			} else {
				rq->msgs[i].msg_len = 0;
				rq->iov[i].iov_len = 0;
			}
			
		}

		/* Gather results. */
		rc = _send_mmsg(fd, rq->addrs, rq->msgs, n);
		
		/* Reset iov buffer size. */
		for (unsigned i = 0; i < n; ++i) {
			rq->iov[i].iov_len = SOCKET_MTU_SZ;
		}
	}

	return rc;
}
#endif

/*! \brief Initialize UDP master routine on run-time. */
void __attribute__ ((constructor)) udp_master_init()
{
	/* Initialize defaults. */
	_udp_init = udp_recvfrom_init;
	_udp_deinit = udp_recvfrom_deinit;
	_udp_handle = udp_recvfrom_handle;

	/* Optimized functions. */
#ifdef ENABLE_RECVMMSG
	/* Check for recvmmsg() support. */
	if (dlsym(RTLD_DEFAULT, "recvmmsg") != 0) {
		recvmmsg(0, NULL, 0, 0, 0);
		if (errno != ENOSYS) {
			_udp_init = udp_recvmmsg_init;
			_udp_deinit = udp_recvmmsg_deinit;
			_udp_handle = udp_recvmmsg_handle;
		}
	}
	
	/* Check for sendmmsg() support. */
	_send_mmsg = udp_sendto;
#ifdef ENABLE_SENDMMSG
	sendmmsg(0, 0, 0, 0); /* Just check if syscall exists */
	if (errno != ENOSYS) {
		_send_mmsg = udp_sendmmsg;
	}
#endif /* ENABLE_SENDMMSG */
#endif /* ENABLE_RECVMMSG */
}
	
	
int udp_master(dthread_t *thread)
{
	/* Drop all capabilities on workers. */
#ifdef HAVE_CAP_NG_H
	if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
		capng_clear(CAPNG_SELECT_BOTH);
		capng_apply(CAPNG_SELECT_BOTH);
	}
#endif /* HAVE_CAP_NG_H */

	int cpcount = dt_online_cpus();
	if (cpcount > 0) {
		unsigned cpu = dt_get_id(thread) % cpcount;
		dt_setaffinity(thread, &cpu, 1);
	}

	/* Execute proper handler. */
	dbg_net_verb("udp: thread started (worker %p).\n", thread);
	iostate_t *st = (iostate_t *)thread->data;
	if (!st) {
		dbg_net("udp: invalid parameters for udp_master_recvfrom\n");
		return KNOT_EINVAL;
	}
	
	iohandler_t *h = st->h;
	server_t *server = h->server;
	
	/* Allocate buffer for answering. */
	void *rqdata = _udp_init();
	
	/* Prepare structures for bound sockets. */
	fdset_it_t it;
	fdset_t *fds = NULL;
	iface_t *i = NULL;
	ifacelist_t *ifaces = NULL;

	/* Loop until all data is read. */
	for (;;) {
		
		/* Check handler state. */
		if (knot_unlikely(st->s & ServerReload)) {
			st->s &= ~ServerReload;
			rcu_read_lock();
			fdset_destroy(fds);
			fds = fdset_new();
			ref_release((ref_t *)ifaces);
			ifaces = h->server->ifaces;
			if (ifaces) {
				WALK_LIST(i, ifaces->l) {
					fdset_add(fds, i->fd[IO_UDP], OS_EV_READ);
				}
				
			}
			rcu_read_unlock();
		}
		
		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}
		
		/* Wait for events. */
		int nfds = fdset_wait(fds, OS_EV_FOREVER);
		if (nfds <= 0) {
			if (nfds == EINTR) continue;
			break;
		}
		
		fdset_begin(fds, &it);
		while(nfds > 0) {
			_udp_handle(server, it.fd, rqdata);
			if (fdset_next(fds, &it) != 0) {
				break;
			}
		}
	}
	
	fdset_destroy(fds);
	ref_release((ref_t *)ifaces);
	_udp_deinit(rqdata);

	dbg_net_verb("udp: worker %p finished.\n", thread);
	
	return KNOT_EOK;
}

