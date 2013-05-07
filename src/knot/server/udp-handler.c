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
#include <limits.h>
#include <sys/param.h>
#ifdef HAVE_SYS_UIO_H /* 'struct iovec' for OpenBSD */
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common/queue.h"
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

/* FD_COPY macro compat. */
#ifndef FD_COPY
#define FD_COPY(src, dest) memcpy((dest), (src), sizeof(fd_set))
#endif

/* Mirror mode (no answering). */
/* #define MIRROR_MODE 1 */

/* PPS measurement. */
/* #define MEASURE_PPS 1 */

/* PPS measurement */
#ifdef MEASURE_PPS

/* Not thread-safe, used only for RX thread. */
static struct timeval __pps_t0, __pps_t1;
volatile static unsigned __pps_rx = 0;
static inline void udp_pps_begin()
{
	gettimeofday(&__pps_t0, NULL);
}

static inline void udp_pps_sample(unsigned n)
{
	__pps_rx += n;
	gettimeofday(&__pps_t1, NULL);
	if (time_diff(&__pps_t0, &__pps_t1) >= 1000.0) {
		unsigned pps = __pps_rx;
		memcpy(&__pps_t0, &__pps_t1, sizeof(struct timeval));
		__pps_rx = 0;
		log_server_info("RX rate %u p/s.\n", pps);
	}
}
#else
static inline void udp_pps_begin() {}
static inline void udp_pps_sample(unsigned n) {}
#endif

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
               sockaddr_t* addr, knot_nameserver_t *ns, rrl_table_t *rrl,
               unsigned *slip)
{
#ifdef DEBUG_ENABLE_BRIEF
	char strfrom[SOCKADDR_STRLEN];
	memset(strfrom, 0, sizeof(strfrom));
	sockaddr_tostr(addr, strfrom, sizeof(strfrom));
	dbg_net("udp: received %zd bytes from '%s@%d'.\n", qbuflen,
	        strfrom, sockaddr_portnum(addr));
#endif

	int res = KNOT_EOK;
	int rcode = KNOT_RCODE_NOERROR;
	knot_packet_type_t qtype = KNOT_QUERY_INVALID;
	*resp_len = SOCKET_MTU_SZ;

#ifdef MIRROR_MODE
	knot_wire_set_qr(qbuf);
	*resp_len = qbuflen;
	return KNOT_EOK;
#endif

	knot_packet_t *packet = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (packet == NULL) {
		dbg_net("udp: failed to create packet\n");
		int ret = knot_ns_error_response_from_query_wire(ns, qbuf, qbuflen,
		                                            KNOT_RCODE_SERVFAIL,
		                                            qbuf, resp_len);
		return ret;
	}

	/* Parse query. */
	rcode = knot_ns_parse_packet(qbuf, qbuflen, packet, &qtype);
	if (rcode < KNOT_RCODE_NOERROR) {
		dbg_net("udp: failed to parse packet\n");
		rcode = KNOT_RCODE_SERVFAIL;
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
		res = knot_ns_error_response_from_query(ns, packet,
		                                        KNOT_RCODE_FORMERR, qbuf,
		                                        resp_len);
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

	/* Do not issue response to incoming response to avoid loops. */
	case KNOT_RESPONSE_AXFR: /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_IXFR: /*!< Processed in XFR handler. */
	case KNOT_RESPONSE_NORMAL:
	case KNOT_RESPONSE_NOTIFY:
	case KNOT_RESPONSE_UPDATE:
		res = KNOT_EOK;
		*resp_len = 0;
		break;
	/* Unknown opcodes */
	default:
		res = knot_ns_error_response_from_query(ns, packet,
		                                        rcode, qbuf,
		                                        resp_len);
		break;
	}

	/* Process RRL. */
	if (knot_unlikely(rrl != NULL)) {
		rrl_req_t rrl_rq;
		memset(&rrl_rq, 0, sizeof(rrl_req_t));
		rrl_rq.w = qbuf; /* Wire */
		rrl_rq.qst = &packet->question;

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
static int (*_udp_recv)(int, void *) = 0;
static int (*_udp_handle)(server_t *, void *, unsigned *) = 0;
static int (*_udp_send)(void *) = 0;

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	int fd;
	sockaddr_t addr;
	struct msghdr msg;
	struct iovec iov;
	uint8_t buf[SOCKET_MTU_SZ];
	size_t buflen;
};

static void *udp_recvfrom_init(void)
{
	struct udp_recvfrom *rq = malloc(sizeof(struct udp_recvfrom));
	if (rq) {
		sockaddr_prep(&rq->addr);
		rq->buflen = SOCKET_MTU_SZ;
		rq->iov.iov_base = rq->buf;
		rq->iov.iov_len = rq->buflen;
		rq->msg.msg_name = &rq->addr;
		rq->msg.msg_namelen = rq->addr.len;
		rq->msg.msg_iov = &rq->iov;
		rq->msg.msg_iovlen = 1;
		rq->msg.msg_control = NULL;
		rq->msg.msg_controllen = 0;
	}
	return rq;
}

static int udp_recvfrom_deinit(void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	free(rq);
	return 0;
}

static int udp_recvfrom_recv(int fd, void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	int ret = recvmsg(fd, &rq->msg, MSG_DONTWAIT);
	if (ret > 0) {
		rq->fd = fd;
		rq->buflen = ret;
		return 1;
	}

	return 0;
}

static int udp_recvfrom_handle(server_t *s, void *d, unsigned *slip)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;

	/* Process received pkt. */
	rq->addr.len = rq->msg.msg_namelen;
	int ret = udp_handle(rq->fd, rq->buf, rq->buflen, &rq->iov.iov_len, &rq->addr,
	                     s->nameserver, s->rrl, slip);
	if (ret != KNOT_EOK) {
		rq->iov.iov_len = 0;
	}

	return ret;
}

static int udp_recvfrom_send(void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	int rc = 0;
	if (rq->iov.iov_len > 0) {
		rc = sendmsg(rq->fd, &rq->msg, 0);
	}

	/* Reset buffer size and address len. */
	rq->iov.iov_len = SOCKET_MTU_SZ;
	sockaddr_prep(&rq->addr);
	rq->msg.msg_namelen = rq->addr.len;

	/* Return number of packets sent. */
	if (rc > 1) {
		return 1;
	}

	return 0;
}

#ifdef ENABLE_RECVMMSG

/*! \brief Pointer to selected UDP send implementation. */
static int (*_send_mmsg)(int, sockaddr_t *, struct mmsghdr *, size_t) = 0;

/*!
 * \brief Send multiple packets.
 *
 * Basic, sendmsg() based implementation.
 */
int udp_sendmsg(int sock, sockaddr_t * addrs, struct mmsghdr *msgs, size_t count)
{
	int sent = 0;
	for (unsigned i = 0; i < count; ++i) {
		if (sendmsg(sock, &msgs[i].msg_hdr, 0) > 0) {
			++sent;
		}
	}

	return sent;
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
	return sendmmsg(sock, msgs, count, 0);
}
#endif

/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	int fd;
	char *iobuf;
	sockaddr_t *addrs;
	struct iovec *iov;
	struct mmsghdr *msgs;
	unsigned rcvd;
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

static int udp_recvmmsg_recv(int fd, void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	int n = recvmmsg(fd, rq->msgs, RECVMMSG_BATCHLEN, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->fd = fd;
		rq->rcvd = n;
	}
	return n;
}

static int udp_recvmmsg_handle(server_t *s, void *d, unsigned *slip)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;

	/* Handle each received msg. */
	int ret = 0;
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *cvec = rq->msgs[i].msg_hdr.msg_iov;
		size_t rlen = 0;
		rq->addrs[i].len = rq->msgs[i].msg_hdr.msg_namelen;
		ret = udp_handle(rq->fd, cvec->iov_base, rq->msgs[i].msg_len, &rlen,
		                 rq->addrs + i, s->nameserver, s->rrl, slip);
		if (ret != KNOT_EOK) { /* Do not send. */
			rlen = 0;
		}
		cvec->iov_len = rlen;
	}
	return KNOT_EOK;
}

static int udp_recvmmsg_send(void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	int rc = _send_mmsg(rq->fd, rq->addrs, rq->msgs, rq->rcvd);
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		/* Reset buffer size and address len. */
		struct iovec *cvec = rq->msgs[i].msg_hdr.msg_iov;
		cvec->iov_len = SOCKET_MTU_SZ;

		sockaddr_prep(rq->addrs + i);
		rq->msgs[i].msg_hdr.msg_namelen = rq->addrs[i].len;
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
	_udp_recv = udp_recvfrom_recv;
	_udp_send = udp_recvfrom_send;
	_udp_handle = udp_recvfrom_handle;

	/* Optimized functions. */
#ifdef ENABLE_RECVMMSG
	/* Check for recvmmsg() support. */
	if (dlsym(RTLD_DEFAULT, "recvmmsg") != 0) {
		recvmmsg(0, NULL, 0, 0, 0);
		if (errno != ENOSYS) {
			_udp_init = udp_recvmmsg_init;
			_udp_deinit = udp_recvmmsg_deinit;
			_udp_recv = udp_recvmmsg_recv;
			_udp_send = udp_recvmmsg_send;
			_udp_handle = udp_recvmmsg_handle;
		}
	}

	/* Check for sendmmsg() support. */
	_send_mmsg = udp_sendmsg;
#ifdef ENABLE_SENDMMSG
	sendmmsg(0, 0, 0, 0); /* Just check if syscall exists */
	if (errno != ENOSYS) {
		_send_mmsg = udp_sendmmsg;
	}
#endif /* ENABLE_SENDMMSG */
#endif /* ENABLE_RECVMMSG */
}

struct udpstate_t {
	unsigned rqlen;
	void *rqs[QUEUE_ELEMS - 1];
	queue_t rx, tx;
};

void* udp_create_ctx(void)
{
	struct udpstate_t *ctx = malloc(sizeof(struct udpstate_t));
	if (ctx == NULL) {
		return NULL;
	}
	memset(ctx, 0, sizeof(struct udpstate_t));

	queue_init(&ctx->rx);
	queue_init(&ctx->tx);

	/* Fill queue with empty requests. */
	for (unsigned i = 0; i < QUEUE_ELEMS - 1; ++i) {
		if ((ctx->rqs[i] = _udp_init()) == NULL) {
			break;
		}
		queue_insert(&ctx->rx, ctx->rqs[i]);
		++ctx->rqlen;
	}
	return ctx;
}

void udp_free_ctx(void *ctx)
{
	struct udpstate_t *_ctx = (struct udpstate_t *)ctx;
	queue_deinit(&_ctx->rx);
	queue_deinit(&_ctx->tx);

	/* Free requests. */
	for (unsigned i = 0; i < _ctx->rqlen; ++i) {
		_udp_deinit(_ctx->rqs[i]);
	}
	free(_ctx);
}

int udp_writer(iohandler_t *h, dthread_t *thread)
{
	struct udpstate_t *ctx = (struct udpstate_t *)h->data;
	void *rq = NULL;
	unsigned slip = 0;
	while ((rq = queue_remove(&ctx->tx)) != NULL) {
		_udp_handle(h->server, rq, &slip);
		_udp_send(rq);
		queue_insert(&ctx->rx, rq); /* Return to readq. */
	}

	queue_insert(&ctx->tx, NULL); /* Signalize next to close. */
	return KNOT_EOK;
}

int udp_reader(iohandler_t *h, dthread_t *thread)
{
	/* Bind reader to CPU0. It shouldn't matter much which, but it is good
	 * to bind I/O to single process to avoid context switches.
	 * Moreover CPU0 _usually_ gets most of the interrupts.
	 */
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = 0;
		dt_setaffinity(thread, &cpu_mask, 1);
	}

	iostate_t *st = (iostate_t *)thread->data;
	struct udpstate_t *ctx = (struct udpstate_t *)h->data;

	/* Prepare structures for bound sockets. */
	void *rq = queue_remove(&ctx->rx);
	ifacelist_t *ref = NULL;

	/* Chose select as epoll/kqueue has larger overhead for a
	 * single or handful of sockets. */
	fd_set fds;
	FD_ZERO(&fds);
	int minfd = 0, maxfd = 0;
	int rcvd = 0;

	udp_pps_begin();

	/* Loop until all data is read. */
	for (;;) {

		/* Check handler state. */
		if (knot_unlikely(st->s & ServerReload)) {
			st->s &= ~ServerReload;
			maxfd = 0;
			minfd = INT_MAX;
			FD_ZERO(&fds);

			rcu_read_lock();
			ref_release((ref_t *)ref);
			ref = h->server->ifaces;
			if (ref) {
				iface_t *i = NULL;
				WALK_LIST(i, ref->l) {
					int fd = i->fd[IO_UDP];
					FD_SET(fd, &fds);
					maxfd = MAX(fd, maxfd);
					minfd = MIN(fd, minfd);
				}
			}
			rcu_read_unlock();
		}

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		fd_set rfds;
		FD_COPY(&fds, &rfds);
		int nfds = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (nfds <= 0) {
			if (errno == EINTR) continue;
			break;
		}
		/* Bound sockets will be usually closely coupled. */
		for (unsigned fd = minfd; fd <= maxfd; ++fd) {
			if (FD_ISSET(fd, &rfds)) {
				while ((rcvd = _udp_recv(fd, rq)) > 0) {
					queue_insert(&ctx->tx, rq);
					udp_pps_sample(rcvd);
					rq = queue_remove(&ctx->rx);
				}
			}
		}
	}

	queue_insert(&ctx->rx, rq); /* Return */
	queue_insert(&ctx->tx, NULL);
	ref_release((ref_t *)ref);

	return KNOT_EOK;
}

int udp_master(dthread_t *thread)
{
	/* Drop all capabilities on all workers. */
#ifdef HAVE_CAP_NG_H
        if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
                capng_clear(CAPNG_SELECT_BOTH);
                capng_apply(CAPNG_SELECT_BOTH);
        }
#endif /* HAVE_CAP_NG_H */

	iostate_t *st = (iostate_t *)thread->data;
	if (!st) return KNOT_EINVAL;
	iohandler_t *h = st->h;

	switch(dt_get_id(thread)) {
	case 0: return udp_reader(h, thread);
	default: return udp_writer(h, thread);
	}
}
