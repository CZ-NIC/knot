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

#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/param.h>
#include <urcu.h>
#ifdef HAVE_SYS_UIO_H /* 'struct iovec' for OpenBSD */
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "knot/server/udp-handler.h"
#include "knot/server/server.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/internal/mempattern.h"
#include "libknot/internal/macros.h"
#include "libknot/libknot.h"
#include "libknot/processing/overlay.h"
#include "contrib/ucw/mempool.h"

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

/*! \brief UDP context data. */
typedef struct udp_context {
	struct knot_overlay overlay; /*!< Query processing overlay. */
	server_t *server;            /*!< Name server structure. */
	unsigned thread_id;          /*!< Thread identifier. */
} udp_context_t;

/* FD_COPY macro compat. */
#ifndef FD_COPY
#define FD_COPY(src, dest) memcpy((dest), (src), sizeof(fd_set))
#endif

/* Mirror mode (no answering). */
/* #define MIRROR_MODE 1 */

/* PPS measurement. */
/* #define MEASURE_PPS 1 */

/* Next-gen packet processing API. */
#define PACKET_NG
#ifdef PACKET_NG
#include "knot/nameserver/process_query.h"
#endif

/* PPS measurement */
#ifdef MEASURE_PPS

/* Not thread-safe, used only for RX thread. */
static struct timeval __pps_t0, __pps_t1;
volatile static unsigned __pps_rx = 0;
static inline void udp_pps_begin()
{
	gettimeofday(&__pps_t0, NULL);
}

static inline void udp_pps_sample(unsigned n, unsigned thr_id)
{
	__pps_rx += n;
	if (thr_id == 0) {
		gettimeofday(&__pps_t1, NULL);
		if (time_diff(&__pps_t0, &__pps_t1) >= 1000.0) {
			unsigned pps = __pps_rx;
			memcpy(&__pps_t0, &__pps_t1, sizeof(struct timeval));
			__pps_rx = 0;
			log_server_info("RX rate %u packets/second", pps);
		}
	}
}
#else
static inline void udp_pps_begin() {}
static inline void udp_pps_sample(unsigned n, unsigned thr_id) {}
#endif

void udp_handle(udp_context_t *udp, int fd, struct sockaddr_storage *ss,
                struct iovec *rx, struct iovec *tx)
{
	/* Create query processing parameter. */
	struct process_query_param param = {0};
	param.remote = ss;
	param.proc_flags  = NS_QUERY_NO_AXFR|NS_QUERY_NO_IXFR; /* No transfers. */
	param.proc_flags |= NS_QUERY_LIMIT_SIZE; /* Enforce UDP packet size limit. */
	param.proc_flags |= NS_QUERY_LIMIT_ANY;  /* Limit ANY over UDP (depends on zone as well). */
	param.socket = fd;
	param.server = udp->server;
	param.thread_id = udp->thread_id;

	/* Rate limit is applied? */
	if (unlikely(udp->server->rrl != NULL) && udp->server->rrl->rate > 0) {
		param.proc_flags |= NS_QUERY_LIMIT_RATE;
	}

	/* Create packets. */
	mm_ctx_t *mm = udp->overlay.mm;
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, mm);
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, mm);

	/* Create query processing context. */
	knot_overlay_init(&udp->overlay, mm);
	knot_overlay_add(&udp->overlay, NS_PROC_QUERY, &param);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	int state = knot_overlay_consume(&udp->overlay, query);

	/* Process answer. */
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_overlay_produce(&udp->overlay, ans);
	}

	/* Send response only if finished successfuly. */
	if (state == KNOT_STATE_DONE) {
		tx->iov_len = ans->size;
	} else {
		tx->iov_len = 0;
	}

	/* Reset after processing. */
	knot_overlay_finish(&udp->overlay);
	knot_overlay_deinit(&udp->overlay);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);
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
static int (*_udp_handle)(udp_context_t *, void *) = 0;
static int (*_udp_send)(void *) = 0;

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	int fd;
	struct sockaddr_storage addr;
	struct msghdr msg[NBUFS];
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
};

static void *udp_recvfrom_init(void)
{
	struct udp_recvfrom *rq = malloc(sizeof(struct udp_recvfrom));
	if (rq == NULL) {
		return NULL;
	}

	memset(rq, 0, sizeof(struct udp_recvfrom));
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->buf + i;
		rq->iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		rq->msg[i].msg_name = &rq->addr;
		rq->msg[i].msg_namelen = sizeof(rq->addr);
		rq->msg[i].msg_iov = &rq->iov[i];
		rq->msg[i].msg_iovlen = 1;
		rq->msg[i].msg_control = NULL;
		rq->msg[i].msg_controllen = 0;
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
	/* Reset max lengths. */
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	rq->iov[RX].iov_len = KNOT_WIRE_MAX_PKTSIZE;
	rq->msg[RX].msg_namelen = sizeof(struct sockaddr_storage);

	int ret = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
	if (ret > 0) {
		rq->fd = fd;
		rq->iov[RX].iov_len = ret;
		return 1;
	}

	return 0;
}

static int udp_recvfrom_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;

	/* Prepare TX address. */
	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;
	rq->iov[TX].iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Process received pkt. */
	udp_handle(ctx, rq->fd, &rq->addr, &rq->iov[RX], &rq->iov[TX]);

	return KNOT_EOK;
}

static int udp_recvfrom_send(void *d)
{
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	int rc = 0;
	if (rq->iov[TX].iov_len > 0) {
		rc = sendmsg(rq->fd, &rq->msg[TX], 0);
	}

	/* Return number of packets sent. */
	if (rc > 1) {
		return 1;
	}

	return 0;
}

#ifdef HAVE_RECVMMSG

/*! \brief Pointer to selected UDP send implementation. */
static int (*_send_mmsg)(int, struct sockaddr *, struct mmsghdr *, size_t) = 0;

/*!
 * \brief Send multiple packets.
 *
 * Basic, sendmsg() based implementation.
 */
int udp_sendmsg(int sock, struct sockaddr *addrs, struct mmsghdr *msgs, size_t count)
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
#endif /* HAVE_SENDMMSG */

/*!
 * \brief Send multiple packets.
 *
 * sendmmsg() implementation.
 */
int udp_sendmmsg(int sock, struct sockaddr *_, struct mmsghdr *msgs, size_t count)
{
	UNUSED(_);
	return sendmmsg(sock, msgs, count, 0);
}
#endif /* ENABLE_SENDMMSG */

/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	int fd;
	struct sockaddr_storage *addrs;
	char *iobuf[NBUFS];
	struct iovec *iov[NBUFS];
	struct mmsghdr *msgs[NBUFS];
	unsigned rcvd;
	mm_ctx_t mm;
};

static void *udp_recvmmsg_init(void)
{
	mm_ctx_t mm;
	mm_ctx_mempool(&mm, sizeof(struct udp_recvmmsg));

	struct udp_recvmmsg *rq = mm.alloc(mm.ctx, sizeof(struct udp_recvmmsg));
	memcpy(&rq->mm, &mm, sizeof(mm_ctx_t));

	/* Initialize addresses. */
	rq->addrs = mm.alloc(mm.ctx, sizeof(struct sockaddr_storage) * RECVMMSG_BATCHLEN);
	memset(rq->addrs, 0, sizeof(struct sockaddr_storage) * RECVMMSG_BATCHLEN);

	/* Initialize buffers. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iobuf[i] = mm.alloc(mm.ctx, KNOT_WIRE_MAX_PKTSIZE * RECVMMSG_BATCHLEN);
		rq->iov[i] = mm.alloc(mm.ctx, sizeof(struct iovec) * RECVMMSG_BATCHLEN);
		rq->msgs[i] = mm.alloc(mm.ctx, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		memset(rq->msgs[i], 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
			rq->iov[i][k].iov_base = rq->iobuf[i] + k * KNOT_WIRE_MAX_PKTSIZE;
			rq->iov[i][k].iov_len = KNOT_WIRE_MAX_PKTSIZE;
			rq->msgs[i][k].msg_hdr.msg_iov = rq->iov[i] + k;
			rq->msgs[i][k].msg_hdr.msg_iovlen = 1;
			rq->msgs[i][k].msg_hdr.msg_name = rq->addrs + k;
			rq->msgs[i][k].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		}
	}

	return rq;
}

static int udp_recvmmsg_deinit(void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	if (rq) {
		mp_delete(rq->mm.ctx);
	}

	return 0;
}

static int udp_recvmmsg_recv(int fd, void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	int n = recvmmsg(fd, rq->msgs[RX], RECVMMSG_BATCHLEN, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->fd = fd;
		rq->rcvd = n;
	}
	return n;
}

static int udp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;

	/* Handle each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = rq->msgs[RX][i].msg_len; /* Received bytes. */

		udp_handle(ctx, rq->fd, rq->addrs + i, rx, tx);
		rq->msgs[TX][i].msg_len = tx->iov_len;
		rq->msgs[TX][i].msg_hdr.msg_namelen = 0;
		if (tx->iov_len > 0) {
			/* @note sendmmsg() workaround to prevent sending the packet */
			rq->msgs[TX][i].msg_hdr.msg_namelen = rq->msgs[RX][i].msg_hdr.msg_namelen;
		}
	}

	return KNOT_EOK;
}

static int udp_recvmmsg_send(void *d)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *)d;
	int rc = _send_mmsg(rq->fd, (struct sockaddr *)rq->addrs, rq->msgs[TX], rq->rcvd);
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		/* Reset buffer size and address len. */
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = KNOT_WIRE_MAX_PKTSIZE; /* Reset RX buflen */
		tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

		memset(rq->addrs + i, 0, sizeof(struct sockaddr_storage));
		rq->msgs[RX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		rq->msgs[TX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
	}
	return rc;
}
#endif /* HAVE_RECVMMSG */

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
#ifdef HAVE_RECVMMSG
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
#endif /* HAVE_RECVMMSG */
}

/*! \brief Release the reference on the interface list and clear watched fdset. */
static void forget_ifaces(ifacelist_t *ifaces, fd_set *set, int maxfd)
{
	ref_release((ref_t *)ifaces);
	FD_ZERO(set);
}

/*! \brief Add interface sockets to the watched fdset. */
static void track_ifaces(ifacelist_t *ifaces, fd_set *set,
                         int *maxfd, int *minfd, int thrid)
{
	assert(ifaces && set && maxfd && minfd);

	FD_ZERO(set);
	*maxfd = 0;
	*minfd = FD_SETSIZE - 1;

	iface_t *iface = NULL;
	WALK_LIST(iface, ifaces->l) {
#ifdef ENABLE_REUSEPORT
		int fd = iface->fd_udp[thrid % iface->fd_udp_count];
#else
		int fd = iface->fd_udp[0];
#endif
		*maxfd = MAX(fd, *maxfd);
		*minfd = MIN(fd, *minfd);
		FD_SET(fd, set);
	}
}

int udp_master(dthread_t *thread)
{
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = (dt_get_id(thread) % cpu);
		dt_setaffinity(thread, &cpu_mask, 1);
	}

	/* Drop all capabilities on all workers. */
#ifdef HAVE_CAP_NG_H
        if (capng_have_capability(CAPNG_EFFECTIVE, CAP_SETPCAP)) {
                capng_clear(CAPNG_SELECT_BOTH);
                capng_apply(CAPNG_SELECT_BOTH);
        }
#endif /* HAVE_CAP_NG_H */

	/* Prepare structures for bound sockets. */
	unsigned thr_id = dt_get_id(thread);
	iohandler_t *handler = (iohandler_t *)thread->data;
	unsigned *iostate = &handler->thread_state[thr_id];
	void *rq = _udp_init();
	ifacelist_t *ref = NULL;

	/* Create UDP answering context. */
	udp_context_t udp;
	memset(&udp, 0, sizeof(udp_context_t));
	udp.server = handler->server;
	udp.thread_id = handler->thread_id[thr_id];

	/* Create big enough memory cushion. */
	mm_ctx_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);
	udp.overlay.mm = &mm;

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
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;
			udp.thread_id = handler->thread_id[thr_id];

			rcu_read_lock();
			forget_ifaces(ref, &fds, maxfd);
			ref = handler->server->ifaces;
			track_ifaces(ref, &fds, &maxfd, &minfd, udp.thread_id);
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
				if ((rcvd = _udp_recv(fd, rq)) > 0) {
					_udp_handle(&udp, rq);
					/* Flush allocated memory. */
					mp_flush(mm.ctx);
					_udp_send(rq);
					udp_pps_sample(rcvd, thr_id);
				}
			}
		}
	}

	_udp_deinit(rq);
	forget_ifaces(ref, &fds, maxfd);
	mp_delete(mm.ctx);
	return KNOT_EOK;
}
