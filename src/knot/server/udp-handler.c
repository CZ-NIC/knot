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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <string.h>
#include <assert.h>
#include <sys/param.h>
#include <urcu.h>
#ifdef HAVE_SYS_UIO_H /* 'struct iovec' for OpenBSD */
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/overlay.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"

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

static void udp_handle(udp_context_t *udp, int fd, struct sockaddr_storage *ss,
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

	knot_mm_t *mm = udp->overlay.mm;

	/* Create query processing context. */
	knot_overlay_init(&udp->overlay, mm);
	knot_overlay_add(&udp->overlay, NS_PROC_QUERY, &param);

	/* Create packets. */
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, mm);
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, mm);

	/* Input packet. */
	(void) knot_pkt_parse(query, 0);
	int state = knot_overlay_consume(&udp->overlay, query);

	/* Process answer. */
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_overlay_produce(&udp->overlay, ans);
	}

	/* Send response only if finished successfully. */
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

/*! \brief Control message to fit IP_PKTINFO or IPv6_RECVPKTINFO. */
typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
} cmsg_pktinfo_t;

static void udp_pktinfo_handle(const struct msghdr *rx, struct msghdr *tx)
{
	tx->msg_controllen = rx->msg_controllen;
	if (tx->msg_controllen > 0) {
		tx->msg_control = rx->msg_control;
	} else {
		// BSD has problem with zero length and not-null pointer
		tx->msg_control = NULL;
	}

	#if defined(__APPLE__)
	/*
	 * Workaround for OS X: If ipi_ifindex is non-zero, the source address
	 * will be ignored. We need to use correct one.
	 */
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(tx);
	if (cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		info->ipi_spec_dst = info->ipi_addr;
		info->ipi_ifindex = 0;
	}
	#endif
}

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	int fd;
	struct sockaddr_storage addr;
	struct msghdr msg[NBUFS];
	struct iovec iov[NBUFS];
	uint8_t buf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	cmsg_pktinfo_t pktinfo;
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
		rq->msg[i].msg_control = &rq->pktinfo.cmsg;
		rq->msg[i].msg_controllen = sizeof(rq->pktinfo);
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
	rq->msg[RX].msg_controllen = sizeof(rq->pktinfo);

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

	udp_pktinfo_handle(&rq->msg[RX], &rq->msg[TX]);

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
static int udp_sendmsg(int sock, struct sockaddr *addrs, struct mmsghdr *msgs, size_t count)
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
static int udp_sendmmsg(int sock, struct sockaddr *_, struct mmsghdr *msgs, size_t count)
{
	UNUSED(_);
	return sendmmsg(sock, msgs, count, 0);
}
#endif /* ENABLE_SENDMMSG */

/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	int fd;
	struct sockaddr_storage addrs[RECVMMSG_BATCHLEN];
	char *iobuf[NBUFS];
	struct iovec *iov[NBUFS];
	struct mmsghdr *msgs[NBUFS];
	unsigned rcvd;
	knot_mm_t mm;
	cmsg_pktinfo_t pktinfo[RECVMMSG_BATCHLEN];
};

static void *udp_recvmmsg_init(void)
{
	knot_mm_t mm;
	mm_ctx_mempool(&mm, sizeof(struct udp_recvmmsg));

	struct udp_recvmmsg *rq = mm.alloc(mm.ctx, sizeof(struct udp_recvmmsg));
	memset(rq, 0, sizeof(*rq));
	memcpy(&rq->mm, &mm, sizeof(knot_mm_t));

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
			rq->msgs[i][k].msg_hdr.msg_control = &rq->pktinfo[k].cmsg;
			rq->msgs[i][k].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);
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

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr,&rq->msgs[TX][i].msg_hdr);

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
		rq->msgs[RX][i].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);
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
	recvmmsg(0, NULL, 0, 0, 0);
	if (errno != ENOSYS) {
		_udp_init = udp_recvmmsg_init;
		_udp_deinit = udp_recvmmsg_deinit;
		_udp_recv = udp_recvmmsg_recv;
		_udp_send = udp_recvmmsg_send;
		_udp_handle = udp_recvmmsg_handle;
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

/*! \brief Get interface UDP descriptor for a given thread. */
static int iface_udp_fd(const iface_t *iface, int thread_id)
{
#ifdef ENABLE_REUSEPORT
		return iface->fd_udp[thread_id % iface->fd_udp_count];
#else
		return iface->fd_udp[0];
#endif
}

/*! \brief Release the interface list reference and free watched descriptor set. */
static void forget_ifaces(ifacelist_t *ifaces, struct pollfd **fds_ptr)
{
	ref_release((ref_t *)ifaces);
	free(*fds_ptr);
	*fds_ptr = NULL;
}

/*!
 * \brief Make a set of watched descriptors based on the interface list.
 *
 * \param[in]   ifaces  New interface list.
 * \param[in]   thrid   Thread ID.
 * \param[out]  fds_ptr Allocated set of descriptors.
 *
 * \return Number of watched descriptors, zero on error.
 */
static nfds_t track_ifaces(const ifacelist_t *ifaces, int thrid,
                           struct pollfd **fds_ptr)
{
	assert(ifaces && fds_ptr);

	nfds_t nfds = list_size(&ifaces->l);
	struct pollfd *fds = malloc(nfds * sizeof(*fds));
	if (!fds) {
		*fds_ptr = NULL;
		return 0;
	}

	iface_t *iface = NULL;
	int i = 0;
	WALK_LIST(iface, ifaces->l) {
		fds[i].fd = iface_udp_fd(iface, thrid);
		fds[i].events = POLLIN;
		fds[i].revents = 0;
		i += 1;
	}
	assert(i == nfds);

	*fds_ptr = fds;
	return nfds;
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
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);
	udp.overlay.mm = &mm;

	/* Event source. */
	struct pollfd *fds = NULL;
	nfds_t nfds = 0;

	/* Loop until all data is read. */
	for (;;) {

		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;
			udp.thread_id = handler->thread_id[thr_id];

			rcu_read_lock();
			forget_ifaces(ref, &fds);
			ref = handler->server->ifaces;
			nfds = track_ifaces(ref, udp.thread_id, &fds);
			rcu_read_unlock();
			if (nfds == 0) {
				break;
			}
		}

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		int events = poll(fds, nfds, -1);
		if (events <= 0) {
			if (errno == EINTR) continue;
			break;
		}

		/* Process the events. */
		for (nfds_t i = 0; i < nfds && events > 0; i++) {
			if (fds[i].revents == 0) {
				continue;
			}
			events -= 1;
			int rcvd = 0;
			if ((rcvd = _udp_recv(fds[i].fd, rq)) > 0) {
				_udp_handle(&udp, rq);
				/* Flush allocated memory. */
				mp_flush(mm.ctx);
				_udp_send(rq);
			}
		}
	}

	_udp_deinit(rq);
	forget_ifaces(ref, &fds);
	mp_delete(mm.ctx);
	return KNOT_EOK;
}
