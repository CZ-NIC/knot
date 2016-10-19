/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/common/fdset.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

/*! \brief UDP context data. */
typedef struct {
	knot_mm_t mm;
	void *rq;
	knot_layer_t layer; /*!< Query processing layer. */
	struct process_query_param param;
	knot_pkt_t *query;
	knot_pkt_t *ans;
} udp_context_t;

static void udp_handle(udp_context_t *udp, int fd, struct sockaddr_storage *ss,
                       struct iovec *rx, struct iovec *tx)
{
	int state = udp->layer.state;

	if (udp->layer.defer_fd.fd == 0) {
		/* Create query processing parameter. */
		udp->param.proc_flags = 0;
		udp->param.remote = ss;
		udp->param.proc_flags  = NS_QUERY_NO_AXFR|NS_QUERY_NO_IXFR; /* No transfers. */
		udp->param.proc_flags |= NS_QUERY_LIMIT_SIZE; /* Enforce UDP packet size limit. */
		udp->param.proc_flags |= NS_QUERY_LIMIT_ANY;  /* Limit ANY over UDP (depends on zone as well). */
		udp->param.socket = fd;

		/* Rate limit is applied? */
		if (unlikely(udp->param.server->rrl != NULL) && udp->param.server->rrl->rate > 0) {
			udp->param.proc_flags |= NS_QUERY_LIMIT_RATE;
		}

		/* Start query processing. */
		udp->layer.state = knot_layer_begin(&udp->layer, &udp->param);

		/* Create packets. */
		udp->query = knot_pkt_new(rx->iov_base, rx->iov_len, udp->layer.mm);
		udp->ans = knot_pkt_new(tx->iov_base, tx->iov_len, udp->layer.mm);

		/* Input packet. */
		(void) knot_pkt_parse(udp->query, 0);
		state = knot_layer_consume(&udp->layer, udp->query);
	}

	/* Process answer. */
	while (state & (KNOT_STATE_PRODUCE|KNOT_STATE_FAIL)) {
		state = knot_layer_produce_nonblocking(&udp->layer, udp->ans);
		if (udp->layer.defer_fd.fd) return;
	}

	/* Send response only if finished successfully. */
	if (state == KNOT_STATE_DONE) {
		tx->iov_len = udp->ans->size;
	} else {
		tx->iov_len = 0;
	}

	/* Reset after processing. */
	knot_layer_finish(&udp->layer);

	/* Cleanup. */
	knot_pkt_free(&udp->query);
	knot_pkt_free(&udp->ans);
}

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
	if (cmsg != NULL && cmsg->cmsg_type == IP_PKTINFO) {
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

#ifdef ENABLE_RECVMMSG

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

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr, &rq->msgs[TX][i].msg_hdr);

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
	int rc = sendmmsg(rq->fd, rq->msgs[TX], rq->rcvd, 0);
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
#endif /* ENABLE_RECVMMSG */

/*! \brief Initialize UDP master routine on run-time. */
void __attribute__ ((constructor)) udp_master_init(void)
{
	/* Initialize defaults. */
	_udp_init =   udp_recvfrom_init;
	_udp_deinit = udp_recvfrom_deinit;
	_udp_recv =   udp_recvfrom_recv;
	_udp_handle = udp_recvfrom_handle;
	_udp_send =   udp_recvfrom_send;

#ifdef ENABLE_RECVMMSG
	_udp_init =   udp_recvmmsg_init;
	_udp_deinit = udp_recvmmsg_deinit;
	_udp_recv =   udp_recvmmsg_recv;
	_udp_handle = udp_recvmmsg_handle;
	_udp_send =   udp_recvmmsg_send;
#endif /* ENABLE_RECVMMSG */
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

/*!
 * \brief Make a set of watched descriptors based on the interface list.
 *
 * \param[in]   ifaces  New interface list.
 * \param[in]   thrid   Thread ID.
 * \param[out]  fds     Allocated set of descriptors.
 *
 * \return A Knot error code.
 */
static int track_ifaces(const ifacelist_t *ifaces, int thrid,
                           fdset_t *fds)
{
	assert(ifaces && fds);

	nfds_t nfds = list_size(&ifaces->l);
	if (fds->size == 0) {
		/* Use a modest initial size. */
		int rc = fdset_init(fds, nfds);
		if (rc != KNOT_EOK)
			return rc;
	} else {
		/* Remove any obsolete file descriptors. */
		unsigned i = 0;
		while (i < fds->n) {
			if (fds->ctx[i] == NULL) fdset_remove(fds, i);
			else ++i;
		}
	}

	iface_t *iface = NULL;
	WALK_LIST(iface, ifaces->l) {
		fdset_add(fds, iface_udp_fd(iface, thrid), POLLIN, NULL);
	}
	assert(fds->n >= nfds);

	return KNOT_EOK;
}

static udp_context_t *udp_setup(udp_context_t *udp,
                                server_t *server, unsigned thread_id) {
	if (udp != NULL) return udp;

	udp = malloc(sizeof(*udp));
	if (udp == NULL) return NULL;

	memset(udp, 0, sizeof(udp_context_t));
	udp->rq = _udp_init();
	udp->param.server = server;
	udp->param.thread_id = thread_id;
	udp->param.layer = &udp->layer;
	knot_layer_init(&udp->layer, &udp->mm, process_query_layer());

	/* Create big enough memory cushion. */
	mm_ctx_mempool(&udp->mm, 16 * MM_DEFAULT_BLKSIZE);

	return udp;
}

static void udp_cleanup(udp_context_t *udp) {
	if (udp->layer.defer_fd.fd) {
		/* Ask the module to clean up its resources. */
		udp->layer.defer_fd.fd = 0;
		_udp_handle(udp, udp->rq);
	}

	_udp_deinit(udp->rq);
	mp_delete(udp->mm.ctx);
}

/* Returns main_udp if it is available for reuse, or NULL if main_udp has
 * been assigned to a deferred query. */
static udp_context_t *handle_udp_event(udp_context_t *main_udp,
                                       fdset_t *fds, nfds_t i) {
	udp_context_t *udp = fds->ctx[i];
	if (udp == NULL) {
		/* This event is an incoming query. */
		if (_udp_recv(fds->pfd[i].fd, main_udp->rq) <= 0)
			return main_udp;
		udp = main_udp;
	}

	udp->layer.defer_fd.revents = fds->pfd[i].revents;
	_udp_handle(udp, udp->rq);

	if (udp->layer.defer_fd.fd) {
		if (udp == main_udp) {
			/* This is the first time this query is being
			 * deferred.  Move it into the deferred set. */
			int i = fdset_add(fds, udp->layer.defer_fd.fd,
					  udp->layer.defer_fd.events, udp);
			if (i < 0) {
				/* Failed to add fd. */
				udp->layer.defer_fd.fd = -1;
				_udp_handle(udp, udp->rq);
				udp->layer.defer_fd.fd = 0;
				return main_udp;
			}

			fdset_set_watchdog(fds, i, udp->layer.defer_timeout);
			return NULL;
		} else {
			/* The file descriptor and/or timeout value may have
			 * changed.  Update the fdset accordingly. */
			fds->pfd[i].fd = udp->layer.defer_fd.fd;
			fds->pfd[i].events = udp->layer.defer_fd.events;
			fdset_set_watchdog(fds, i, udp->layer.defer_timeout);
			return main_udp;
		}
	}

	/* Flush allocated memory. */
	mp_flush(udp->mm.ctx);
	_udp_send(udp->rq);

	if (udp != main_udp) {
		/* Remove the query from the deferred set. */
		fdset_remove(fds, i);
		udp_cleanup(udp);
		free(udp);
	}

	return main_udp;
}

static enum fdset_sweep_state sweep_cb(fdset_t* fds, int i, void* data) {
	udp_context_t *udp = fds->ctx[i];

	/* udp will never be NULL because the sweep callback is only
	 * called when timeouts occur, and timeouts are only set on
	 * file descriptors for deferred queries. */
	assert(udp != NULL);

	udp->layer.defer_timeout = -1;
	_udp_handle(udp, udp->rq);

	if (udp->layer.defer_fd.fd) {
		return FDSET_KEEP;
	}

	return FDSET_SWEEP;
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
	ifacelist_t *ref = NULL;
	udp_context_t *udp = NULL;

	/* Event source. */
	fdset_t fds;
	fdset_init(&fds, 0);

	/* Loop until all data is read. */
	for (;;) {

		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;
			if(udp) udp->param.thread_id = handler->thread_id[thr_id];

			rcu_read_lock();
			ref_release((ref_t *)ref);
			ref = handler->server->ifaces;
			track_ifaces(ref, handler->thread_id[thr_id], &fds);
			rcu_read_unlock();
			if (fds.n == 0) {
				break;
			}
		}

		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Check whether there are pending timeouts.  If so,
		 * we need to use a positive poll() timeout value. */
		int timeout = -1;
		for (int i=0; i < fds.n; ++i) {
			if (fds.timeout[i] > 0) {
				timeout = 2;
				break;
			}
		}

		/* Make sure we have a UDP context ready. */
		udp = udp_setup(udp, handler->server, handler->thread_id[thr_id]);
		if (udp == NULL) break;

		/* Wait for events. */
		int events = poll(fds.pfd, fds.n, timeout);
		if (events <= 0) {
			if (errno == EINTR) continue;
			break;
		}

		/* Process the events.  This must be done in reverse
                 * order so that handle_udp_event() may safely add or
                 * remove entries. */
		for (int i = fds.n-1; i >= 0 && events > 0; i--) {
			if (fds.pfd[i].revents == 0) {
				continue;
			}
			events -= 1;

			udp = udp_setup(udp, handler->server,
				handler->thread_id[thr_id]);
			if (udp == NULL) break;

			udp = handle_udp_event(udp, &fds, i);
		}

		/* Handle timeouts. */
		fdset_sweep(&fds, sweep_cb, NULL);
	}

	/* Drop any remaining deferred queries. */
	for (int i=0; i < fds.n; ++i) {
		udp_context_t *_udp = fds.ctx[i];
		if (_udp == NULL) continue;
		udp_cleanup(_udp);
		free(_udp);
	}

	if(udp) udp_cleanup(udp);
	ref_release((ref_t *)ref);
	fdset_clear(&fds);
	return KNOT_EOK;
}
