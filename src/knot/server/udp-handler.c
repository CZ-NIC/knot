/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h>
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */
#include <unistd.h>

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/fdset.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/xdp-handler.h"

/* Buffer identifiers. */
enum {
	RX = 0,
	TX = 1,
	NBUFS = 2
};

/*! \brief UDP context data. */
typedef struct {
	knot_layer_t layer; /*!< Query processing layer. */
	server_t *server;   /*!< Name server structure. */
	unsigned thread_id; /*!< Thread identifier. */
} udp_context_t;

static bool udp_state_active(int state)
{
	return (state == KNOT_STATE_PRODUCE || state == KNOT_STATE_FAIL);
}

static void udp_handle(udp_context_t *udp, int fd, struct sockaddr_storage *ss,
                       struct iovec *rx, struct iovec *tx, struct knot_xdp_msg *xdp_msg)
{
	/* Create query processing parameter. */
	knotd_qdata_params_t params = {
		.remote = ss,
		.flags = KNOTD_QUERY_FLAG_NO_AXFR | KNOTD_QUERY_FLAG_NO_IXFR | /* No transfers. */
		         KNOTD_QUERY_FLAG_LIMIT_SIZE, /* Enforce UDP packet size limit. */
		.socket = fd,
		.server = udp->server,
		.xdp_msg = xdp_msg,
		.thread_id = udp->thread_id
	};

	/* Start query processing. */
	knot_layer_begin(&udp->layer, &params);

	/* Create packets. */
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, udp->layer.mm);
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, udp->layer.mm);

	/* Input packet. */
	int ret = knot_pkt_parse(query, 0);
	if (ret != KNOT_EOK && query->parsed > 0) { // parsing failed (e.g. 2x OPT)
		query->parsed--; // artificially decreasing "parsed" leads to FORMERR
	}
	knot_layer_consume(&udp->layer, query);

	/* Process answer. */
	while (udp_state_active(udp->layer.state)) {
		knot_layer_produce(&udp->layer, ans);
	}

	/* Send response only if finished successfully. */
	if (udp->layer.state == KNOT_STATE_DONE) {
		tx->iov_len = ans->size;
	} else {
		tx->iov_len = 0;
	}

	/* Reset after processing. */
	knot_layer_finish(&udp->layer);

	/* Flush per-query memory (including query and answer packets). */
	mp_flush(udp->layer.mm->ctx);
}

typedef struct {
	void* (*udp_init)(void *);
	void (*udp_deinit)(void *);
	int (*udp_recv)(int, void *);
	void (*udp_handle)(udp_context_t *, void *);
	void (*udp_send)(void *);
	void (*udp_sweep)(void *); // Optional
} udp_api_t;

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

#if defined(__linux__) || defined(__APPLE__)
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(tx);
	if (cmsg == NULL) {
		return;
	}

	/* Unset the ifindex to not bypass the routing tables. */
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		info->ipi_spec_dst = info->ipi_addr;
		info->ipi_ifindex = 0;
	} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		info->ipi6_ifindex = 0;
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

static void *udp_recvfrom_init(_unused_ void *xdp_sock)
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

static void udp_recvfrom_deinit(void *d)
{
	struct udp_recvfrom *rq = d;
	free(rq);
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

static void udp_recvfrom_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvfrom *rq = d;

	/* Prepare TX address. */
	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;
	rq->iov[TX].iov_len = KNOT_WIRE_MAX_PKTSIZE;

	udp_pktinfo_handle(&rq->msg[RX], &rq->msg[TX]);

	/* Process received pkt. */
	udp_handle(ctx, rq->fd, &rq->addr, &rq->iov[RX], &rq->iov[TX], NULL);
}

static void udp_recvfrom_send(void *d)
{
	struct udp_recvfrom *rq = d;
	if (rq->iov[TX].iov_len > 0) {
		(void)sendmsg(rq->fd, &rq->msg[TX], 0);
	}
}

_unused_
static udp_api_t udp_recvfrom_api = {
	udp_recvfrom_init,
	udp_recvfrom_deinit,
	udp_recvfrom_recv,
	udp_recvfrom_handle,
	udp_recvfrom_send,
};

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

static void *udp_recvmmsg_init(_unused_ void *xdp_sock)
{
	knot_mm_t mm;
	mm_ctx_mempool(&mm, sizeof(struct udp_recvmmsg));

	struct udp_recvmmsg *rq = mm_alloc(&mm, sizeof(struct udp_recvmmsg));
	memset(rq, 0, sizeof(*rq));
	memcpy(&rq->mm, &mm, sizeof(knot_mm_t));

	/* Initialize buffers. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iobuf[i] = mm_alloc(&mm, KNOT_WIRE_MAX_PKTSIZE * RECVMMSG_BATCHLEN);
		rq->iov[i] = mm_alloc(&mm, sizeof(struct iovec) * RECVMMSG_BATCHLEN);
		rq->msgs[i] = mm_alloc(&mm, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
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

static void udp_recvmmsg_deinit(void *d)
{
	struct udp_recvmmsg *rq = d;
	if (rq != NULL) {
		mp_delete(rq->mm.ctx);
	}
}

static int udp_recvmmsg_recv(int fd, void *d)
{
	struct udp_recvmmsg *rq = d;

	int n = recvmmsg(fd, rq->msgs[RX], RECVMMSG_BATCHLEN, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->fd = fd;
		rq->rcvd = n;
	}
	return n;
}

static void udp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvmmsg *rq = d;

	/* Handle each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = rq->msgs[RX][i].msg_len; /* Received bytes. */

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr, &rq->msgs[TX][i].msg_hdr);

		udp_handle(ctx, rq->fd, rq->addrs + i, rx, tx, NULL);
		rq->msgs[TX][i].msg_len = tx->iov_len;
		rq->msgs[TX][i].msg_hdr.msg_namelen = 0;
		if (tx->iov_len > 0) {
			/* @note sendmmsg() workaround to prevent sending the packet */
			rq->msgs[TX][i].msg_hdr.msg_namelen = rq->msgs[RX][i].msg_hdr.msg_namelen;
		}
	}
}

static void udp_recvmmsg_send(void *d)
{
	struct udp_recvmmsg *rq = d;
	(void)sendmmsg(rq->fd, rq->msgs[TX], rq->rcvd, 0);
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
}

static udp_api_t udp_recvmmsg_api = {
	udp_recvmmsg_init,
	udp_recvmmsg_deinit,
	udp_recvmmsg_recv,
	udp_recvmmsg_handle,
	udp_recvmmsg_send,
};
#endif /* ENABLE_RECVMMSG */

#ifdef ENABLE_XDP

static void *xdp_recvmmsg_init(void *xdp_sock)
{
	return xdp_handle_init(xdp_sock);
}

static void xdp_recvmmsg_deinit(void *d)
{
	if (d != NULL) {
		xdp_handle_free(d);
	}
}

static int xdp_recvmmsg_recv(_unused_ int fd, void *d)
{
	return xdp_handle_recv(d);
}

static void xdp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	xdp_handle_msgs(d, &ctx->layer, ctx->server, ctx->thread_id);
}

static void xdp_recvmmsg_send(void *d)
{
	xdp_handle_send(d);
}

static void xdp_recvmmsg_sweep(void *d)
{
	xdp_handle_reconfigure(d);
	xdp_handle_sweep(d);
}

static udp_api_t xdp_recvmmsg_api = {
	xdp_recvmmsg_init,
	xdp_recvmmsg_deinit,
	xdp_recvmmsg_recv,
	xdp_recvmmsg_handle,
	xdp_recvmmsg_send,
	xdp_recvmmsg_sweep,
};
#endif /* ENABLE_XDP */

static bool is_xdp_thread(const server_t *server, int thread_id)
{
	return server->handlers[IO_XDP].size > 0 &&
	       server->handlers[IO_XDP].handler.thread_id[0] <= thread_id;
}

static int iface_udp_fd(const iface_t *iface, int thread_id, bool xdp_thread,
                        void **xdp_socket)
{
	if (xdp_thread) {
#ifdef ENABLE_XDP
		if (thread_id <  iface->xdp_first_thread_id ||
		    thread_id >= iface->xdp_first_thread_id + iface->fd_xdp_count) {
			return -1; // Different XDP interface.
		}
		size_t xdp_wrk_id = thread_id - iface->xdp_first_thread_id;
		assert(xdp_wrk_id < iface->fd_xdp_count);
		*xdp_socket = iface->xdp_sockets[xdp_wrk_id];
		return iface->fd_xdp[xdp_wrk_id];
#else
		assert(0);
		return -1;
#endif
	} else { // UDP thread.
		if (iface->fd_udp_count == 0) { // No UDP interfaces.
			assert(iface->fd_xdp_count > 0);
			return -1;
		}
#ifdef ENABLE_REUSEPORT
		assert(thread_id < iface->fd_udp_count);
		return iface->fd_udp[thread_id];
#else
		return iface->fd_udp[0];
#endif
	}
}

static unsigned udp_set_ifaces(const server_t *server, size_t n_ifaces, fdset_t *fds,
                               int thread_id, void **xdp_socket)
{
	if (n_ifaces == 0) {
		return 0;
	}

	bool xdp_thread = is_xdp_thread(server, thread_id);
	const iface_t *ifaces = server->ifaces;

	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
		int fd = iface_udp_fd(i, thread_id, xdp_thread, xdp_socket);
		if (fd < 0) {
			continue;
		}
		int ret = fdset_add(fds, fd, FDSET_POLLIN, NULL);
		if (ret < 0) {
			return 0;
		}
	}

	assert(!xdp_thread || fdset_get_length(fds) == 1);
	return fdset_get_length(fds);
}

int udp_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int thread_id = handler->thread_id[dt_get_id(thread)];

	if (handler->server->n_ifaces == 0) {
		return KNOT_EOK;
	}

	/* Set thread affinity to CPU core (same for UDP and XDP). */
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = (dt_get_id(thread) % cpu);
		dt_setaffinity(thread, &cpu_mask, 1);
	}

	/* Choose processing API. */
	udp_api_t *api = NULL;
	if (is_xdp_thread(handler->server, thread_id)) {
#ifdef ENABLE_XDP
		api = &xdp_recvmmsg_api;
#else
		assert(0);
#endif
	} else {
#ifdef ENABLE_RECVMMSG
		api = &udp_recvmmsg_api;
#else
		api = &udp_recvfrom_api;
#endif
	}
	void *api_ctx = NULL;

	/* Create big enough memory cushion. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, 16 * MM_DEFAULT_BLKSIZE);

	/* Create UDP answering context. */
	udp_context_t udp = {
		.server = handler->server,
		.thread_id = thread_id,
	};
	knot_layer_init(&udp.layer, &mm, process_query_layer());

	/* Allocate descriptors for the configured interfaces. */
	void *xdp_socket = NULL;
	size_t nifs = handler->server->n_ifaces;
	fdset_t fds;
	if (fdset_init(&fds, nifs) != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = udp_set_ifaces(handler->server, nifs, &fds,
	                               thread_id, &xdp_socket);
	if (nfds == 0) {
		goto finish;
	}

	/* Initialize the networking API. */
	api_ctx = api->udp_init(xdp_socket);
	if (api_ctx == NULL) {
		goto finish;
	}

	/* Loop until all data is read. */
	for (;;) {
		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		fdset_it_t it;
		(void)fdset_poll(&fds, &it, 0, 1000);

		/* Process the events. */
		for (; !fdset_it_is_done(&it); fdset_it_next(&it)) {
			if (!fdset_it_is_pollin(&it)) {
				continue;
			}
			if (api->udp_recv(fdset_it_get_fd(&it), api_ctx) > 0) {
				api->udp_handle(&udp, api_ctx);
				api->udp_send(api_ctx);
			}
		}

		/* Regular maintenance (XDP-TCP only). */
		if (api->udp_sweep != NULL) {
			api->udp_sweep(api_ctx);
		}
	}

finish:
	api->udp_deinit(api_ctx);
	mp_delete(mm.ctx);
	fdset_clear(&fds);

	return KNOT_EOK;
}
