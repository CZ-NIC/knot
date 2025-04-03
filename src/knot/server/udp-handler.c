/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 // IPV6_PKTINFO
#endif

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

#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/handler.h"
#include "knot/server/server.h"
#ifdef ENABLE_QUIC
#include "knot/server/quic-handler.h"
#endif // ENABLE_QUIC
#include "knot/server/udp-handler.h"
#include "knot/server/xdp-handler.h"
#include "libknot/xdp/tcp_iobuf.h"

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
	sockaddr_t local;   /*!< Storage for local any address for currently processed query. */

#ifdef ENABLE_QUIC
	knot_quic_table_t *quic_table;  /*!< QUIC connection table if active. */
	knot_sweep_stats_t quic_closed; /*!< QUIC sweep context. */
	uint64_t quic_idle_close;       /*!< QUIC idle close timeout (in nanoseconds). */
#endif // ENABLE_QUIC
} udp_context_t;

static void udp_handler(udp_context_t *udp, knotd_qdata_params_t *params,
                        struct iovec *rx, struct iovec *tx)
{
	if (process_query_proto(params, KNOTD_STAGE_PROTO_BEGIN) == KNOTD_PROTO_STATE_BLOCK) {
		return;
	}

	// Prepare a reply.
	struct sockaddr_storage proxied_remote;
	handle_udp_reply(params, &udp->layer, rx, tx, &proxied_remote);

	(void)process_query_proto(params, KNOTD_STAGE_PROTO_END);
}

typedef struct {
	void* (*udp_init)(udp_context_t *, void *);
	void (*udp_deinit)(void *);
	int (*udp_recv)(int, void *);
	void (*udp_handle)(udp_context_t *, const iface_t *, void *);
	void (*udp_send)(void *);
	void (*udp_sweep)(udp_context_t *, void *);
} udp_api_t;

/*! \brief Control message to fit IP_PKTINFO/IPv6_RECVPKTINFO and/or ECN. */
typedef union {
	struct cmsghdr cmsg;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
} cmsg_buf_t;

static const sockaddr_t *local_addr(sockaddr_t *local_storage, const iface_t *iface)
{
	return local_storage->un.sun_family == AF_UNSPEC
	       ? (const sockaddr_t *)&iface->addr
	       : local_storage;
}

static void cmsg_handle_ecn(int **p_ecn, struct cmsghdr *cmsg)
{
	int *p = net_cmsg_ecn_ptr(cmsg);
	if (p != NULL) {
		*p_ecn = p;
	}
}

static void cmsg_handle_pktinfo(sockaddr_t *local, const iface_t *iface,
                                struct cmsghdr *cmsg)
{
#if defined(IP_PKTINFO)
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		info->ipi_spec_dst = info->ipi_addr;
		info->ipi_ifindex = 0; // Unset to not bypass the routing tables.

		local->ip4.sin_family = AF_INET;
		local->ip4.sin_port = ((const struct sockaddr_in *)&iface->addr)->sin_port;
		local->ip4.sin_addr = info->ipi_addr;
#elif defined(IP_RECVDSTADDR)
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR) {
		struct in_addr *addr = (struct in_addr *)CMSG_DATA(cmsg);
		local->ip4.sin_family = AF_INET;
		local->ip4.sin_port = ((const struct sockaddr_in *)&iface->addr)->sin_port;
		local->ip4.sin_addr = *addr;
#else
	if (false) {
#endif
	} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		info->ipi6_ifindex = 0; // Unset to not bypass the routing tables.

		local->ip6.sin6_family = AF_INET6;
		local->ip6.sin6_port = ((const struct sockaddr_in6 *)&iface->addr)->sin6_port;
		local->ip6.sin6_addr = info->ipi6_addr;
	}
}

void cmsg_handle(const struct msghdr *rx, struct msghdr *tx,
                 sockaddr_t *local, int **p_ecn, const iface_t *iface)
{
	local->un.sun_family = AF_UNSPEC;

	tx->msg_controllen = rx->msg_controllen;
	if (tx->msg_controllen > 0) {
		tx->msg_control = rx->msg_control;
	} else {
		// BSD has problem with zero length and not-null pointer
		tx->msg_control = NULL;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(tx);
	if (iface->tls) {
		*p_ecn = NULL;
		while (cmsg != NULL) {
			cmsg_handle_ecn(p_ecn, cmsg);
			cmsg_handle_pktinfo(local, iface, cmsg);
			cmsg = CMSG_NXTHDR(tx, cmsg);
		}
	} else {
		if (cmsg != NULL) {
			cmsg_handle_pktinfo(local, iface, cmsg);
		}
	}
}

static void udp_sweep(udp_context_t *ctx, void *d)
{
#ifdef ENABLE_QUIC
	int fd = *(int *)d; // NOTE both udp_msg_ctx_t and udp_mmsg_ctx_t have 'fd' as first item
	quic_sweep_table(ctx->quic_table, &ctx->quic_closed, fd);
	quic_reconfigure_table(ctx->quic_table);
#endif // ENABLE_QUIC
}

typedef struct {
	int fd;
	struct msghdr msg[NBUFS];
	struct iovec iov[NBUFS];
	uint8_t iobuf[NBUFS][KNOT_WIRE_MAX_PKTSIZE];
	sockaddr_t addr;
	cmsg_buf_t cmsgs;
} udp_msg_ctx_t;

static void *udp_msg_init(_unused_ udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_msg_ctx_t *rq = calloc(1, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->iov[i].iov_base = rq->iobuf[i];
		rq->iov[i].iov_len = sizeof(rq->iobuf[i]);
		rq->msg[i].msg_iov = &rq->iov[i];
		rq->msg[i].msg_iovlen = 1;
		rq->msg[i].msg_name = &rq->addr;
		rq->msg[i].msg_namelen = sizeof(rq->addr);
		rq->msg[i].msg_control = &rq->cmsgs.cmsg;
		rq->msg[i].msg_controllen = sizeof(rq->cmsgs);
	}

	return rq;
}

static void udp_msg_deinit(void *d)
{
	udp_msg_ctx_t *rq = d;

	free(rq);
}

static int udp_msg_recv(int fd, void *d)
{
	udp_msg_ctx_t *rq = d;

	/* Reset max lengths. */
	rq->iov[RX].iov_len = sizeof(rq->iobuf[RX]);
	rq->msg[RX].msg_namelen = sizeof(rq->addr);
	rq->msg[RX].msg_controllen = sizeof(rq->cmsgs);

	int ret = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
	if (ret > 0) {
		rq->fd = fd;
		rq->iov[RX].iov_len = ret;
		return 1;
	}

	return 0;
}

static void udp_msg_handle(udp_context_t *ctx, const iface_t *iface, void *d)
{
	udp_msg_ctx_t *rq = d;

	/* Prepare TX address. */
	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;
	rq->iov[TX].iov_len = sizeof(rq->iobuf[TX]);

	int *p_ecn;
	cmsg_handle(&rq->msg[RX], &rq->msg[TX], &ctx->local, &p_ecn, iface);
	const sockaddr_t *local = local_addr(&ctx->local, iface);

	/* Process received pkt. */
	knotd_qdata_params_t params = params_init(
		iface->tls ? KNOTD_QUERY_PROTO_QUIC : KNOTD_QUERY_PROTO_UDP,
		&rq->addr, local, rq->fd, ctx->server, ctx->thread_id);
	if (iface->tls) {
#ifdef ENABLE_QUIC
		quic_handler(&params, &ctx->layer, ctx->quic_idle_close,
		             ctx->quic_table, &rq->iov[RX], &rq->msg[TX], p_ecn);
#else
		assert(0);
#endif // ENABLE_QUIC
	} else {
		udp_handler(ctx, &params, &rq->iov[RX], &rq->iov[TX]);
	}
}

static void udp_msg_send(void *d)
{
	udp_msg_ctx_t *rq = d;

	if (rq->iov[TX].iov_len > 0) {
		int ret = sendmsg(rq->fd, &rq->msg[TX], 0);
		if (ret == -1 && log_enabled_debug()) {
			log_debug("UDP, failed to send a packet (%s)", strerror(errno));
		}
	}
}

_unused_
static udp_api_t udp_msg_api = {
	udp_msg_init,
	udp_msg_deinit,
	udp_msg_recv,
	udp_msg_handle,
	udp_msg_send,
	udp_sweep,
};

#ifdef ENABLE_RECVMMSG
typedef struct {
	int fd;
	unsigned rcvd;
	struct mmsghdr msgs[NBUFS][RECVMMSG_BATCHLEN];
	struct iovec iov[NBUFS][RECVMMSG_BATCHLEN];
	uint8_t iobuf[NBUFS][RECVMMSG_BATCHLEN][KNOT_WIRE_MAX_PKTSIZE];
	sockaddr_t addrs[RECVMMSG_BATCHLEN];
	cmsg_buf_t cmsgs[RECVMMSG_BATCHLEN];
} udp_mmsg_ctx_t;

static void *udp_mmsg_init(_unused_ udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_mmsg_ctx_t *rq = calloc(1, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}

	for (unsigned i = 0; i < NBUFS; ++i) {
		for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
			rq->iov[i][k].iov_base = rq->iobuf[i][k];
			rq->iov[i][k].iov_len = sizeof(rq->iobuf[i][k]);
			rq->msgs[i][k].msg_hdr.msg_iov = &rq->iov[i][k];
			rq->msgs[i][k].msg_hdr.msg_iovlen = 1;
			rq->msgs[i][k].msg_hdr.msg_name = &rq->addrs[k];
			rq->msgs[i][k].msg_hdr.msg_namelen = sizeof(rq->addrs[k]);
			rq->msgs[i][k].msg_hdr.msg_control = &rq->cmsgs[k].cmsg;
			rq->msgs[i][k].msg_hdr.msg_controllen = sizeof(rq->cmsgs[k]);
		}
	}

	return rq;
}

static void udp_mmsg_deinit(void *d)
{
	udp_mmsg_ctx_t *rq = d;

	free(rq);
}

static int udp_mmsg_recv(int fd, void *d)
{
	udp_mmsg_ctx_t *rq = d;

	int n = recvmmsg(fd, rq->msgs[RX], RECVMMSG_BATCHLEN, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->fd = fd;
		rq->rcvd = n;
	}
	return n;
}

static void udp_mmsg_handle(udp_context_t *ctx, const iface_t *iface, void *d)
{
	udp_mmsg_ctx_t *rq = d;

	/* Handle each received message. */
	unsigned j = 0;
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct msghdr *rx = &rq->msgs[RX][i].msg_hdr;
		struct msghdr *tx = &rq->msgs[TX][j].msg_hdr;

		/* Set received bytes. */
		rx->msg_iov->iov_len = rq->msgs[RX][i].msg_len;
		/* Update mapping of address buffer. */
		tx->msg_name = rx->msg_name;
		tx->msg_namelen = rx->msg_namelen;

		/* Update output message control buffer. */
		int *p_ecn;
		cmsg_handle(rx, tx, &ctx->local, &p_ecn, iface);
		const sockaddr_t *local = local_addr(&ctx->local, iface);

		knotd_qdata_params_t params = params_init(
			iface->tls ? KNOTD_QUERY_PROTO_QUIC : KNOTD_QUERY_PROTO_UDP,
			&rq->addrs[i], local, rq->fd, ctx->server, ctx->thread_id);
		if (iface->tls) {
#ifdef ENABLE_QUIC
			quic_handler(&params, &ctx->layer, ctx->quic_idle_close,
			             ctx->quic_table, rx->msg_iov, tx, p_ecn);
#else
		assert(0);
#endif // ENABLE_QUIC
		} else {
			udp_handler(ctx, &params, rx->msg_iov, tx->msg_iov);
		}

		if (tx->msg_iov->iov_len > 0) {
			rq->msgs[TX][j].msg_len = tx->msg_iov->iov_len;
			j++;
		} else {
			/* Reset tainted output context. */
			tx->msg_iov->iov_len = sizeof(rq->iobuf[TX][i]);
		}

		/* Reset input context. */
		rx->msg_iov->iov_len = sizeof(rq->iobuf[RX][i]);
		rx->msg_namelen = sizeof(rq->addrs[i]);
		rx->msg_controllen = sizeof(rq->cmsgs[i]);
	}
	rq->rcvd = j;
}

static void udp_mmsg_send(void *d)
{
	udp_mmsg_ctx_t *rq = d;

	int ret = sendmmsg(rq->fd, rq->msgs[TX], rq->rcvd, 0);
	if (ret == -1 && log_enabled_debug()) {
		log_debug("UDP, failed to send some packets (%s)", strerror(errno));
	}
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct msghdr *tx = &rq->msgs[TX][i].msg_hdr;

		/* Reset output context. */
		tx->msg_iov->iov_len = sizeof(rq->iobuf[TX][i]);
	}
}

static udp_api_t udp_mmsg_api = {
	udp_mmsg_init,
	udp_mmsg_deinit,
	udp_mmsg_recv,
	udp_mmsg_handle,
	udp_mmsg_send,
	udp_sweep,
};
#endif /* ENABLE_RECVMMSG */

#ifdef ENABLE_XDP
static void *xdp_mmsg_init(udp_context_t *ctx, void *xdp_sock)
{
	return xdp_handle_init(ctx->server, xdp_sock);
}

static void xdp_mmsg_deinit(void *d)
{
	if (d != NULL) {
		xdp_handle_free(d);
	}
}

static int xdp_mmsg_recv(_unused_ int fd, void *d)
{
	return xdp_handle_recv(d);
}

static void xdp_mmsg_handle(udp_context_t *ctx, _unused_ const iface_t *iface, void *d)
{
	assert(!iface->tls);
	xdp_handle_msgs(d, &ctx->layer, ctx->server, ctx->thread_id);
}

static void xdp_mmsg_send(void *d)
{
	xdp_handle_send(d);
}

static void xdp_mmsg_sweep(_unused_ udp_context_t *ctx, void *d)
{
	xdp_handle_reconfigure(d);
	xdp_handle_sweep(d);
}

static udp_api_t xdp_mmsg_api = {
	xdp_mmsg_init,
	xdp_mmsg_deinit,
	xdp_mmsg_recv,
	xdp_mmsg_handle,
	xdp_mmsg_send,
	xdp_mmsg_sweep,
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
			return -1;
		}
#ifdef ENABLE_REUSEPORT
		if (iface->addr.ss_family != AF_UNIX) {
			assert(thread_id < iface->fd_udp_count);
			return iface->fd_udp[thread_id];
		}
#endif
		return iface->fd_udp[0];
	}
}

static unsigned udp_set_ifaces(const server_t *server, size_t n_ifaces, fdset_t *fds,
                               int thread_id, void **xdp_socket, bool *quic)
{
	if (n_ifaces == 0) {
		return 0;
	}

	bool xdp_thread = is_xdp_thread(server, thread_id);
	const iface_t *ifaces = server->ifaces;

	for (const iface_t *i = ifaces; i != ifaces + n_ifaces; i++) {
#ifndef ENABLE_REUSEPORT
		/* If loadbalanced SO_REUSEPORT isn't available, ensure that
		 * just one (first) UDP worker handles the QUIC sockets. */
		if (i->tls && thread_id > 0) {
			continue;
		}
#endif
		int fd = iface_udp_fd(i, thread_id, xdp_thread, xdp_socket);
		if (fd < 0) {
			continue;
		}
		int ret = fdset_add(fds, fd, FDSET_POLLIN, (void *)i);
		if (ret < 0) {
			return 0;
		}
		if (i->tls) {
			*quic = true;
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
		api = &xdp_mmsg_api;
#else
		assert(0);
#endif
	} else {
#ifdef ENABLE_RECVMMSG
		api = &udp_mmsg_api;
#else
		api = &udp_msg_api;
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
	bool quic = false;
	void *xdp_socket = NULL;
	size_t nifs = handler->server->n_ifaces;
	fdset_t fds;
	if (fdset_init(&fds, nifs) != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = udp_set_ifaces(handler->server, nifs, &fds,
	                               thread_id, &xdp_socket, &quic);
	if (nfds == 0) {
		goto finish;
	}

#ifdef ENABLE_QUIC
	if (quic) {
		udp.quic_idle_close= conf()->cache.srv_quic_idle_close * 1000000000LU;
		udp.quic_table = quic_make_table(handler->server);
		if (udp.quic_table == NULL) {
			goto finish;
		}
	}
#endif // ENABLE_QUIC

	/* Initialize the networking API. */
	api_ctx = api->udp_init(&udp, xdp_socket);
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
				const iface_t *iface = fdset_it_get_ctx(&it);
				assert(iface);
				api->udp_handle(&udp, iface, api_ctx);
				api->udp_send(api_ctx);
			}
		}

		/* Regular maintenance. */
		api->udp_sweep(&udp, api_ctx);
	}

finish:
	api->udp_deinit(api_ctx);
#ifdef ENABLE_QUIC
	quic_unmake_table(udp.quic_table);
#endif // ENABLE_QUIC
	mp_delete(mm.ctx);
	fdset_clear(&fds);

	return KNOT_EOK;
}
