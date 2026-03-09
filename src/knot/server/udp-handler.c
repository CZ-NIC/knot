/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
#include <urcu.h>

#include "contrib/mempattern.h"
#include "contrib/net.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/common/fdset.h"
#include "knot/common/log.h"
#include "knot/common/stats.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/dns-handler.h"
#include "knot/server/handler.h"
#include "knot/server/network_req_manager.h"
#include "knot/server/server.h"
#ifdef ENABLE_QUIC
#include "knot/server/quic-handler.h"
#endif // ENABLE_QUIC
#include "knot/server/udp-handler.h"
#include "knot/server/xdp-handler.h"
#include "libknot/xdp/tcp_iobuf.h"

/*! \brief UDP context data. */
typedef struct {
	dns_request_handler_context_t dns_handler; /*!< DNS request handler context. */
	network_dns_request_manager_t *req_mgr;    /*!< DNS request manager. */
#ifdef ENABLE_QUIC
	knot_quic_table_t *quic_table;  /*!< QUIC connection table if active. */
	knot_sweep_stats_t quic_closed; /*!< QUIC sweep context. */
	uint64_t quic_idle_close;       /*!< QUIC idle close timeout (in nanoseconds). */
#endif // ENABLE_QUIC
} udp_context_t;

static void udp_handler(udp_context_t *udp, network_dns_request_t *req)
{
	knotd_qdata_params_t *params = &req->dns_req.req_data.params;

	if (process_query_proto(params, KNOTD_STAGE_PROTO_BEGIN) == KNOTD_PROTO_STATE_BLOCK) {
		return;
	}

	handle_dns_request(&udp->dns_handler, &req->dns_req);

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

static void upd_local_addr(struct sockaddr_storage *local_storage, const iface_t *iface)
{
	if (local_storage->ss_family == AF_UNSPEC) {
		*local_storage = iface->addr;
	}
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
                 struct sockaddr_storage *local, int **p_ecn, const iface_t *iface)
{
	local->ss_family = AF_UNSPEC;

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
			cmsg_handle_pktinfo((sockaddr_t *)local, iface, cmsg);
			cmsg = CMSG_NXTHDR(tx, cmsg);
		}
	} else {
		if (cmsg != NULL) {
			cmsg_handle_pktinfo((sockaddr_t *)local, iface, cmsg);
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

static void udp_set_msghdr_from_req(struct msghdr *msg, network_dns_request_t *req, int rxtx)
{
	msg->msg_name = &req->dns_req.req_data.source_addr;
	msg->msg_namelen = sizeof(req->dns_req.req_data.source_addr);
	msg->msg_iov = &req->iov[rxtx];
	msg->msg_iovlen = 1;
	msg->msg_control = &req->pktinfo.cmsg;
	msg->msg_controllen = sizeof(req->pktinfo);
}

typedef struct {
	network_dns_request_manager_t *req_mgr;
	network_dns_request_t *udp_req;
	struct msghdr msg[NBUFS];
	int fd;
} udp_msg_ctx_t;

static void udp_msg_set_request(udp_msg_ctx_t *udp, network_dns_request_t *req)
{
	udp->udp_req = req;
	for (unsigned i = 0; i < NBUFS; ++i) {
		udp_set_msghdr_from_req(&udp->msg[i], req, i);
	}
}

static void *udp_msg_init(udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_msg_ctx_t *rq = ctx->req_mgr->allocate_mem_func(ctx->req_mgr, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(*rq));
	rq->req_mgr = ctx->req_mgr;

	network_dns_request_t *udp_req = ctx->req_mgr->allocate_network_request_func(ctx->req_mgr);
	if (udp_req == NULL) {
		rq->req_mgr->free_mem_func(rq->req_mgr, rq);
		return NULL;
	}

	udp_msg_set_request(rq, udp_req);

	return rq;
}

static void udp_msg_deinit(void *d)
{
	udp_msg_ctx_t *rq = d;
	if (rq != NULL && rq->req_mgr != NULL) {
		if (rq->udp_req != NULL) {
			rq->req_mgr->free_network_request_func(rq->req_mgr, rq->udp_req);
		}
		rq->req_mgr->free_mem_func(rq->req_mgr, rq);
	}
}

static int udp_msg_recv(int fd, void *d)
{
	udp_msg_ctx_t *rq = d;

	if (rq->udp_req != NULL) {
		// We are reusing the request, reset it.
		rq->req_mgr->restore_network_request_func(rq->req_mgr, rq->udp_req);

		rq->msg[RX].msg_namelen = sizeof(rq->udp_req->dns_req.req_data.source_addr);
		rq->msg[RX].msg_controllen = sizeof(rq->udp_req->pktinfo);
	} else {
		network_dns_request_t *udp_req = rq->req_mgr->allocate_network_request_func(rq->req_mgr);
		if (udp_req == NULL) {
			server_stats_increment_counter(server_stats_udp_no_req_obj, 1);
			return 0; // Dont process incoming, let the async handler free a request.
		}

		udp_msg_set_request(rq, udp_req);
	}

	int ret = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
	if (ret > 0) {
		rq->fd = fd;
		rq->udp_req->iov[RX].iov_len = ret;
		return 1;
	}

	return 0;
}

static void udp_msg_handle(udp_context_t *ctx, const iface_t *iface, void *d)
{
	udp_msg_ctx_t *rq = d;

	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;

	int *p_ecn;
	cmsg_handle(&rq->msg[RX], &rq->msg[TX], &rq->udp_req->dns_req.req_data.target_addr, &p_ecn, iface);
	upd_local_addr(&rq->udp_req->dns_req.req_data.target_addr, iface);

	init_dns_request(&ctx->dns_handler, &rq->udp_req->dns_req, rq->fd,
	                 iface->tls ? KNOTD_QUERY_PROTO_QUIC : KNOTD_QUERY_PROTO_UDP);
	knotd_qdata_params_t *params = &rq->udp_req->dns_req.req_data.params;

	/* Process received pkt. */
	if (iface->tls) {
#ifdef ENABLE_QUIC
		quic_handler(params, &ctx->dns_handler.layer, ctx->quic_idle_close,
		             ctx->quic_table, &rq->udp_req->iov[RX], &rq->msg[TX], p_ecn);
#else
		assert(0);
#endif // ENABLE_QUIC
	} else {
		udp_handler(ctx, rq->udp_req);
	}
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (dns_handler_request_is_async(rq->udp_req->dns_req)) {
		// Save udp source state
		rq->udp_req->msg_namelen_received = rq->msg[RX].msg_namelen;
		rq->udp_req->msg_controllen_received = rq->msg[RX].msg_controllen;
		// Release the request
		rq->udp_req = NULL;
	}
#endif
}

static void udp_send_single_response(network_dns_request_t *udp_req, struct msghdr *msghdr_tx)
{
	if (udp_req != NULL && udp_req->iov[TX].iov_len > 0) {
		int ret = sendmsg(udp_req->dns_req.req_data.params.socket, msghdr_tx, 0);
		if (ret == -1 && log_enabled_debug()) {
			log_debug("UDP, failed to send a packet (%s)", strerror(errno));
		}
	}
}

static void udp_msg_send(void *d)
{
	udp_msg_ctx_t *rq = d;

	udp_send_single_response(rq->udp_req, &rq->msg[TX]);
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
	network_dns_request_manager_t *req_mgr;
	network_dns_request_t *udp_reqs[RECVMMSG_BATCHLEN];
	struct mmsghdr msgs[NBUFS][RECVMMSG_BATCHLEN];
	unsigned udp_reqs_available;
	unsigned rcvd;
	int fd;
	bool udp_reqs_fully_allocated;
} udp_mmsg_ctx_t;

static void udp_mmsg_set_request(udp_mmsg_ctx_t *rq, unsigned req_index, network_dns_request_t *req)
{
	rq->udp_reqs[req_index] = req;
	for (unsigned i = 0; i < NBUFS; ++i) {
		udp_set_msghdr_from_req(&rq->msgs[i][req_index].msg_hdr, req, i);
	}
}

static void *udp_mmsg_init(udp_context_t *ctx, _unused_ void *xdp_sock)
{
	udp_mmsg_ctx_t *rq = ctx->req_mgr->allocate_mem_func(ctx->req_mgr, sizeof(*rq));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(*rq));
	rq->req_mgr = ctx->req_mgr;

	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		udp_mmsg_set_request(rq, k, ctx->req_mgr->allocate_network_request_func(ctx->req_mgr));
	}

	rq->udp_reqs_available = RECVMMSG_BATCHLEN;
	rq->udp_reqs_fully_allocated = true;

	return rq;
}

static void udp_mmsg_deinit(void *d)
{
	udp_mmsg_ctx_t *rq = d;
	if (rq != NULL && rq->req_mgr != NULL) {
		for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
			if (rq->udp_reqs[k] != NULL) {
				rq->req_mgr->free_network_request_func(rq->req_mgr, rq->udp_reqs[k]);
			}
		}

		rq->req_mgr->free_mem_func(rq->req_mgr, rq);
	}
}

/*!
 * \brief If any request in mmsg is null, this function tries to allocate the req for NULL.
 * If allocation fails, it packs the request to have the first N allocated and updates udp_reqs_available.
 */
static void allocate_or_pack_udp_req(udp_mmsg_ctx_t *rq)
{
	unsigned reqs_allocated = 0;
	int last_non_null_index = RECVMMSG_BATCHLEN - 1;
	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		if (rq->udp_reqs[k] == NULL) {
			network_dns_request_t *udp_req = rq->req_mgr->allocate_network_request_func(rq->req_mgr);
			if (udp_req != NULL) {
				udp_mmsg_set_request(rq, k, udp_req);
			} else {
				// Allocation failed. Move something from end to here.
				while (last_non_null_index > k && rq->udp_reqs[last_non_null_index] == NULL) {
					last_non_null_index--;
				}

				if (last_non_null_index > k) {
					// Found non-null after current, move it to current.
					udp_mmsg_set_request(rq, k, rq->udp_reqs[last_non_null_index]);
					rq->udp_reqs[last_non_null_index] = NULL;
				} else {
					break;
				}
			}
		}
		reqs_allocated++;
	}

	rq->udp_reqs_available = reqs_allocated;
	if (reqs_allocated == 0) {
		server_stats_increment_counter(server_stats_udp_no_req_obj, 1);
	}

	rq->udp_reqs_fully_allocated = (reqs_allocated == RECVMMSG_BATCHLEN);
	if (!rq->udp_reqs_fully_allocated) {
		server_stats_increment_counter(server_stats_udp_req_batch_limited, 1);
	}
}

static int udp_mmsg_recv(int fd, void *d)
{
	udp_mmsg_ctx_t *rq = d;

	if (!rq->udp_reqs_fully_allocated) {
		allocate_or_pack_udp_req(rq);
	}

	int n = recvmmsg(fd, rq->msgs[RX], rq->udp_reqs_available, MSG_DONTWAIT, NULL);
	if (n > 0) {
		rq->rcvd = n;
		rq->fd = fd;
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
		cmsg_handle(rx, tx, &rq->udp_reqs[j]->dns_req.req_data.target_addr, &p_ecn, iface);
		upd_local_addr(&rq->udp_reqs[j]->dns_req.req_data.target_addr, iface);

		init_dns_request(&ctx->dns_handler, &rq->udp_reqs[j]->dns_req, rq->fd,
		                 iface->tls ? KNOTD_QUERY_PROTO_QUIC : KNOTD_QUERY_PROTO_UDP);
		knotd_qdata_params_t *params = &rq->udp_reqs[j]->dns_req.req_data.params;
		if (iface->tls) {
#ifdef ENABLE_QUIC
			quic_handler(params, &ctx->dns_handler.layer, ctx->quic_idle_close,
			             ctx->quic_table, rx->msg_iov, tx, p_ecn);
#else
		assert(0);
#endif // ENABLE_QUIC
		} else {
			udp_handler(ctx, rq->udp_reqs[j]);
		}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (dns_handler_request_is_async(rq->udp_reqs[j]->dns_req)) {
			// Save udp source state
			rq->udp_reqs[j]->msg_namelen_received = rx->msg_namelen;
			rq->udp_reqs[j]->msg_controllen_received = rx->msg_controllen;

			tx->msg_iov->iov_len = 0; // Asynced request has nothing to send
			rq->udp_reqs[j] = NULL;
			rq->udp_reqs_fully_allocated = false;
		}
#endif
		if (tx->msg_iov->iov_len > 0) {
			rq->msgs[TX][j].msg_len = tx->msg_iov->iov_len;
			j++;
		} else if (rq->udp_reqs[j] != NULL) {
			/* Reset tainted output context. */
			rq->req_mgr->restore_network_request_func(rq->req_mgr, rq->udp_reqs[i]);
		}

		/* Reset input context. */
		rx->msg_namelen = sizeof(rq->udp_reqs[i]->dns_req.req_data.source_addr);
		rx->msg_controllen = sizeof(rq->udp_reqs[i]->pktinfo);
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
		rq->req_mgr->restore_network_request_func(rq->req_mgr, rq->udp_reqs[i]);
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
	return xdp_handle_init(ctx->dns_handler.server, xdp_sock);
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
	xdp_handle_msgs(d, &ctx->dns_handler.layer, ctx->dns_handler.server, ctx->dns_handler.thread_id);
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

#ifdef ENABLE_ASYNC_QUERY_HANDLING
static bool use_numa = false;
static bool udp_use_async = false;
static atomic_shared_dns_request_manager_t udp_shared_req_mgr[KNOT_MAX_NUMA];
static size_t udp_req_pool_size;

int init_udp_async(size_t pool_size, bool numa_enabled)
{
	for (int i = 0; i < KNOT_MAX_NUMA; i++) {
		init_shared_req_mgr(udp_shared_req_mgr[i]);
	}
	udp_req_pool_size = pool_size;
	udp_use_async = true;
	use_numa = numa_enabled;
	return KNOT_EOK;
}

static void udp_async_query_completed_callback(dns_request_handler_context_t *net, dns_handler_request_t *req)
{
	udp_context_t *udp = caa_container_of(net, udp_context_t, dns_handler);
	network_dns_request_t *udp_req = caa_container_of(req, network_dns_request_t, dns_req);

	// Prepare response and send it
	struct msghdr txmsg;
	udp_set_msghdr_from_req(&txmsg, udp_req, TX);
	txmsg.msg_namelen = udp_req->msg_namelen_received;
	txmsg.msg_controllen = udp_req->msg_controllen_received;
	txmsg.msg_control = (txmsg.msg_controllen != 0) ? &udp_req->pktinfo.cmsg : NULL;
	udp_send_single_response(udp_req, &txmsg);

	// Free the request
	udp->req_mgr->free_network_request_func(udp->req_mgr, udp_req);
}
#endif

int udp_master(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	int thread_id = handler->thread_id[dt_get_id(thread)];

	_unused_ int numa_node = 0;
	/* Set thread affinity to CPU core (same for UDP and XDP). */
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = (dt_get_id(thread) % cpu);
		dt_setaffinity(thread, &cpu_mask, 1);
#ifdef KNOT_ENABLE_NUMA
		if (use_numa) {
			int cpu_numa_node = numa_node_of_cpu(cpu_mask);
			numa_node =  cpu_numa_node % KNOT_MAX_NUMA;
			log_info("UDP thread %d using numa %d, original %d", thread_id, numa_node, cpu_numa_node);
		}
#endif
	}

	int ret = KNOT_EOK;

	/* Create UDP answering context. */
	udp_context_t udp = { 0 };

	/* Choose processing API. */
	udp_api_t *api = NULL;
	void *api_ctx = NULL;
	if (is_xdp_thread(handler->server, thread_id)) {
#ifdef ENABLE_XDP
		api = &xdp_mmsg_api;
#else
		assert(0);
#endif
	} else {
#ifdef ENABLE_RECVMMSG
		api = &udp_mmsg_api;
		udp.req_mgr =
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			udp_use_async ?
				network_dns_request_pool_manager_create(&udp_shared_req_mgr[numa_node],
					KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE, udp_req_pool_size) :
#endif
				network_dns_request_manager_knot_mm_create(
					KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE);
#else
		api = &udp_msg_api;
		udp.req_mgr =
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			udp_use_async ?
				network_dns_request_pool_manager_create(&udp_shared_req_mgr[numa_node],
					KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE, udp_req_pool_size) :
#endif
				network_dns_request_manager_basic_create(
					KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE);
#endif
	}
	if (udp.req_mgr == NULL) {
		ret = KNOT_ENOMEM;
		goto finish;
	}

	/* Allocate descriptors for the configured interfaces. */
	bool quic = false;
	void *xdp_socket = NULL;
	size_t fds_size = handler->server->n_ifaces;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (udp_use_async) {
		fds_size++;
	}
#endif
	fdset_t fds;
	ret = fdset_init(&fds, fds_size, 1);
	if (ret != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = udp_set_ifaces(handler->server, handler->server->n_ifaces,
	                               &fds, thread_id, &xdp_socket, &quic);
	if (nfds == 0) {
		goto finish; /* Terminate on zero interfaces. */
	}

#ifdef ENABLE_QUIC
	if (quic) {
		udp.quic_idle_close= conf()->cache.srv_quic_idle_close * 1000000000LU;
		udp.quic_table = quic_make_table(handler->server);
		if (udp.quic_table == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}
#endif // ENABLE_QUIC

	/* Initialize UDP answering context. */
	ret = initialize_dns_handle(&udp.dns_handler, handler->server, thread_id, NULL
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	                           ,udp_async_query_completed_callback
#endif
	                           );
	if (ret != KNOT_EOK) {
		goto finish;
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	int async_completed_notification = dns_request_handler_context_get_async_notify_handle(&udp.dns_handler);
	if (fdset_add(&fds, async_completed_notification, FDSET_POLLIN, NULL) < 0) {
		goto finish;
	}
#endif

	/* Initialize the networking API. */
	api_ctx = api->udp_init(&udp, xdp_socket);
	if (api_ctx == NULL) {
		ret = KNOT_ENOMEM;
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
			int ready_handle = fdset_it_get_fd(&it);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			if (ready_handle == async_completed_notification) {
				server_stats_increment_counter(server_stats_udp_async_done, 1);
				handle_dns_request_async_completed_queries(&udp.dns_handler);
			} else
#endif
			{
				server_stats_increment_counter(server_stats_udp_received, 1);
				if (api->udp_recv(ready_handle, api_ctx) > 0) {
					const iface_t *iface = fdset_it_get_ctx(&it, 0);
					assert(iface);
					api->udp_handle(&udp, iface, api_ctx);
					api->udp_send(api_ctx);
				}
			}
		}

		/* Regular maintenance. */
		api->udp_sweep(&udp, api_ctx);
	}

finish:
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	{
		struct timespec five_sec = { 0, 0 };
		nanosleep(&five_sec, &five_sec);
	}
#endif

	cleanup_dns_handle(&udp.dns_handler);
	api->udp_deinit(api_ctx);
	if (udp.req_mgr) {
		udp.req_mgr->delete_req_manager(udp.req_mgr);
	}
#ifdef ENABLE_QUIC
	quic_unmake_table(udp.quic_table);
#endif // ENABLE_QUIC
	fdset_clear(&fds);

	return ret;
}
