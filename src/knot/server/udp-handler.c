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
#include "knot/server/dns-handler.h"
#include "knot/server/udp-handler.h"
#include "knot/server/xdp-handler.h"
#include <urcu.h>
#include "knot/server/network_req_manager.h"
#include "knot/common/stats.h"

/*! \brief UDP context data. */
typedef struct {
	dns_request_handler_context_t dns_handler; /*!< DNS Request handler context. */
	network_dns_request_manager_t *req_mgr;
} udp_context_t;

static void udp_pktinfo_handle(const struct msghdr *rx, struct msghdr *tx, int fd, struct sockaddr_storage *target_addr)
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
		/* The socket is not bound to ANY addr. Get the socket ip. */
		socklen_t sock_len = sizeof(*target_addr);
		if (getsockname(fd, (struct sockaddr *)target_addr,
						&sock_len) != 0) {
			/* Socket get failed. Cleanup the IP */
			memset(target_addr, 0, sizeof(*target_addr));
		}
		return;
	}

	/* Unset the ifindex to not bypass the routing tables. */
	if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
		info->ipi_spec_dst = info->ipi_addr;
		info->ipi_ifindex = 0;
		struct sockaddr_in * target_socket_v4 = (struct sockaddr_in *)target_addr;
		target_socket_v4->sin_family = AF_INET;
		target_socket_v4->sin_port   = -1; // TBD, if we need port later
		target_socket_v4->sin_addr = info->ipi_addr;
	} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		info->ipi6_ifindex = 0;
		struct sockaddr_in6 * target_socket_v6 = (struct sockaddr_in6 *)target_addr;
		target_socket_v6->sin6_family = AF_INET6;
		target_socket_v6->sin6_port   = -1; // TBD, if we need port later
		target_socket_v6->sin6_addr = info->ipi6_addr;
	}
#endif
}

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
	network_dns_request_t *udp_req;
	struct msghdr msg[NBUFS];
	network_dns_request_manager_t *req_mgr;
};

static inline void udp_set_msghdr_from_req(struct msghdr *msg, network_dns_request_t *req, int rxtx) {
	msg->msg_name = &req->dns_req.req_data.source_addr;
	msg->msg_namelen = sizeof(struct sockaddr_storage);
	msg->msg_iov = &req->iov[rxtx];
	msg->msg_iovlen = 1;
	msg->msg_control = &req->pktinfo.cmsg;
	msg->msg_controllen = sizeof(cmsg_pktinfo_t);
}

/*!
 * \brief Sets the DNS request for msghdr.
 *
 * \param udp_recv udp_recvfrom context which needs to be udpated.
 * \param req Request to be setup on msghdr.
 */
static void udp_recvfrom_set_request(struct udp_recvfrom *udp_recv, network_dns_request_t *req) {
	udp_recv->udp_req = req;
	for (unsigned i = 0; i < NBUFS; ++i) {
		udp_set_msghdr_from_req(&udp_recv->msg[i], req, i);
	}
}

typedef struct {
	void* (*udp_init)(void *, network_dns_request_manager_t *req_mgr);
	void (*udp_deinit)(void *);
	int (*udp_recv)(int, void *);
	void (*udp_handle)(udp_context_t *, void *);
	void (*udp_send)(void *);
	void (*udp_sweep)(void *); // Optional
} udp_api_t;


static void *udp_recvfrom_init(_unused_ void *xdp_sock, network_dns_request_manager_t *req_mgr)
{
	struct udp_recvfrom *rq = malloc(sizeof(struct udp_recvfrom));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(struct udp_recvfrom));
	rq->req_mgr = req_mgr;

	network_dns_request_t *udp_req = req_mgr->allocate_network_request_func(req_mgr);
	if (udp_req == NULL) {
		free(rq);
		return NULL;
	}

	udp_recvfrom_set_request(rq, udp_req);

	return rq;
}

static void udp_recvfrom_deinit(void *d)
{
	struct udp_recvfrom *rq = d;
	rq->req_mgr->free_network_request_func(rq->req_mgr, rq->udp_req);
	free(rq);
}

static int udp_recvfrom_recv(int fd, void *d)
{
	/* Reset max lengths. */
	struct udp_recvfrom *rq = (struct udp_recvfrom *)d;
	if (rq->udp_req) {
		// we are reusing the request, reset it
		rq->req_mgr->restore_network_request_func(rq->req_mgr, rq->udp_req);
	}
	else {
		rq->udp_req = rq->req_mgr->allocate_network_request_func(rq->req_mgr);
		if (rq->udp_req == NULL) {
			// We could not allocate a request
			server_stats_increment_counter(server_stats_udp_no_req_obj, 1);
			return 0; // Dont process incoming, let the async handler free a request.
		}
	}
	rq->msg[RX].msg_namelen = sizeof(struct sockaddr_storage);
	rq->msg[RX].msg_controllen = sizeof(cmsg_pktinfo_t);

	int ret = recvmsg(fd, &rq->msg[RX], MSG_DONTWAIT);
	if (ret > 0) {
		rq->udp_req->dns_req.req_data.fd = fd;
		rq->udp_req->iov[RX].iov_len = ret;
		return 1;
	}

	return 0;
}

static void udp_recvfrom_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvfrom *rq = d;

	/* Prepare TX address. */
	rq->msg[TX].msg_namelen = rq->msg[RX].msg_namelen;

	udp_pktinfo_handle(&rq->msg[RX], &rq->msg[TX], rq->udp_req->dns_req.req_data.fd, &rq->udp_req->dns_req.req_data.target_addr);

	/* Process received pkt. */
	handle_dns_request(&ctx->dns_handler, &rq->udp_req->dns_req);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (dns_handler_request_is_async(rq->udp_req->dns_req)) {
		// Save udp source state
		rq->udp_req->msg_namelen_received = rq->msg[RX].msg_namelen;
		rq->udp_req->msg_controllen_received = rq->msg[RX].msg_controllen;
		// release the request
		rq->udp_req = NULL;
	}
#endif

}

static void udp_send_single_response(network_dns_request_t *udp_req, struct msghdr *msghdr_tx) {
	if (udp_req->iov[TX].iov_len > 0) {
		(void)sendmsg(udp_req->dns_req.req_data.fd, msghdr_tx, 0);
	}
}

static void udp_recvfrom_send(void *d)
{
	struct udp_recvfrom *rq = d;
	udp_send_single_response(rq->udp_req, &rq->msg[TX]);
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
	network_dns_request_t *udp_reqs[RECVMMSG_BATCHLEN];
	struct mmsghdr *msgs[NBUFS];
	unsigned rcvd;
	network_dns_request_manager_t *req_mgr;
	size_t udp_reqs_available;
	bool udp_reqs_fully_allocated;
	int in_progress_fd;
};

/*!
 * \brief Sets the DNS request as req_index'th request in mmsghdr.
 *
 * \param rq udp_recvmmsg context which needs to be udpated.
 * \param req_index index where req needs to be set in rq.
 * \param req Request to be setup on mmsghdr.
 */
static void udp_recvmmsg_set_request(struct udp_recvmmsg *rq, unsigned req_index, network_dns_request_t *req) {
	rq->udp_reqs[req_index] = req;
	for (unsigned i = 0; i < NBUFS; ++i) {
		udp_set_msghdr_from_req(&rq->msgs[i][req_index].msg_hdr, req, i);
	}
}


static void *udp_recvmmsg_init(_unused_ void *xdp_sock, _unused_ network_dns_request_manager_t *req_mgr)
{
	struct udp_recvmmsg *rq = (struct udp_recvmmsg *) req_mgr->allocate_mem_func(req_mgr, sizeof(struct udp_recvmmsg));
	memset(rq, 0, sizeof(*rq));
	rq->req_mgr = req_mgr;

	/* Initialize buffers. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->msgs[i] =  req_mgr->allocate_mem_func(req_mgr, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
		memset(rq->msgs[i], 0, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
	}

	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		udp_recvmmsg_set_request(rq, k, req_mgr->allocate_network_request_func(req_mgr));
	}

	rq->udp_reqs_available = RECVMMSG_BATCHLEN;
	rq->udp_reqs_fully_allocated = true;
	return rq;
}

static void udp_recvmmsg_deinit(void *d)
{
	struct udp_recvmmsg *rq = d;
	if (rq != NULL) {
		for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
			if (rq->udp_reqs[k] != NULL) {
				rq->req_mgr->free_network_request_func(rq->req_mgr, rq->udp_reqs[k]);
			}
		}

		if (rq->req_mgr != NULL)
		{
			for (unsigned i = 0; i < NBUFS; ++i) {
				rq->req_mgr->free_mem_func(rq->req_mgr, rq->msgs[i]);
			}

			rq->req_mgr->free_mem_func(rq->req_mgr, rq);
		}
	}
}

/*!
 * \brief If any request in mmsg is null, this function tries to allocate the req for NULL.
 * If allocation fails, it packs the request to have the first N allocated and updates udp_reqs_available.
 *
 * \param rq udp_recvmmsg context which needs to be udpated.
 */
static void allocate_or_pack_udp_req(struct udp_recvmmsg *rq) {
	int last_non_null_index = RECVMMSG_BATCHLEN - 1;
	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		if (rq->udp_reqs[k] == NULL) {
			// try to allocate
			network_dns_request_t *new_req = rq->req_mgr->allocate_network_request_func(rq->req_mgr);
			if (new_req != NULL) {
				udp_recvmmsg_set_request(rq, k, new_req);
			} else {
				// allocation failed. Move something from end to here.

				while (last_non_null_index > k && rq->udp_reqs[last_non_null_index] == NULL) {
					last_non_null_index--;
				}

				if (last_non_null_index > k) {
					// found non-null after current, move it to current
					udp_recvmmsg_set_request(rq, k, rq->udp_reqs[last_non_null_index]);
					rq->udp_reqs[last_non_null_index] = NULL;
				} else {
					break;
				}
			}
		}
	}

	// At this point, the requests are packed or fully allocated
	int reqs_allocated = RECVMMSG_BATCHLEN;
	while (reqs_allocated > 0 && rq->udp_reqs[reqs_allocated - 1] == NULL) {
		reqs_allocated--;
	}

	rq->udp_reqs_available = reqs_allocated;
	rq->udp_reqs_fully_allocated = (reqs_allocated == RECVMMSG_BATCHLEN);

	if (!rq->udp_reqs_fully_allocated) {
		server_stats_increment_counter(server_stats_udp_req_batch_limited, 1);
	}

	if (reqs_allocated == 0) {
		server_stats_increment_counter(server_stats_udp_no_req_obj, 1);
	}
}

static int udp_recvmmsg_recv(int fd, void *d)
{
	struct udp_recvmmsg *rq = d;

	if (!rq->udp_reqs_fully_allocated) {
		allocate_or_pack_udp_req(rq);
	}

	int n = recvmmsg(fd, rq->msgs[RX], rq->udp_reqs_available, MSG_DONTWAIT, NULL);
	if (n > 0) {
		for (int i = 0; i < n; i++) {
			rq->udp_reqs[i]->dns_req.req_data.fd = fd;
		}
		rq->rcvd = n;
		rq->in_progress_fd = fd;
	}
	return n;
}

static void udp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvmmsg *rq = d;

	/* Handle each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		rx->iov_len = rq->msgs[RX][i].msg_len; /* Received bytes. */

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr, &rq->msgs[TX][i].msg_hdr, rq->udp_reqs[i]->dns_req.req_data.fd, &rq->udp_reqs[i]->dns_req.req_data.target_addr);

		handle_dns_request(&ctx->dns_handler, &rq->udp_reqs[i]->dns_req);
	}

	/* Setup response for each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (dns_handler_request_is_async(rq->udp_reqs[i]->dns_req)) {
			// Save udp source state
			rq->udp_reqs[i]->msg_namelen_received = rq->msgs[RX][i].msg_hdr.msg_namelen;
			rq->udp_reqs[i]->msg_controllen_received = rq->msgs[RX][i].msg_hdr.msg_controllen;

			tx->iov_len = 0; // asynced request have nothing to send
			rq->udp_reqs[i] = NULL;
			rq->udp_reqs_fully_allocated = false;
		}
#endif
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
	(void)sendmmsg(rq->in_progress_fd, rq->msgs[TX], rq->rcvd, 0);
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		if (rq->udp_reqs[i] != NULL) {
			/* Reset buffer size and address len. */
			rq->req_mgr->restore_network_request_func(rq->req_mgr, rq->udp_reqs[i]);

			memset(&rq->udp_reqs[i]->dns_req.req_data.source_addr, 0, sizeof(struct sockaddr_storage));
			rq->msgs[RX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			rq->msgs[TX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
			rq->msgs[RX][i].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);
		}
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

static void *xdp_recvmmsg_init(void *xdp_sock, _unused_ network_dns_request_manager_t *req_mgr)
{
	return xdp_handle_init(xdp_sock);
}

static void xdp_recvmmsg_deinit(void *d)
{
	xdp_handle_free(d);
}

static int xdp_recvmmsg_recv(_unused_ int fd, void *d)
{
	return xdp_handle_recv(d);
}

static void xdp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	xdp_handle_msgs(d, &ctx->dns_handler.layer, ctx->dns_handler.server, ctx->dns_handler.thread_id);
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

#ifdef ENABLE_ASYNC_QUERY_HANDLING
static bool use_numa = false;
static bool udp_use_async = false;
static atomic_shared_dns_request_manager_t udp_shared_req_mgr[KNOT_MAX_NUMA];
static size_t udp_req_pool_size;

/*!
 * \brief Initialize udp async.
 *
 * \param pool_size Request pool size.
 * \param numa_enabled Indicates if numa available.
 *
 * \retval KNOT_EOK on success.
 */
int init_udp_async(size_t pool_size, bool numa_enabled) {
	for (int i = 0; i < KNOT_MAX_NUMA; i++) {
		init_shared_req_mgr(udp_shared_req_mgr[i]);
	}
	udp_req_pool_size = pool_size;
	udp_use_async = true;
	use_numa = numa_enabled;
	return KNOT_EOK;
}

static void udp_async_query_completed_callback(dns_request_handler_context_t *net, dns_handler_request_t *req) {
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

	if (handler->server->n_ifaces == 0) {
		return KNOT_EOK;
	}

	_unused_ int numa_node = 0;
	/* Set thread affinity to CPU core (same for UDP and XDP). */
	unsigned cpu = dt_online_cpus();
	if (cpu > 1) {
		unsigned cpu_mask = (dt_get_id(thread) % cpu);
		dt_setaffinity(thread, &cpu_mask, 1);
#ifdef KNOT_ENABLE_NUMA
		if (use_numa)
		{
			int cpu_numa_node = numa_node_of_cpu(cpu_mask);
			numa_node =  cpu_numa_node % KNOT_MAX_NUMA;
			log_info("UDP thread %d using numa %d, original %d", thread_id, numa_node, cpu_numa_node);
		}
#endif
	}

	/* Create UDP answering context. */
	udp_context_t udp = {0};

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
		udp.req_mgr =
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			udp_use_async ?
				network_dns_request_pool_manager_create(&udp_shared_req_mgr[numa_node], KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE, udp_req_pool_size) :
#endif
				network_dns_request_manager_knot_mm_create(KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE);
#else
		api = &udp_recvfrom_api;
		udp.req_mgr =
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			udp_use_async ?
				network_dns_request_pool_manager_create(&udp_shared_req_mgr[numa_node], KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE, udp_req_pool_size):
#endif
				network_dns_request_manager_basic_create(KNOT_WIRE_MAX_UDP_PKTSIZE, 16 * MM_DEFAULT_BLKSIZE);
#endif
	}
	assert(udp.req_mgr != NULL);
	void *api_ctx = NULL;

	/* Initialize UDP answering context. */
	if ( initialize_dns_handle(
			&udp.dns_handler,
			handler->server,
			thread_id,
			KNOTD_QUERY_FLAG_NO_AXFR | KNOTD_QUERY_FLAG_NO_IXFR | /* No transfers. */
				KNOTD_QUERY_FLAG_LIMIT_SIZE, /* Enforce UDP packet size limit. */
			NULL
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			,udp_async_query_completed_callback
#endif
			) != KNOT_EOK) {
		goto finish;
	}

	/* Allocate descriptors for the configured interfaces. */
	void *xdp_socket = NULL;
	size_t nifs = handler->server->n_ifaces;
	size_t fds_size = handler->server->n_ifaces;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (udp_use_async) {
		fds_size++;
	}
#endif
	fdset_t fds;
	if (fdset_init(&fds, fds_size) != KNOT_EOK) {
		goto finish;
	}
	unsigned nfds = udp_set_ifaces(handler->server, nifs, &fds,
	                               thread_id, &xdp_socket);
	if (nfds == 0) {
		goto finish;
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	int async_completed_notification = dns_request_handler_context_get_async_notify_handle(&udp.dns_handler);
	if (fdset_add(&fds, async_completed_notification, FDSET_POLLIN, NULL) < 0) {
		goto finish;
	}
#endif

	/* Initialize the networking API. */
	api_ctx = api->udp_init(xdp_socket, udp.req_mgr);
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
			int ready_handle = fdset_it_get_fd(&it);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
			if (ready_handle == async_completed_notification) {
				server_stats_increment_counter(server_stats_udp_async_done, 1);
				handle_dns_request_async_completed_queries(&udp.dns_handler);
			}
			else
#endif
			{
				server_stats_increment_counter(server_stats_udp_received, 1);
				if (api->udp_recv(ready_handle, api_ctx) > 0) {
					api->udp_handle(&udp, api_ctx);
					api->udp_send(api_ctx);
				}
			}
		}

		/* Regular maintenance (XDP-TCP only). */
		if (api->udp_sweep != NULL) {
			api->udp_sweep(api_ctx);
		}
	}

finish:
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	{
		struct timespec five_sec = { 5, 0 };
		nanosleep(&five_sec, &five_sec);
	}
#endif

	cleanup_dns_handle(&udp.dns_handler);
	api->udp_deinit(api_ctx);
	if (udp.req_mgr) {
		udp.req_mgr->delete_req_manager(udp.req_mgr);
	}
	fdset_clear(&fds);

	return KNOT_EOK;
}
