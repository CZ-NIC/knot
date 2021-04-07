/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#ifdef HAVE_SYS_UIO_H	// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/ucw/mempool.h"
#include "knot/nameserver/process_query.h"
#include "knot/query/layer.h"
#include "knot/server/server.h"
#include "knot/server/udp-handler.h"
#include "knot/server/network-handler.h"

struct udp_api;
/*! \brief UDP context data. */
typedef struct {
	network_context_t network_ctx;
	struct udp_api *api;
	void *xdp_sock;
} udp_context_t;

typedef struct udp_api {
	void* (*udp_init)(udp_context_t *udp);
	void (*udp_deinit)(udp_context_t *udp, void *);
	int (*udp_recv)(udp_context_t *udp, int, void *);
	int (*udp_handle)(udp_context_t *, void *);
	int (*udp_send)(udp_context_t *udp, void *);
	int (*udp_send_single)(udp_context_t *udp, void *);
	int (*udp_free_async)(udp_context_t *udp, void *);
} udp_api_t;

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

struct udp_recv_msg {
	network_request_t *req;
};

static void *udp_recvfrom_init(udp_context_t *udp)
{
	struct udp_recv_msg *rq_h = malloc(sizeof(*rq_h));

	rq_h->req = network_allocate_request(&udp->network_ctx, NULL, network_request_flag_udp_buff);

	return rq_h;
}

static void udp_recvfrom_deinit(udp_context_t *udp, void *d)
{
	struct udp_recv_msg *rq_h = d;

	network_free_request(&udp->network_ctx, NULL, rq_h->req);

	free(rq_h);
}

static int udp_recvfrom_recv(udp_context_t *udp, int fd, void *d)
{
	/* Reset max lengths. */
	struct udp_recv_msg *rq_h = d;
	network_request_t *rq = rq_h->req;
	network_request_udp_t *udp_rq = udp_req_from_req(rq);
	if (rq) {
		struct iovec *in = request_get_iovec(rq, RX);
		in->iov_len = KNOT_WIRE_MAX_UDP_PKTSIZE;
		udp_rq->msg[RX].msg_namelen = sizeof(struct sockaddr_storage);
		udp_rq->msg[RX].msg_controllen = sizeof(udp_rq->pktinfo);

		int ret = recvmsg(fd, &udp_rq->msg[RX], MSG_DONTWAIT);
		if (ret > 0) {
			rq->fd = fd;
			in->iov_len = ret;
			return 1;
		}
	}

	return 0;
}

static int udp_recvfrom_handle(udp_context_t *ctx, void *d)
{
	struct udp_recv_msg *rq_h = d;
	network_request_t *rq = rq_h->req;
	network_request_udp_t *udp_rq = udp_req_from_req(rq);
	if (rq) {
		struct iovec *out = request_get_iovec(rq, TX);
		/* Prepare TX address. */
		udp_rq->msg[TX].msg_namelen = udp_rq->msg[RX].msg_namelen;
		out->iov_len = KNOT_WIRE_MAX_UDP_PKTSIZE;

		udp_pktinfo_handle(&udp_rq->msg[RX], &udp_rq->msg[TX]);

		/* Process received pkt. */
		network_handle(&ctx->network_ctx, rq, NULL);
	}

	return KNOT_EOK;
}

static int udp_send_one(udp_context_t *udp, void *d)
{
	network_request_t *rq = d;
	network_request_udp_t *udp_rq = udp_req_from_req(rq);
	struct iovec *out = request_get_iovec(rq, TX);
	int rc = 0;
	if (out->iov_len > 0) {
		rc = sendmsg(rq->fd, &udp_rq->msg[TX], 0);
	}

	/* Return number of packets sent. */
	if (rc > 1) {
		return 1;
	}

	/* Declare all bytes in the buffer are not initialized to valgrind.
	 * Otherwise, valgrind will think previous read/written packet data in current buffer is valid too and wont catch reading past current request packet. */
	VALGRIND_MAKE_MEM_UNDEFINED(udp_rq->iov[RX].iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);
	VALGRIND_MAKE_MEM_UNDEFINED(udp_rq->iov[TX].iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);

	return 0;
}

static int udp_recvfrom_send(udp_context_t *udp, void *d)
{
	struct udp_recv_msg *rq_h = d;
	network_request_t *rq = rq_h->req;
	int ret = 0;

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	if (rq && !(rq->flag & network_request_flag_is_async)) {
#endif
		ret = udp_send_one(udp, rq);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
	} else {
		rq_h->req = network_allocate_request(&udp->network_ctx, NULL, network_request_flag_udp_buff);
	}
#endif

	return ret;
}

__attribute__ ((unused))
static udp_api_t udp_recvfrom_api = {
	udp_recvfrom_init,
	udp_recvfrom_deinit,
	udp_recvfrom_recv,
	udp_recvfrom_handle,
	udp_recvfrom_send,
	udp_send_one,
};

#ifdef ENABLE_RECVMMSG
/* UDP recvmmsg() request struct. */
struct udp_recvmmsg {
	network_request_t **reqs;
	struct mmsghdr *msgs[NBUFS];
	unsigned active_buffers;
	unsigned rcvd;
	knot_mm_t mm;   /*!< used for allocating only in udp_recvmmsg, not for requests */
};

static void setup_mmsghdr_from_req(struct udp_recvmmsg *rq, size_t index)
{
	network_request_udp_t *udp_rq = udp_req_from_req(rq->reqs[index]);

	/* Initialize buffers with req */
	for (unsigned k = 0; k < NBUFS; ++k) {
		memcpy(&rq->msgs[k][index].msg_hdr, &udp_rq->msg[k], sizeof(rq->msgs[k][index]));
	}
}

static void *udp_recvmmsg_init(udp_context_t *udp)
{
	knot_mm_t mm;
	mm_ctx_mempool(&mm, sizeof(struct udp_recvmmsg));

	struct udp_recvmmsg *rq = mm_alloc(&mm, sizeof(struct udp_recvmmsg));
	if (rq == NULL) {
		return NULL;
	}
	memset(rq, 0, sizeof(*rq));
	memcpy(&rq->mm, &mm, sizeof(knot_mm_t));

	rq->reqs = mm_alloc(&mm, sizeof(network_request_t*) * RECVMMSG_BATCHLEN);
	if (rq->reqs == NULL) {
		return NULL;
	}
	memset(rq->reqs, 0, sizeof(network_request_t*) * RECVMMSG_BATCHLEN);

	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		rq->reqs[k] = network_allocate_request(&udp->network_ctx, &rq->mm, network_request_flag_udp_buff);
		if (rq->reqs[k] == NULL) {
			return NULL;
		}
	}

	/* Initialize buffers. */
	for (unsigned i = 0; i < NBUFS; ++i) {
		rq->msgs[i] = mm_alloc(&mm, sizeof(struct mmsghdr) * RECVMMSG_BATCHLEN);
	}

	for (unsigned k = 0; k < RECVMMSG_BATCHLEN; ++k) {
		setup_mmsghdr_from_req(rq, k);
	}

	rq->active_buffers = RECVMMSG_BATCHLEN;

	return rq;
}

static void udp_recvmmsg_deinit(udp_context_t *udp, void *d)
{
	struct udp_recvmmsg *rq = d;
	if (rq != NULL) {
		mp_delete(rq->mm.ctx);
	}
}

static int udp_recvmmsg_recv(udp_context_t *udp, int fd, void *d)
{
	struct udp_recvmmsg *rq = d;

	int n = recvmmsg(fd, rq->msgs[RX], rq->active_buffers, MSG_DONTWAIT, NULL);
	if (n > 0) {
		for (int i = 0; i < n; i++) {
			rq->reqs[i]->fd = fd;
		}
		rq->rcvd = n;
	}
	return n;
}

static int udp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct udp_recvmmsg *rq = d;

	/* Handle each received msg. */
	for (unsigned i = 0; i < rq->rcvd; ++i) {
		struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
		struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
		rx->iov_len = rq->msgs[RX][i].msg_len; /* Received bytes. */

		udp_pktinfo_handle(&rq->msgs[RX][i].msg_hdr, &rq->msgs[TX][i].msg_hdr);

		network_handle(&ctx->network_ctx, rq->reqs[i], NULL);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (! (rq->reqs[i]->flag & network_request_flag_is_async)) {
#endif
			rq->msgs[TX][i].msg_len = tx->iov_len;
			rq->msgs[TX][i].msg_hdr.msg_namelen = 0;
			if (tx->iov_len > 0) {
				/* @note sendmmsg() workaround to prevent sending the packet */
				rq->msgs[TX][i].msg_hdr.msg_namelen = rq->msgs[RX][i].msg_hdr.msg_namelen;
			}
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		} else {
			/* copy data from mmsghdr to req msghdr as we will be handling this separately. Only lens not copied, ptr are same. */
			network_request_udp_t *udp_rq = udp_req_from_req(rq->reqs[i]);
			udp_rq->msg[RX].msg_namelen = rq->msgs[RX][i].msg_hdr.msg_namelen;
			udp_rq->msg[RX].msg_controllen = rq->msgs[RX][i].msg_hdr.msg_controllen;
			udp_rq->msg[RX].msg_flags = rq->msgs[RX][i].msg_hdr.msg_flags;

			udp_rq->msg[TX].msg_namelen = rq->msgs[TX][i].msg_hdr.msg_namelen;
			udp_rq->msg[TX].msg_controllen = rq->msgs[TX][i].msg_hdr.msg_controllen;
			udp_rq->msg[TX].msg_flags = rq->msgs[TX][i].msg_hdr.msg_flags;

			rq->msgs[TX][i].msg_hdr.msg_namelen = 0;
			rq->msgs[TX][i].msg_len = 0;
			tx->iov_len = 0;
		}
#endif
	}

	return KNOT_EOK;
}

static void reset_mmsghdr_for_req(struct udp_recvmmsg *rq, int i)
{
	/* Reset buffer size and address len. */
	struct iovec *rx = rq->msgs[RX][i].msg_hdr.msg_iov;
	struct iovec *tx = rq->msgs[TX][i].msg_hdr.msg_iov;
	rx->iov_len = KNOT_WIRE_MAX_UDP_PKTSIZE; /* Reset RX buflen */
	tx->iov_len = KNOT_WIRE_MAX_UDP_PKTSIZE;

	network_request_udp_t *udp_rq = udp_req_from_req(rq->reqs[i]);
	memset(&udp_rq->addr, 0, sizeof(struct sockaddr_storage));
	rq->msgs[RX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
	rq->msgs[TX][i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
	rq->msgs[RX][i].msg_hdr.msg_controllen = sizeof(cmsg_pktinfo_t);

	/* Declare all bytes in the buffer are not initialized to valgrind.
	 * Otherwise, valgrind will think previous read/written packet data in current buffer is valid too and wont catch reading past current request packet. */
	VALGRIND_MAKE_MEM_UNDEFINED(rx->iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);
	VALGRIND_MAKE_MEM_UNDEFINED(tx->iov_base, KNOT_WIRE_MAX_UDP_PKTSIZE);
}

static int udp_recvmmsg_send(udp_context_t *udp, void *d)
{
	struct udp_recvmmsg *rq = d;
	int rc = sendmmsg(rq->reqs[0]->fd, rq->msgs[TX], rq->rcvd, 0);
	for (unsigned i = 0; i < rq->rcvd; ++i) {
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (! (rq->reqs[i]->flag & network_request_flag_is_async)) {
			/* don't cleanup requests in async state */
#endif
			reset_mmsghdr_for_req(rq, i);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		}
#endif
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	/* Restructure the asynced requests with new requests.
	 * Though we processed rq->recv in this iteration, previous iteration could have
	 * left some entries as not enough items in free pool. So check all items. */
	bool has_empty = false;
	for (unsigned i = 0; i < RECVMMSG_BATCHLEN; ++i) {
		if (rq->reqs[i] == NULL || (rq->reqs[i]->flag & network_request_flag_is_async)) {
			rq->reqs[i] = network_allocate_request(&udp->network_ctx, NULL, network_request_flag_udp_buff);
			if (rq->reqs[i]) {
				setup_mmsghdr_from_req(rq, i);
				reset_mmsghdr_for_req(rq, i);
			}
			else {
				has_empty = true;
			}
		}
	}

	size_t curr_max_buff = RECVMMSG_BATCHLEN;
	if (unlikely(has_empty)) {
		/* pack requests at beginning and adjust active_buffers */
		for (unsigned i = 0; i < curr_max_buff; ++i) {
			if (rq->reqs[i] == NULL) {
				/* find the item from end of list */
				for(--curr_max_buff; curr_max_buff > i && rq->reqs[curr_max_buff] == NULL; --curr_max_buff) {
				}

				if (rq->reqs[curr_max_buff] == NULL) {
					/* packing complete */
					break;
				}

				rq->reqs[i] = rq->reqs[curr_max_buff];
				rq->reqs[curr_max_buff] = NULL;
				setup_mmsghdr_from_req(rq, i); // reset is already done. No need to reset.
			}
		}
	}

	rq->active_buffers = curr_max_buff;
#endif

	return rc;
}

static udp_api_t udp_recvmmsg_api = {
	udp_recvmmsg_init,
	udp_recvmmsg_deinit,
	udp_recvmmsg_recv,
	udp_recvmmsg_handle,
	udp_recvmmsg_send,
	udp_send_one,
};
#endif /* ENABLE_RECVMMSG */

#ifdef ENABLE_XDP
struct xdp_recvmmsg {
	knot_xdp_msg_t msgs_rx[XDP_BATCHLEN];
	network_request_t *reqs[XDP_BATCHLEN];
	uint32_t active_buffers;
	uint32_t rcvd;
};

static void *xdp_recvmmsg_init(udp_context_t *udp)
{
	struct xdp_recvmmsg *rq = malloc(sizeof(*rq));
	if (rq != NULL) {
		memset(rq, 0, sizeof(*rq));

		for (int i = 0; i < XDP_BATCHLEN; i++) {
			rq->reqs[i] = network_allocate_request(&udp->network_ctx, NULL, network_request_flag_xdp_buff);
			if (rq->reqs[i]) {
				rq->active_buffers = i+1;
			}
		}
	}
	return rq;
}

static void xdp_recvmmsg_deinit(udp_context_t *udp, void *d)
{
	struct xdp_recvmmsg *rq = d;
	if (rq) {
		for (int i = 0; i < XDP_BATCHLEN; i++) {
			network_free_request(&udp->network_ctx, NULL, rq->reqs[i]);
		}
		free(rq);
	}
}

static int xdp_recvmmsg_recv(udp_context_t *udp, int fd, void *d)
{
	UNUSED(fd);
	struct xdp_recvmmsg *rq = d;

	int ret = knot_xdp_recv(udp->xdp_sock, rq->msgs_rx, rq->active_buffers, &rq->rcvd);

	return ret == KNOT_EOK ? rq->rcvd : ret;
}

static int xdp_recvmmsg_handle(udp_context_t *ctx, void *d)
{
	struct xdp_recvmmsg *rq = d;
	knot_xdp_msg_t completed_rx[XDP_BATCHLEN];

	knot_xdp_send_prepare(ctx->xdp_sock);

	uint32_t completed = 0;
	for (uint32_t i = 0; i < rq->rcvd; ++i) {
		bool is_ipv6 = rq->msgs_rx[i].ip_to.sin6_family == AF_INET6;
		if (rq->msgs_rx[i].payload.iov_len == 0) {
			continue; // Skip marked (zero length) messages.
		}
		network_request_xdp_t *xdp_req = xdp_req_from_req(rq->reqs[i]);
		assert(xdp_req->msg[RX].payload.iov_base == NULL);
		assert(xdp_req->msg[RX].payload.iov_len == 0);
		assert(xdp_req->msg[TX].payload.iov_base == NULL);
		assert(xdp_req->msg[TX].payload.iov_len == 0);
		int ret = knot_xdp_send_alloc(ctx->xdp_sock, is_ipv6,
		                              &xdp_req->msg[TX], &rq->msgs_rx[i]);
		if (ret != KNOT_EOK) {
			uint32_t revd = rq->rcvd;
			rq->rcvd = completed; /* These requests are handled, others are just ignored */
			for(; i < revd; ++i) { // Still free rest of RX buffers.
				completed_rx[completed].payload.iov_base = rq->msgs_rx[i].payload.iov_base;
				completed_rx[completed].ip_from.sin6_family = rq->msgs_rx[i].ip_from.sin6_family;
				completed++;
			}
			break;
		}

		// udp_pktinfo_handle not needed for XDP as one worker is bound
		// to one interface only.
		memcpy(&xdp_req->msg[RX].payload, &rq->msgs_rx[i].payload, sizeof(xdp_req->msg[RX].payload));
		network_handle(&ctx->network_ctx, rq->reqs[i], &rq->msgs_rx[i]);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (! (rq->reqs[i]->flag & network_request_flag_is_async)) {
#endif
			completed_rx[completed].payload.iov_base = rq->msgs_rx[i].payload.iov_base;
			completed_rx[completed].ip_from.sin6_family = rq->msgs_rx[i].ip_from.sin6_family;
			completed++;
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		}
#endif
	}

	knot_xdp_recv_finish(ctx->xdp_sock, completed_rx, completed);

	return KNOT_EOK;
}

static int xdp_recvmmsg_send(udp_context_t *udp, void *d)
{
	knot_xdp_msg_t completed_tx[XDP_BATCHLEN];
	struct xdp_recvmmsg *rq = d;
	uint32_t sent = 0;

	for (unsigned i = 0; i < rq->rcvd; ++i) {
		network_request_xdp_t *xdp_req = xdp_req_from_req(rq->reqs[i]);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (rq->reqs[i]->flag & network_request_flag_is_async) {
			/* The request is async. Move the entire xdp request info to request for further processing. */
			memcpy(&xdp_req->msg[RX], rq->msgs_rx + i, sizeof(rq->msgs_rx[i]));
		} else {
#endif
			memcpy(&completed_tx[sent++], &xdp_req->msg[TX], sizeof(completed_tx[0]));
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		}
#endif
	}

	int ret = knot_xdp_send(udp->xdp_sock, completed_tx, sent, &sent);
	knot_xdp_send_finish(udp->xdp_sock);

	memset(rq->msgs_rx, 0, sizeof(rq->msgs_rx));

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	int next = 0;
#endif
	for (unsigned i = 0; i < XDP_BATCHLEN; ++i) {
		network_request_xdp_t *xdp_req = xdp_req_from_req(rq->reqs[i]);
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (! (rq->reqs[i]->flag & network_request_flag_is_async)) {
			rq->reqs[next++] = rq->reqs[i];
#endif
			memset(xdp_req->msg, 0, sizeof(xdp_req->msg));
#ifdef ENABLE_ASYNC_QUERY_HANDLING
		}
#endif
	}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	for (; next < XDP_BATCHLEN; ++next) {
		rq->reqs[next] = network_allocate_request(&udp->network_ctx, NULL, network_request_flag_xdp_buff);
		if (rq->reqs[next] == NULL) {
			break;
		}
	}

	rq->active_buffers = next;
#endif

	return ret == KNOT_EOK ? sent : ret;
}

static int xdp_send_one(udp_context_t *udp, void *d)
{
	network_request_xdp_t *xdp_req = xdp_req_from_req(d);
	assert(xdp_req->msg[RX].payload.iov_base != NULL);
	assert(xdp_req->msg[RX].payload.iov_len != 0);
	assert(xdp_req->msg[TX].payload.iov_base != NULL);
	unsigned sent = 1;
	int ret = knot_xdp_send(udp->xdp_sock, &xdp_req->msg[TX], sent, &sent);
	knot_xdp_send_finish(udp->xdp_sock);
	memset(&xdp_req->msg[TX], 0, sizeof(xdp_req->msg[TX])); /* buffer is sent. cleanup to avoid second release from async completed */

	return ret == KNOT_EOK ? sent : ret;
}

static int xdp_free_async(udp_context_t *udp, void *d)
{
	network_request_xdp_t *xdp_req = xdp_req_from_req(d);
	assert(xdp_req->msg[RX].payload.iov_base != NULL);
	assert(xdp_req->msg[RX].payload.iov_len != 0);

	if (xdp_req->msg[TX].payload.iov_base) {
		unsigned sent = 1;
		xdp_req->msg[TX].payload.iov_len = 0; /* Just free it. Nothing to send. */
		knot_xdp_send(udp->xdp_sock, &xdp_req->msg[TX], sent, &sent);
		knot_xdp_send_finish(udp->xdp_sock);
		memset(&xdp_req->msg[TX], 0, sizeof(xdp_req->msg[TX]));
	}

	knot_xdp_recv_finish(udp->xdp_sock, &xdp_req->msg[RX], 1);
	memset(&xdp_req->msg[RX], 0, sizeof(xdp_req->msg[RX]));

	return KNOT_EOK;
}

static udp_api_t xdp_recvmmsg_api = {
	xdp_recvmmsg_init,
	xdp_recvmmsg_deinit,
	xdp_recvmmsg_recv,
	xdp_recvmmsg_handle,
	xdp_recvmmsg_send,
	xdp_send_one,
	xdp_free_async
};
#endif /* ENABLE_XDP */

static bool is_xdp_iface(const iface_t *iface)
{
	bool is_xdp1 = (iface->fd_xdp_count > 0);
	bool is_xdp2 = (iface->fd_udp_count == 0 && iface->fd_tcp_count == 0);
	assert(is_xdp1 == is_xdp2);
	return is_xdp1 || is_xdp2;
}

static bool is_xdp_thread(const iface_t *iface_zero, int thread_id)
{
	if (is_xdp_iface(iface_zero)) { // Only XDP interfaces.
		return (thread_id >= iface_zero->xdp_first_thread_id);
	} else {
		return (thread_id >= iface_zero->fd_udp_count + iface_zero->fd_tcp_count);
	}
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

static unsigned udp_set_ifaces(const iface_t *ifaces, size_t n_ifaces, struct pollfd *fds,
                               int thread_id, void **xdp_socket)
{
	if (n_ifaces == 0) {
		return 0;
	}

	bool xdp_thread = is_xdp_thread(ifaces, thread_id);

	unsigned count = 0;

	for (size_t i = 0; i < n_ifaces; i++) {
		int fd = iface_udp_fd(&ifaces[i], thread_id, xdp_thread,
		                      xdp_socket);
		if (fd < 0) {
			continue;
		}
		fds[count].fd = fd;
		fds[count].events = POLLIN;
		fds[count].revents = 0;
		count++;
	}

	assert(!xdp_thread || count == 1);
	return count;
}

int udp_send_response(network_context_t *ctx, network_request_t *req)
{
	udp_context_t *udp_ctx = container_of(ctx, udp_context_t, network_ctx);
	return udp_ctx->api->udp_send_single(udp_ctx, req);
}

int udp_async_complete(network_context_t *ctx, network_request_t *req)
{
	udp_context_t *udp_ctx = container_of(ctx, udp_context_t, network_ctx);
	if (udp_ctx->api->udp_free_async) {
		udp_ctx->api->udp_free_async(udp_ctx, req);
	}
	network_free_request(ctx, NULL, req);
	return KNOT_EOK;
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
	if (is_xdp_thread(handler->server->ifaces, thread_id)) {
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

	/* Allocate descriptors for the configured interfaces. */
	size_t nifs = handler->server->n_ifaces;
	struct pollfd fds[nifs+1];
	int fds_offset = 0;

	/* Create UDP answering context. */
	udp_context_t udp = {0};
	udp.api = api;
	void *rq = NULL;

	if (network_context_initialize(&udp.network_ctx, handler->server, thread_id,
									KNOTD_QUERY_FLAG_NO_AXFR | KNOTD_QUERY_FLAG_NO_IXFR /* No transfers. */
									| KNOTD_QUERY_FLAG_LIMIT_SIZE, /* Enforce UDP packet size limit. */
									response_handler_type_final,
								   	udp_send_response,
									udp_async_complete) != KNOT_EOK) {
		goto finish;
	}

	rq = api->udp_init(&udp);

#ifdef ENABLE_ASYNC_QUERY_HANDLING
	fds[0].fd = network_context_get_async_notify_handle(&udp.network_ctx);
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	fds_offset += 1;
#endif

	unsigned nfds = udp_set_ifaces(handler->server->ifaces, nifs, fds + fds_offset,
	                               thread_id, &udp.xdp_sock);
	if (nfds == 0) {
		goto finish;
	}

	/* Loop until all data is read. */
	for (;;) {
		/* Cancellation point. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Wait for events. */
		int events = poll(fds, nfds + fds_offset, -1);
		if (events <= 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			break;
		}

#ifdef ENABLE_ASYNC_QUERY_HANDLING
		if (fds[0].revents != 0) {
			network_handle_async_completed_queries(&udp.network_ctx);
			fds[0].revents = 0;
		}
#endif

		/* Process the events. */
		for (unsigned i = 0; i < nfds && events > 0; i++) {
			if (fds[i + fds_offset].revents == 0) {
				continue;
			}
			events -= 1;
			if (api->udp_recv(&udp, fds[i + fds_offset].fd, rq) > 0) {
				api->udp_handle(&udp, rq);
				api->udp_send(&udp, rq);
			}
		}
	}

finish:
	if (rq) {
		api->udp_deinit(&udp, rq);
	}

	return KNOT_EOK;
}
