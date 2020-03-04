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

#include "libknot/xdp/af_xdp.h"

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/error.h"
#include "libknot/xdp/bpf-user.h"

#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/filter.h>

#include "contrib/macros.h"

#define FRAME_SIZE 4096
#define UMEM_FRAME_COUNT 8192

/** The memory layout of each umem frame. */
struct umem_frame {
	union { uint8_t bytes[FRAME_SIZE]; union {

	struct udpv4 udpv4;
	struct udpv6 udpv6;

	}; };
};

static const size_t FRAME_PAYLOAD_OFFSET4 = offsetof(struct udpv4, data) + offsetof(struct umem_frame, udpv4);
static const size_t FRAME_PAYLOAD_OFFSET6 = offsetof(struct udpv6, data) + offsetof(struct umem_frame, udpv6);

static const struct xsk_umem_config global_umem_config = {
	.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
	.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
	.frame_size = FRAME_SIZE, // used in xsk_umem__create()
	.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
};

static int configure_xsk_umem(const struct xsk_umem_config *umem_config,
                              uint32_t frame_count, struct xsk_umem_info **out_umem)
{
	struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
	if (umem == NULL) {
		return KNOT_ENOMEM;
	}

	/* Allocate memory for the frames, aligned to a page boundary. */
	umem->frame_count = frame_count;
	int ret = posix_memalign((void **)&umem->frames, getpagesize(), FRAME_SIZE * frame_count);
	if (ret != 0) {
		free(umem);
		return knot_map_errno_code(ret);

	}
	/* Initialize our "frame allocator". */
	umem->free_indices = malloc(frame_count * sizeof(umem->free_indices[0]));
	if (umem->free_indices == NULL) {
		free(umem->frames);
		free(umem);
		return KNOT_ENOMEM;
	}
	umem->free_count = frame_count;
	for (uint32_t i = 0; i < frame_count; ++i) {
		umem->free_indices[i] = i;
	}

	ret = xsk_umem__create(&umem->umem, umem->frames, FRAME_SIZE * frame_count,
	                       &umem->fq, &umem->cq, umem_config);
	if (ret != KNOT_EOK) {
		free(umem->free_indices);
		free(umem->frames);
		free(umem);
		return ret;
	}

	*out_umem = umem;
	return KNOT_EOK;
}

/** undo configure_xsk_umem() */
static void deconfigure_xsk_umem(struct xsk_umem_info *umem)
{
	xsk_umem__delete(umem->umem); // return code cases don't seem useful
	free(umem->frames);
	free(umem->free_indices);
	free(umem);
}

static struct umem_frame *kxsk_alloc_umem_frame(struct xsk_umem_info *umem)
{
	if (unlikely(umem->free_count == 0)) {
		return NULL;
	}

	uint32_t index = umem->free_indices[--umem->free_count];
	return umem->frames + index;
}

_public_
int knot_xsk_alloc_packet(struct knot_xsk_socket *socket, bool ipv6,
                          knot_xsk_msg_t *out, const knot_xsk_msg_t *in_reply_to)
{
	size_t ofs = ipv6 ? FRAME_PAYLOAD_OFFSET6 : FRAME_PAYLOAD_OFFSET4;

	struct umem_frame *uframe = kxsk_alloc_umem_frame(socket->umem);
	if (uframe == NULL) {
		return KNOT_ENOENT;
	}

	memset(out, 0, sizeof(*out));

	out->payload.iov_base = ipv6 ? uframe->udpv6.data : uframe->udpv4.data;
	out->payload.iov_len = MIN(UINT16_MAX, FRAME_SIZE - ofs);

	const struct ethhdr *eth = (struct ethhdr *)uframe;
	out->eth_from = (void *)&eth->h_source;
	out->eth_to = (void *)&eth->h_dest;

	if (in_reply_to != NULL) {
		memcpy(out->eth_from, in_reply_to->eth_to, ETH_ALEN);
		memcpy(out->eth_to, in_reply_to->eth_from, ETH_ALEN);

		memcpy(&out->ip_from, &in_reply_to->ip_to, sizeof(out->ip_from));
		memcpy(&out->ip_to, &in_reply_to->ip_from, sizeof(out->ip_to));
	}
	return KNOT_EOK;
}

static void kxsk_dealloc_umem_frame(struct xsk_umem_info *umem, uint8_t *uframe_p)
{
	assert(umem->free_count < umem->frame_count);
	ptrdiff_t diff = uframe_p - umem->frames->bytes;
	size_t index = diff / FRAME_SIZE;
	assert(index < umem->frame_count);
	umem->free_indices[umem->free_count++] = index;
}

_public_
void knot_xsk_deinit(struct knot_xsk_socket *socket)
{
	if (socket == NULL) {
		return;
	}

	kxsk_socket_stop(socket->iface, socket->if_queue);
	xsk_socket__delete(socket->xsk);
	deconfigure_xsk_umem(socket->umem);

	kxsk_iface_free((struct kxsk_iface *)/*const-cast*/socket->iface);
	free(socket);
}

/** Add some free frames into the RX fill queue (possibly zero, etc.) */
static int kxsk_umem_refill(struct xsk_umem_info *umem)
{
	/* First find to_reserve: how many frames to move to the RX fill queue.
	 * Let's keep about as many frames ready for TX (free_count) as for RX (fq_ready),
	 * and don't fill the queue to more than a half. */
	const int fq_target = global_umem_config.fill_size / 2;
	uint32_t fq_free = xsk_prod_nb_free(&umem->fq, 65536*256);
		/* TODO: not nice - ^^ the caching logic inside is the other way,
		 * so we disable it clumsily by passing a high value. */
	if (fq_free <= fq_target) {
		return KNOT_EOK;
	}
	const int fq_ready = global_umem_config.fill_size - fq_free;
	const int balance = (fq_ready + umem->free_count) / 2;
	const int fq_want = MIN(balance, fq_target); // don't overshoot the target
	const int to_reserve = fq_want - fq_ready;
	if (to_reserve <= 0) {
		return KNOT_EOK;
	}

	/* Now really reserve the frames. */
	uint32_t idx;
	int ret = xsk_ring_prod__reserve(&umem->fq, to_reserve, &idx);
	if (ret != to_reserve) {
		assert(false);
		return KNOT_ESPACE;
	}
	for (int i = 0; i < to_reserve; ++i, ++idx) {
		struct umem_frame *uframe = kxsk_alloc_umem_frame(umem);
		if (!uframe) {
			assert(false);
			return KNOT_ESPACE;
		}
		size_t offset = uframe->bytes - umem->frames->bytes;
		*xsk_ring_prod__fill_addr(&umem->fq, idx) = offset;
	}
	xsk_ring_prod__submit(&umem->fq, to_reserve);
	return KNOT_EOK;
}

static struct knot_xsk_socket *xsk_configure_socket(struct xsk_umem_info *umem,
                                                    const struct kxsk_iface *iface,
                                                    int if_queue)
{
	errno = -kxsk_umem_refill(umem);
	if (errno) {
		return NULL;
	}

	struct knot_xsk_socket *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info) {
		return NULL;
	}
	xsk_info->iface = iface;
	xsk_info->if_queue = if_queue;
	xsk_info->umem = umem;

	const struct xsk_socket_config sock_conf = {
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	};

	errno = xsk_socket__create(&xsk_info->xsk, iface->ifname,
	                           xsk_info->if_queue, umem->umem,
	                           &xsk_info->rx, &xsk_info->tx, &sock_conf);
	if (errno) {
		free(xsk_info);
		return NULL;
	} else {
		return xsk_info;
	}
}

static inline uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

// TODO: slow?
static __be16 pkt_ipv4_checksum_2(const struct iphdr *h)
{
	const uint16_t *ha = (const uint16_t *)h;
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i) {
		if (i != 5) {
			sum32 += be16toh(ha[i]);
		}
	}
	return ~htobe16(from32to16(sum32));
}

static void udp_checksum1(size_t *result, const void *_data, size_t _data_len)
{
	assert(!(_data_len & 1));
	const uint16_t *data = _data;
	size_t len = _data_len / 2;
	while (len-- > 0) {
		*result += *data++;
	}
}

static void udp_checksum_finish(size_t *result)
{
	while (*result > 0xffff) {
		*result = (*result & 0xffff) + (*result >> 16);
	}
	if (*result != 0xffff) {
		*result = ~*result;
	}
}

static int pkt_send(struct knot_xsk_socket *xsk, uint64_t addr, uint32_t len)
{
	uint32_t tx_idx;
	int ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
	if (unlikely(ret != 1)) {
		return KNOT_NET_ESEND;
	}

	*xsk_ring_prod__tx_desc(&xsk->tx, tx_idx) = (struct xdp_desc){
		.addr = addr,
		.len = len,
	};
	xsk_ring_prod__submit(&xsk->tx, 1);
	xsk->kernel_needs_wakeup = true;
	return KNOT_EOK;
}

static uint8_t *msg_uframe_p(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg)
{
	// FIXME: for some reason the message alignment isn't what we expect
	//uint8_t *uframe_p = msg->payload.iov_base - FRAME_PAYLOAD_OFFSET;
	uint8_t *uNULL = NULL;
	uint8_t *uframe_p = uNULL + ((msg->payload.iov_base - NULL) & ~(FRAME_SIZE - 1));
	const uint8_t *umem_mem_start = socket->umem->frames->bytes;
	if (//((uframe_p - uNULL) % FRAME_SIZE != 0) ||
	    ((uframe_p - umem_mem_start) / FRAME_SIZE >= socket->umem->frame_count)) {
		// not allocated msg->payload correctly
		return NULL;
	}

	return uframe_p;
}

static int xsk_sendmsg_ipv4(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg_uframe_p(socket, msg);
	if (uframe_p == NULL) {
		return KNOT_EINVAL;
	}

	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	struct udpv4 *h = &uframe->udpv4;

	// sockaddr* contents is already in network byte order
	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)&msg->ip_to;

	const uint16_t udp_len = sizeof(h->udp) + msg->payload.iov_len;
	h->udp.len = htobe16(udp_len);
	h->udp.source = src_v4->sin_port;
	h->udp.dest   = dst_v4->sin_port;
	h->udp.check  = 0;

	h->ipv4.ihl      = 5; // required <= hdr len 20
	h->ipv4.version  = 4;
	h->ipv4.tos      = 0; // default: best-effort DSCP + no ECN support
	h->ipv4.tot_len  = htobe16(20 + udp_len);
	h->ipv4.id       = 0; // probably anything; details: RFC 6864
	h->ipv4.frag_off = 0;
	h->ipv4.ttl      = IPDEFTTL;
	h->ipv4.protocol = 0x11; // UDP

	memcpy(&h->ipv4.saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&h->ipv4.daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
	h->ipv4.check = pkt_ipv4_checksum_2(&h->ipv4);
#pragma GCC diagnostic pop

	// MAC addresses are assumed to be already there.
	h->eth.h_proto = htobe16(ETH_P_IP);

	uint32_t eth_len = FRAME_PAYLOAD_OFFSET4 + msg->payload.iov_len;

	return pkt_send(socket, h->bytes - socket->umem->frames->bytes, eth_len);
}

static int xsk_sendmsg_ipv6(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg_uframe_p(socket, msg);
	if (uframe_p == NULL) {
		return KNOT_EINVAL;
	}

	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	struct udpv6 *h = &uframe->udpv6;

	// sockaddr* contents is already in network byte order
	const struct sockaddr_in6 *src_v6 = (const struct sockaddr_in6 *)&msg->ip_from;
	const struct sockaddr_in6 *dst_v6 = (const struct sockaddr_in6 *)&msg->ip_to;

	const uint16_t udp_len = sizeof(h->udp) + msg->payload.iov_len;
	h->udp.len = htobe16(udp_len);
	h->udp.source = src_v6->sin6_port;
	h->udp.dest   = dst_v6->sin6_port;
	h->udp.check  = 0;

	h->ipv6.version = 6;
	h->ipv6.payload_len = htobe16(udp_len);
	memset(h->ipv6.flow_lbl, 0, sizeof(h->ipv6.flow_lbl));
	h->ipv6.hop_limit = IPDEFTTL;
	h->ipv6.nexthdr = 17; // UDP
	h->ipv6.priority = 0;

	memcpy(&h->ipv6.saddr, &src_v6->sin6_addr, sizeof(src_v6->sin6_addr));
	memcpy(&h->ipv6.daddr, &dst_v6->sin6_addr, sizeof(dst_v6->sin6_addr));

	// UDP checksum is mandatory for IPv6, in contrast to IPv4
	size_t chk = 0;
	udp_checksum1(&chk, &h->ipv6.saddr, sizeof(h->ipv6.saddr));
	udp_checksum1(&chk, &h->ipv6.daddr, sizeof(h->ipv6.daddr));
	udp_checksum1(&chk, &h->udp.len, sizeof(h->udp.len));
	__be16 version = htobe16(h->ipv6.nexthdr);
	udp_checksum1(&chk, &version, sizeof(version));
	udp_checksum1(&chk, &h->udp, sizeof(h->udp));
	size_t padded_len = msg->payload.iov_len;
	if (padded_len & 1) {
		((uint8_t *)msg->payload.iov_base)[padded_len++] = 0;
	}
	udp_checksum1(&chk, msg->payload.iov_base, padded_len);
	udp_checksum_finish(&chk);
	h->udp.check = chk;

	// MAC addresses are assumed to be already there.
	h->eth.h_proto = htobe16(ETH_P_IPV6);

	uint32_t eth_len = FRAME_PAYLOAD_OFFSET6 + msg->payload.iov_len;

	return pkt_send(socket, h->bytes - socket->umem->frames->bytes, eth_len);
}

_public_
int knot_xsk_sendmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg)
{
	switch (msg->ip_from.ss_family) {
	case AF_INET:
		return xsk_sendmsg_ipv4(socket, msg);
	case AF_INET6:
		return xsk_sendmsg_ipv6(socket, msg);
	default:
		return KNOT_EINVAL;
	}
}

_public_
int knot_xsk_sendmmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[], uint32_t count, uint32_t *sent)
{
	int ret = KNOT_EOK;
	*sent = 0;
	for (int i = 0; i < count && ret == KNOT_EOK; i++) {
		if (msgs[i].payload.iov_len > 0) {
			ret = knot_xsk_sendmsg(socket, &msgs[i]);
			*sent += (ret == KNOT_EOK ? 1 : 0);
		}
	}
	return ret;
}

/** Periodical callback. Just using 'the_socket' global. */
_public_
int knot_xsk_check(struct knot_xsk_socket *socket)
{
	/* Trigger sending queued packets. */
	if (socket->kernel_needs_wakeup) {
		int sendret = sendto(xsk_socket__fd(socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		bool is_ok = (sendret != -1);
		const bool is_again = !is_ok && (errno == EWOULDBLOCK || errno == EAGAIN);
		if (is_ok || is_again) {
			socket->kernel_needs_wakeup = false;
			// EAGAIN is unclear; we'll retry the syscall later, to be sure
		}
		if (!is_ok && !is_again) {
			return KNOT_EAGAIN;
		}
		/* This syscall might be avoided with a newer kernel feature (>= 5.4):
		   https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-use-need-wakeup-bind-flag
		   Unfortunately it's not easy to continue supporting older kernels
		   when using this feature on newer ones.
		 */
	}

	/* Collect completed packets. */
	struct xsk_ring_cons *cq = &socket->umem->cq;
	uint32_t idx_cq;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx_cq);
	if (!completed) {
		return KNOT_EOK;
	}

	/* Free shared memory. */
	for (int i = 0; i < completed; ++i, ++idx_cq) {
		uint8_t *uframe_p = (uint8_t *)socket->umem->frames
		                    + *xsk_ring_cons__comp_addr(cq, idx_cq)
		                    - offsetof(struct umem_frame, udpv4); // udpv6 has same offset
		kxsk_dealloc_umem_frame(socket->umem, uframe_p);
	}

	xsk_ring_cons__release(cq, completed);
	//TODO: one uncompleted packet/batch is left until the next I/O :-/
	/* And feed frames into RX fill queue. */
	return kxsk_umem_refill(socket->umem);
}

static int rx_desc(struct knot_xsk_socket *xsi, const struct xdp_desc *desc,
		   knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = xsi->umem->frames->bytes + desc->addr;
	const struct ethhdr *eth = (struct ethhdr *)uframe_p;
	const struct iphdr *ipv4 = NULL;
	const struct ipv6hdr *ipv6 = NULL;
	const struct udphdr *udp = NULL;

	int ret = KNOT_EOK;

	// FIXME: length checks on multiple places
	if (eth->h_proto == htobe16(ETH_P_IP)) {
		ipv4 = (struct iphdr *)(uframe_p + sizeof(struct ethhdr));
		// Any fragmentation stuff is bad for use, except for the DF flag
		uint16_t frag_off = be16toh(ipv4->frag_off);
		if (ipv4->version != 4 || (frag_off & ~(1 << 14))) {
			ret = KNOT_EFEWDATA;
			goto free_frame;
		}
		if (ipv4->protocol != 0x11) { // UDP
			ret = KNOT_ESEMCHECK;
			goto free_frame;
		}
		// FIXME ipv4->check (sensitive to ipv4->ihl), ipv4->tot_len, udp->len
		udp = (struct udphdr *)(uframe_p + sizeof(struct ethhdr) + ipv4->ihl * 4);

	} else if (eth->h_proto == htobe16(ETH_P_IPV6)) {
		ipv6 = (struct ipv6hdr *)(uframe_p + sizeof(struct ethhdr));
		if (ipv6->version != 6) {
			ret = KNOT_EFEWDATA;
			goto free_frame;
		}
		udp = (struct udphdr *)(uframe_p + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)); // TODO ???
	} else {
		ret = KNOT_ENOTSUP;
		goto free_frame;
	}

	assert(eth && (!!ipv4 != !!ipv6) && udp);

	msg->payload.iov_base = (uint8_t *)udp + sizeof(struct udphdr);
	msg->payload.iov_len = be16toh(udp->len) - sizeof(struct udphdr);

	msg->eth_from = (void *)&eth->h_source;
	msg->eth_to = (void *)&eth->h_dest;

	// process the packet; ownership is passed on, but beware of holding frames
	if (ipv4) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *)&msg->ip_from;
		struct sockaddr_in *dst_v4 = (struct sockaddr_in *)&msg->ip_to;
		memcpy(&src_v4->sin_addr, &ipv4->saddr, sizeof(src_v4->sin_addr));
		memcpy(&dst_v4->sin_addr, &ipv4->daddr, sizeof(dst_v4->sin_addr));
		src_v4->sin_port = udp->source;
		dst_v4->sin_port = udp->dest;
		src_v4->sin_family = AF_INET;
		dst_v4->sin_family = AF_INET;
	} else {
		assert(ipv6);
		struct sockaddr_in6 *src_v6 = (struct sockaddr_in6 *)&msg->ip_from;
		struct sockaddr_in6 *dst_v6 = (struct sockaddr_in6 *)&msg->ip_to;
		memcpy(&src_v6->sin6_addr, &ipv6->saddr, sizeof(src_v6->sin6_addr));
		memcpy(&dst_v6->sin6_addr, &ipv6->daddr, sizeof(dst_v6->sin6_addr));
		src_v6->sin6_port = udp->source;
		dst_v6->sin6_port = udp->dest;
		src_v6->sin6_family = AF_INET6;
		dst_v6->sin6_family = AF_INET6;
		// TODO shall we anyhow handle flow info ?
	}

	return KNOT_EOK;

free_frame:
	kxsk_dealloc_umem_frame(xsi->umem, uframe_p);
	return ret;
}

_public_
int knot_xsk_recvmmsg(struct knot_xsk_socket *socket, knot_xsk_msg_t msgs[], uint32_t max_count, uint32_t *count)
{
	uint32_t idx_rx = 0;
	int ret = KNOT_EOK;
	const ssize_t i_max = xsk_ring_cons__peek(&socket->rx, max_count, &idx_rx);
	assert(i_max <= max_count);

	ssize_t i;
	for (i = 0; i < i_max && ret == KNOT_EOK; ++idx_rx) {
		ret = rx_desc(socket, xsk_ring_cons__rx_desc(&socket->rx, idx_rx), &msgs[i]);
		++i; /* we need to do it even after the last iteration */
	}

	/* At this point we processed the first i buffers and skipped the rest (if any). */
	xsk_ring_cons__release(&socket->rx, i);
	*count = i;
	return ret;
}

_public_
void knot_xsk_free_recvd(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg_uframe_p(socket, msg);
	assert(uframe_p);
	if (uframe_p != NULL) {
		kxsk_dealloc_umem_frame(socket->umem, uframe_p);
	}
}

_public_
int knot_xsk_init(struct knot_xsk_socket **socket, const char *ifname, int if_queue,
                  int listen_port, knot_xsk_load_bpf_t load_bpf)
{
	if (socket == NULL || *socket != NULL) {
		return KNOT_EINVAL;
	}

	struct kxsk_iface *iface;
	int ret = kxsk_iface_new(ifname, load_bpf, &iface);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Initialize shared packet_buffer for umem usage */
	struct xsk_umem_info *umem = NULL;
	ret = configure_xsk_umem(&global_umem_config, UMEM_FRAME_COUNT, &umem);
	if (ret != KNOT_EOK) {
		kxsk_iface_free(iface);
		return ret;
	}

	*socket = xsk_configure_socket(umem, iface, if_queue);
	if (!*socket) {
		deconfigure_xsk_umem(umem);
		kxsk_iface_free(iface);
		return KNOT_NET_ESOCKET;
	}

	ret = kxsk_socket_start(iface, (*socket)->if_queue, listen_port, (*socket)->xsk);
	if (ret != KNOT_EOK) {
		xsk_socket__delete((*socket)->xsk);
		deconfigure_xsk_umem(umem);
		kxsk_iface_free(iface);
		free(*socket);
		*socket = NULL;
		return ret;
	}

	return ret;
}

_public_
int knot_xsk_get_poll_fd(struct knot_xsk_socket *socket)
{
	return xsk_socket__fd(socket->xsk);
}
