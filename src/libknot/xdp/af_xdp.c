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

#define FRAME_SIZE 2048
#define UMEM_FRAME_COUNT_RX 4096
#define UMEM_FRAME_COUNT_TX UMEM_FRAME_COUNT_RX /* no reason to differ so far */
#define UMEM_RING_LEN_RX (UMEM_FRAME_COUNT_RX * 2)
#define UMEM_RING_LEN_TX (UMEM_FRAME_COUNT_TX * 2)
#define UMEM_FRAME_COUNT (UMEM_FRAME_COUNT_RX + UMEM_FRAME_COUNT_TX)

/* With recent compilers we statically check #defines for settings that
 * get refused by AF_XDP drivers (in current versions, at least). */
#if (__STDC_VERSION__ >= 201112L)
#define IS_POWER_OF_2(n) (((n) & (n - 1)) == 0)
_Static_assert((FRAME_SIZE == 4096 || FRAME_SIZE == 2048)
	&& IS_POWER_OF_2(UMEM_FRAME_COUNT)
	/* The following two inequalities aren't required by drivers, but they allow
	 * our implementation assume that the rings can never get filled. */
	&& IS_POWER_OF_2(UMEM_RING_LEN_RX) && UMEM_RING_LEN_RX > UMEM_FRAME_COUNT_RX
	&& IS_POWER_OF_2(UMEM_RING_LEN_TX) && UMEM_RING_LEN_TX > UMEM_FRAME_COUNT_TX
	&& UMEM_FRAME_COUNT_TX <= (1 << 16) /* see tx_free_indices */
	, "Incorrect #define combination for AF_XDP.");
#endif

_public_
void knot_xsk_print_frames(const knot_xsk_socket_t *s)
{
       // The number of busy frames
       #define RING_BUSY(ring) \
               ((*(ring)->producer - *(ring)->consumer) & (ring)->mask)

       #define RING_PRINFO(name, ring) \
               printf("Ring %s: size %4d, busy %4d (prod %4d, cons %4d)\n", \
                       name, (unsigned)(ring)->size, \
                       (unsigned)RING_BUSY((ring)), \
                       (unsigned)*(ring)->producer, (unsigned)*(ring)->consumer)

       const int rx_busyf = RING_BUSY(&s->umem->fq) + RING_BUSY(&s->rx);
       printf("\nLOST RX frames: %4d", (int)(UMEM_FRAME_COUNT_RX - rx_busyf));


       const int tx_busyf = RING_BUSY(&s->umem->cq) + RING_BUSY(&s->tx);
       const int tx_freef = s->umem->tx_free_count;
       printf("\nLOST TX frames: %4d\n", (int)(UMEM_FRAME_COUNT_TX - tx_busyf - tx_freef));

       RING_PRINFO("FQ", &s->umem->fq);
       RING_PRINFO("RX", &s->rx);
       RING_PRINFO("TX", &s->tx);
       RING_PRINFO("CQ", &s->umem->cq);
       printf("TX free frames: %4d\n", tx_freef);
}

/** The memory layout of each umem frame. */
struct umem_frame {
	union { uint8_t bytes[FRAME_SIZE]; union {

	struct udpv4 udpv4;
	struct udpv6 udpv6;

	}; };
};

static const size_t FRAME_PAYLOAD_OFFSET4 = offsetof(struct udpv4, data) + offsetof(struct umem_frame, udpv4);
static const size_t FRAME_PAYLOAD_OFFSET6 = offsetof(struct udpv6, data) + offsetof(struct umem_frame, udpv6);

static int configure_xsk_umem(struct xsk_umem_info **out_umem)
{
	/* Allocate memory and call driver to create the UMEM. */
	struct xsk_umem_info *umem = calloc(1,
			offsetof(struct xsk_umem_info, tx_free_indices)
			+ sizeof(umem->tx_free_indices[0]) * UMEM_FRAME_COUNT_TX);
	if (umem == NULL) {
		return KNOT_ENOMEM;
	}
	int ret = posix_memalign((void **)&umem->frames, getpagesize(),
				 FRAME_SIZE * UMEM_FRAME_COUNT);
	if (ret != 0) {
		free(umem);
		return knot_map_errno_code(ret);

	}
	const struct xsk_umem_config config = {
		.fill_size = UMEM_RING_LEN_RX,
		.comp_size = UMEM_RING_LEN_TX,
		.frame_size = FRAME_SIZE,
		.frame_headroom = 0,
	};
	ret = xsk_umem__create(&umem->umem, umem->frames, FRAME_SIZE * UMEM_FRAME_COUNT,
	                       &umem->fq, &umem->cq, &config);
	if (ret != KNOT_EOK) {
		free(umem->frames);
		free(umem);
		return ret;
	}
	*out_umem = umem;

	/* Designate the starting chunk of buffers for TX, and put them onto the stack. */
	umem->tx_free_count = UMEM_FRAME_COUNT_TX;
	for (int buf_i = 0; buf_i < UMEM_FRAME_COUNT_TX; ++buf_i) {
		umem->tx_free_indices[buf_i] = buf_i;
	}

	/* Designate the rest of buffers for RX, and pass them to the driver. */
	uint32_t ring_i = -1/*shut up incorrect warning*/;
	ret = xsk_ring_prod__reserve(&umem->fq, UMEM_FRAME_COUNT_RX, &ring_i);
	if (ret != UMEM_FRAME_COUNT - UMEM_FRAME_COUNT_TX) {
		abort(); // impossible, but let's abort at least
	}
	assert(ring_i == 0);
	for (ssize_t buf_i = UMEM_FRAME_COUNT_TX; buf_i < UMEM_FRAME_COUNT; ++buf_i, ++ring_i) {
		*xsk_ring_prod__fill_addr(&umem->fq, ring_i) = buf_i * FRAME_SIZE;
	}
	xsk_ring_prod__submit(&umem->fq, UMEM_FRAME_COUNT_RX);

	return KNOT_EOK;
}

/** undo configure_xsk_umem() */
static void deconfigure_xsk_umem(struct xsk_umem_info *umem)
{
	xsk_umem__delete(umem->umem); // return code cases don't seem useful
	free(umem->frames);
	free(umem);
}

static struct umem_frame *kxsk_alloc_tx_frame(struct xsk_umem_info *umem)
{
	if (unlikely(umem->tx_free_count == 0)) {
		return NULL;
	}

	uint32_t index = umem->tx_free_indices[--umem->tx_free_count];
	return umem->frames + index;
}

_public_
int knot_xsk_alloc_packet(struct knot_xsk_socket *socket, bool ipv6,
                          knot_xsk_msg_t *out, const knot_xsk_msg_t *in_reply_to)
{
	size_t ofs = ipv6 ? FRAME_PAYLOAD_OFFSET6 : FRAME_PAYLOAD_OFFSET4;

	struct umem_frame *uframe = kxsk_alloc_tx_frame(socket->umem);
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

static struct knot_xsk_socket *xsk_configure_socket(struct xsk_umem_info *umem,
                                                    const struct kxsk_iface *iface,
                                                    int if_queue)
{
	struct knot_xsk_socket *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info) {
		return NULL;
	}
	xsk_info->iface = iface;
	xsk_info->if_queue = if_queue;
	xsk_info->umem = umem;

	const struct xsk_socket_config sock_conf = {
		.tx_size = UMEM_RING_LEN_TX,
		.rx_size = UMEM_RING_LEN_RX,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
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

static uint8_t *msg_uframe_p(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg,
			/* these are just for debugging */
			     bool ipv6, bool send)
{
	uint8_t *uNULL = NULL;
	uint8_t *uframe_p = uNULL + ((msg->payload.iov_base - NULL) & ~(FRAME_SIZE - 1));
	assert(uframe_p == msg->payload.iov_base // this assertion is unimportant
			- (ipv6 ? FRAME_PAYLOAD_OFFSET6 : FRAME_PAYLOAD_OFFSET4)
			- (send ? 0 : XDP_PACKET_HEADROOM));
	const uint8_t *umem_mem_start = socket->umem->frames->bytes;
	const uint8_t *umem_mem_end = umem_mem_start + FRAME_SIZE * UMEM_FRAME_COUNT;
	if (uframe_p < umem_mem_start || uframe_p >= umem_mem_end) {
		// not allocated msg->payload correctly
		assert(0);
		return NULL;
	}

	return uframe_p;
}

static void xsk_sendmsg_ipv4(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg,
                             uint32_t index)
{
	uint8_t *uframe_p = msg_uframe_p(socket, msg, false, true);

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

	*xsk_ring_prod__tx_desc(&socket->tx, index) = (struct xdp_desc){
		.addr = h->bytes - socket->umem->frames->bytes,
		.len = eth_len,
	};
}

static void xsk_sendmsg_ipv6(struct knot_xsk_socket *socket, const knot_xsk_msg_t *msg,
                             uint32_t index)
{
	uint8_t *uframe_p = msg_uframe_p(socket, msg, true, true);

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

	*xsk_ring_prod__tx_desc(&socket->tx, index) = (struct xdp_desc){
		.addr = h->bytes - socket->umem->frames->bytes,
		.len = eth_len,
	};
}

static void tx_free_relative(struct xsk_umem_info *umem, uint64_t addr_relative)
{
	/* The address may not point to *start* of buffer, but `/` solves that. */
	uint64_t index = addr_relative / FRAME_SIZE;
	assert(index < UMEM_FRAME_COUNT);
	umem->tx_free_indices[umem->tx_free_count++] = index;
}

_public_
int knot_xsk_sendmmsg(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[], uint32_t count, uint32_t *sent)
{
	if (socket == NULL || msgs == NULL || sent == NULL) {
		return KNOT_EINVAL;
	}

	// FIXME: explain why we do this by hand!
	uint32_t idx = socket->tx.cached_prod;

	for (uint32_t i = 0; i < count; ++i) {
		const knot_xsk_msg_t *msg = &msgs[i];

		if (msg->payload.iov_len && msg->ip_from.ss_family == AF_INET) {
			xsk_sendmsg_ipv4(socket, msg, idx++);
		} else if (msg->payload.iov_len && msg->ip_from.ss_family == AF_INET6) {
			xsk_sendmsg_ipv6(socket, msg, idx++);
		} else {
			/* Some problem; we just ignore this message. */
			uint64_t addr_relative = (uint8_t *)msg->payload.iov_base
						- socket->umem->frames->bytes;
			tx_free_relative(socket->umem, addr_relative);
		}
	}

	*sent = idx - socket->tx.cached_prod;
	assert(*sent <= count);
	socket->tx.cached_prod = idx;
	xsk_ring_prod__submit(&socket->tx, *sent);
	socket->kernel_needs_wakeup = true;

	return KNOT_EOK;
}

_public_
void knot_xsk_prepare_alloc(struct knot_xsk_socket *socket)
{
	struct xsk_umem_info *umem = socket->umem;
	struct xsk_ring_cons *cq = &umem->cq;
	uint32_t idx_cq;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx_cq);
	if (!completed) return;
	assert(umem->tx_free_count + completed <= UMEM_FRAME_COUNT_TX);
	for (int i = 0; i < completed; ++i, ++idx_cq) {
		uint64_t addr_relative = *xsk_ring_cons__comp_addr(cq, idx_cq);
		tx_free_relative(umem, addr_relative);
	}
	xsk_ring_cons__release(cq, completed);
}

_public_
int knot_xsk_sendmsg_finish(struct knot_xsk_socket *socket)
{
	/* Trigger sending queued packets. */
	if (!socket->kernel_needs_wakeup) {
		return KNOT_EOK;
	}
	int sendret = sendto(xsk_socket__fd(socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	bool is_ok = (sendret != -1);
	const bool is_again = !is_ok && (errno == EWOULDBLOCK || errno == EAGAIN);
	// Some of the !is_ok cases are a little unclear - what to do about the syscall,
	// including how caller of _sendmsg_finish() should react.
	if (is_ok || !is_again) {
		socket->kernel_needs_wakeup = false;
	}
	if (is_again) {
		return KNOT_EAGAIN;
	} else if (is_ok) {
		return KNOT_EOK;
	} else {
		return -errno;
	}
	/* This syscall might be avoided with a newer kernel feature (>= 5.4):
	   https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-use-need-wakeup-bind-flag
	   Unfortunately it's not easy to continue supporting older kernels
	   when using this feature on newer ones.
	 */
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
	knot_xsk_free_recvd(xsi, msg, 1);
	return ret;
}

_public_
int knot_xsk_recvmmsg(struct knot_xsk_socket *socket, knot_xsk_msg_t msgs[], uint32_t max_count, uint32_t *count)
{
	int ret = KNOT_EOK;
	uint32_t idx_rx = 0;
	const ssize_t i_max = xsk_ring_cons__peek(&socket->rx, max_count, &idx_rx);
	assert(i_max <= max_count);

	ssize_t i;
	for (i = 0; i < i_max && ret == KNOT_EOK; ++i) {
		ret = rx_desc(socket, xsk_ring_cons__rx_desc(&socket->rx, idx_rx++), &msgs[i]);
	}

	/* At this point we processed the first i buffers and skipped the rest (if any). */
	xsk_ring_cons__release(&socket->rx, i);
	*count = i;
	return ret;
}

_public_
void knot_xsk_free_recvd(struct knot_xsk_socket *socket, const knot_xsk_msg_t msgs[],
			 uint32_t count)
{
	struct xsk_ring_prod * const fq = &socket->umem->fq;
	uint32_t idx = -1/*shut up incorrect warning*/;
	int ret = xsk_ring_prod__reserve(fq, count, &idx);
	if (ret != count) abort(); // impossible, but let's abort at least

	uint32_t count_ok = 0;
	for (uint32_t msg_i = 0; msg_i < count; ++msg_i) {
		uint8_t *uframe_p = msg_uframe_p(socket, &msgs[msg_i],
				msgs[msg_i].ip_from.ss_family == AF_INET6, false);
		if (!uframe_p) continue;
		uint64_t offset = uframe_p - socket->umem->frames->bytes;
		*xsk_ring_prod__fill_addr(fq, idx + count_ok) = offset;
		++count_ok;
	}
	assert(count_ok == count);
	xsk_ring_prod__submit(fq, count_ok);
}

_public_
int knot_xsk_init(struct knot_xsk_socket **socket, const char *ifname, int if_queue,
                  uint32_t listen_port, knot_xsk_load_bpf_t load_bpf)
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
	ret = configure_xsk_umem(&umem);
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
