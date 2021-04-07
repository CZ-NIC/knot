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

#include <assert.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/xdp/bpf-user.h"
#include "libknot/xdp/xdp.h"
#include "contrib/macros.h"
#include "contrib/asan.h"
#include "contrib/memcheck.h"

/* Don't fragment flag. */
#define	IP_DF 0x4000

#define FRAME_SIZE 2048
#define UMEM_FRAME_COUNT_RX 4096
#define UMEM_FRAME_COUNT_TX UMEM_FRAME_COUNT_RX // No reason to differ so far.
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

/*! \brief The memory layout of IPv4 umem frame. */
struct udpv4 {
	union {
		uint8_t bytes[1];
		struct {
			struct ethhdr eth; // No VLAN support; CRC at the "end" of .data!
			struct iphdr ipv4;
			struct udphdr udp;
			uint8_t data[];
		} __attribute__((packed));
	};
};

/*! \brief The memory layout of IPv6 umem frame. */
struct udpv6 {
	union {
		uint8_t bytes[1];
		struct {
			struct ethhdr eth; // No VLAN support; CRC at the "end" of .data!
			struct ipv6hdr ipv6;
			struct udphdr udp;
			uint8_t data[];
		} __attribute__((packed));
	};
};

/*! \brief The memory layout of each umem frame. */
struct umem_frame {
	union {
		uint8_t bytes[FRAME_SIZE];
		union {
			struct udpv4 udpv4;
			struct udpv6 udpv6;
		};
	};
};

_public_
const size_t KNOT_XDP_PAYLOAD_OFFSET4 = offsetof(struct udpv4, data) + offsetof(struct umem_frame, udpv4);
_public_
const size_t KNOT_XDP_PAYLOAD_OFFSET6 = offsetof(struct udpv6, data) + offsetof(struct umem_frame, udpv6);

static int configure_xsk_umem(struct kxsk_umem **out_umem)
{
	/* Allocate memory and call driver to create the UMEM. */
	struct kxsk_umem *umem = calloc(1,
		offsetof(struct kxsk_umem, tx_free_indices)
		+ sizeof(umem->tx_free_indices[0]) * UMEM_FRAME_COUNT_TX);
	if (umem == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = posix_memalign((void **)&umem->frames, getpagesize(),
	                         FRAME_SIZE * UMEM_FRAME_COUNT);
	if (ret != 0) {
		free(umem);
		return KNOT_ENOMEM;
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
	for (uint32_t i = 0; i < UMEM_FRAME_COUNT_TX; ++i) {
		umem->tx_free_indices[i] = i;
	}

	/* Designate the rest of buffers for RX, and pass them to the driver. */
	uint32_t idx = 0;
	ret = xsk_ring_prod__reserve(&umem->fq, UMEM_FRAME_COUNT_RX, &idx);
	if (ret != UMEM_FRAME_COUNT - UMEM_FRAME_COUNT_TX) {
		assert(0);
		return KNOT_ERROR;
	}
	assert(idx == 0);
	for (uint32_t i = UMEM_FRAME_COUNT_TX; i < UMEM_FRAME_COUNT; ++i) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
	}
	xsk_ring_prod__submit(&umem->fq, UMEM_FRAME_COUNT_RX);

	return KNOT_EOK;
}

static void deconfigure_xsk_umem(struct kxsk_umem *umem)
{
	(void)xsk_umem__delete(umem->umem);
	free(umem->frames);
	free(umem);
}

static int configure_xsk_socket(struct kxsk_umem *umem,
                                const struct kxsk_iface *iface,
                                knot_xdp_socket_t **out_sock)
{
	knot_xdp_socket_t *xsk_info = calloc(1, sizeof(*xsk_info));
	if (xsk_info == NULL) {
		return KNOT_ENOMEM;
	}
	xsk_info->iface = iface;
	xsk_info->umem = umem;

	const struct xsk_socket_config sock_conf = {
		.tx_size = UMEM_RING_LEN_TX,
		.rx_size = UMEM_RING_LEN_RX,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
	};

	int ret = xsk_socket__create(&xsk_info->xsk, iface->if_name,
	                             iface->if_queue, umem->umem,
	                             &xsk_info->rx, &xsk_info->tx, &sock_conf);
	if (ret != 0) {
		free(xsk_info);
		return ret;
	}

	*out_sock = xsk_info;
	return KNOT_EOK;
}

_public_
int knot_xdp_init(knot_xdp_socket_t **socket, const char *if_name, int if_queue,
                  uint32_t listen_port, knot_xdp_load_bpf_t load_bpf)
{
	if (socket == NULL || if_name == NULL) {
		return KNOT_EINVAL;
	}

	struct kxsk_iface *iface;
	int ret = kxsk_iface_new(if_name, if_queue, load_bpf, &iface);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Initialize shared packet_buffer for umem usage. */
	struct kxsk_umem *umem = NULL;
	ret = configure_xsk_umem(&umem);
	if (ret != KNOT_EOK) {
		kxsk_iface_free(iface);
		return ret;
	}

	ret = configure_xsk_socket(umem, iface, socket);
	if (ret != KNOT_EOK) {
		deconfigure_xsk_umem(umem);
		kxsk_iface_free(iface);
		return ret;
	}

	ret = kxsk_socket_start(iface, listen_port, (*socket)->xsk);
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
void knot_xdp_deinit(knot_xdp_socket_t *socket)
{
	if (socket == NULL) {
		return;
	}

	kxsk_socket_stop(socket->iface);
	xsk_socket__delete(socket->xsk);
	deconfigure_xsk_umem(socket->umem);

	kxsk_iface_free((struct kxsk_iface *)/*const-cast*/socket->iface);
	free(socket);
}

_public_
int knot_xdp_socket_fd(knot_xdp_socket_t *socket)
{
	if (socket == NULL) {
		return 0;
	}

	return xsk_socket__fd(socket->xsk);
}

static void tx_free_relative(struct kxsk_umem *umem, uint64_t addr_relative)
{
	/* The address may not point to *start* of buffer, but `/` solves that. */
	uint64_t index = addr_relative / FRAME_SIZE;
	assert(index < UMEM_FRAME_COUNT);
	umem->tx_free_indices[umem->tx_free_count++] = index;
}

_public_
void knot_xdp_send_prepare(knot_xdp_socket_t *socket)
{
	if (socket == NULL) {
		return;
	}

	struct kxsk_umem *const umem = socket->umem;
	struct xsk_ring_cons *const cq = &umem->cq;

	uint32_t idx = 0;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx);
	if (completed == 0) {
		return;
	}
	assert(umem->tx_free_count + completed <= UMEM_FRAME_COUNT_TX);

	for (uint32_t i = 0; i < completed; ++i) {
		uint64_t addr_relative = *xsk_ring_cons__comp_addr(cq, idx++);
		tx_free_relative(umem, addr_relative);
	}

	xsk_ring_cons__release(cq, completed);
}

static struct umem_frame *alloc_tx_frame(struct kxsk_umem *umem)
{
	if (unlikely(umem->tx_free_count == 0)) {
		return NULL;
	}

	uint32_t index = umem->tx_free_indices[--umem->tx_free_count];
	return umem->frames + index;
}

_public_
int knot_xdp_send_alloc(knot_xdp_socket_t *socket, bool ipv6, knot_xdp_msg_t *out,
                        const knot_xdp_msg_t *in_reply_to)
{
	if (socket == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	size_t ofs = ipv6 ? KNOT_XDP_PAYLOAD_OFFSET6 : KNOT_XDP_PAYLOAD_OFFSET4;

	struct umem_frame *uframe = alloc_tx_frame(socket->umem);
	if (uframe == NULL) {
		return KNOT_ENOMEM;
	}

	/* Ideally we should declare the memory not valid when we free the tx frame.
	 * But tx is added to pool with actual data and bpf after sending makes the data invalid.
	 * Since no way to intercept and declare invalid after sent, let us at least reset the data validity before reusing the buffer */
	VALGRIND_MAKE_MEM_UNDEFINED(uframe, sizeof(struct umem_frame));

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

static uint16_t from32to16(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

static uint16_t ipv4_checksum(const uint8_t *ipv4_hdr)
{
	const uint16_t *h = (const uint16_t *)ipv4_hdr;
	uint32_t sum32 = 0;
	for (int i = 0; i < 10; ++i) {
		if (i != 5) {
			sum32 += h[i];
		}
	}
	return ~from32to16(sum32);
}

/* Checksum endianness implementation notes for ipv4_checksum() and udp_checksum_step().
 *
 * The basis for checksum is addition on big-endian 16-bit words, with bit 16 carrying
 * over to bit 0.  That can be viewed as first byte carrying to the second and the
 * second one carrying back to the first one, i.e. a symmetrical situation.
 * Therefore the result is the same even when arithmetics is done on litte-endian (!)
 */

static void udp_checksum_step(size_t *result, const void *_data, size_t _data_len)
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

static uint8_t *msg_uframe_ptr(knot_xdp_socket_t *socket, const knot_xdp_msg_t *msg,
                               /* Next parameters are just for debugging. */
                               bool ipv6)
{
	uint8_t *uNULL = NULL;
	uint8_t *uframe_p = uNULL + ((msg->payload.iov_base - NULL) & ~(FRAME_SIZE - 1));

#ifndef NDEBUG
	intptr_t pd = (uint8_t *)msg->payload.iov_base - uframe_p
	              - (ipv6 ? KNOT_XDP_PAYLOAD_OFFSET6 : KNOT_XDP_PAYLOAD_OFFSET4);
	/* This assertion might fire in some OK cases.  For example, the second branch
	 * had to be added for cases with "emulated" AF_XDP support. */
	assert(pd == XDP_PACKET_HEADROOM || pd == 0);

	const uint8_t *umem_mem_start = socket->umem->frames->bytes;
	const uint8_t *umem_mem_end = umem_mem_start + FRAME_SIZE * UMEM_FRAME_COUNT;
	assert(umem_mem_start <= uframe_p && uframe_p < umem_mem_end);
#endif
	return uframe_p;
}

static void xsk_sendmsg_ipv4(knot_xdp_socket_t *socket, const knot_xdp_msg_t *msg,
                             uint32_t index)
{
	uint8_t *uframe_p = msg_uframe_ptr(socket, msg, false);
	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	struct udpv4 *h = &uframe->udpv4;

	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)&msg->ip_to;
	const uint16_t udp_len = sizeof(h->udp) + msg->payload.iov_len;

	h->eth.h_proto = __constant_htons(ETH_P_IP);

	h->ipv4.version  = IPVERSION;
	h->ipv4.ihl      = 5;
	h->ipv4.tos      = 0;
	h->ipv4.tot_len  = htobe16(5 * 4 + udp_len);
	h->ipv4.id       = 0;
	h->ipv4.frag_off = 0;
	h->ipv4.ttl      = IPDEFTTL;
	h->ipv4.protocol = IPPROTO_UDP;
	memcpy(&h->ipv4.saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&h->ipv4.daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));
	h->ipv4.check    = ipv4_checksum(h->bytes + sizeof(struct ethhdr));

	h->udp.len    = htobe16(udp_len);
	h->udp.source = src_v4->sin_port;
	h->udp.dest   = dst_v4->sin_port;
	h->udp.check  = 0; // Optional for IPv4 - not computed.

	*xsk_ring_prod__tx_desc(&socket->tx, index) = (struct xdp_desc){
		.addr = h->bytes - socket->umem->frames->bytes,
		.len = KNOT_XDP_PAYLOAD_OFFSET4 + msg->payload.iov_len
	};
}

static void xsk_sendmsg_ipv6(knot_xdp_socket_t *socket, const knot_xdp_msg_t *msg,
                             uint32_t index)
{
	uint8_t *uframe_p = msg_uframe_ptr(socket, msg, true);
	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	struct udpv6 *h = &uframe->udpv6;

	const struct sockaddr_in6 *src_v6 = (const struct sockaddr_in6 *)&msg->ip_from;
	const struct sockaddr_in6 *dst_v6 = (const struct sockaddr_in6 *)&msg->ip_to;
	const uint16_t udp_len = sizeof(h->udp) + msg->payload.iov_len;

	h->eth.h_proto = __constant_htons(ETH_P_IPV6);

	h->ipv6.version     = 6;
	h->ipv6.priority    = 0;
	memset(h->ipv6.flow_lbl, 0, sizeof(h->ipv6.flow_lbl));
	h->ipv6.payload_len = htobe16(udp_len);
	h->ipv6.nexthdr     = IPPROTO_UDP;
	h->ipv6.hop_limit   = IPDEFTTL;
	memcpy(&h->ipv6.saddr, &src_v6->sin6_addr, sizeof(src_v6->sin6_addr));
	memcpy(&h->ipv6.daddr, &dst_v6->sin6_addr, sizeof(dst_v6->sin6_addr));

	h->udp.len    = htobe16(udp_len);
	h->udp.source = src_v6->sin6_port;
	h->udp.dest   = dst_v6->sin6_port;
	h->udp.check  = 0; // Mandatory for IPv6 - computed afterwards.

	size_t chk = 0;
	udp_checksum_step(&chk, &h->ipv6.saddr, sizeof(h->ipv6.saddr));
	udp_checksum_step(&chk, &h->ipv6.daddr, sizeof(h->ipv6.daddr));
	udp_checksum_step(&chk, &h->udp.len, sizeof(h->udp.len));
	__be16 version = htobe16(h->ipv6.nexthdr);
	udp_checksum_step(&chk, &version, sizeof(version));
	udp_checksum_step(&chk, &h->udp, sizeof(h->udp));
	size_t padded_len = msg->payload.iov_len;
	if (padded_len & 1) {
		((uint8_t *)msg->payload.iov_base)[padded_len++] = 0;
	}
	udp_checksum_step(&chk, msg->payload.iov_base, padded_len);
	udp_checksum_finish(&chk);
	h->udp.check = chk;

	*xsk_ring_prod__tx_desc(&socket->tx, index) = (struct xdp_desc){
		.addr = h->bytes - socket->umem->frames->bytes,
		.len = KNOT_XDP_PAYLOAD_OFFSET6 + msg->payload.iov_len
	};
}

_public_
int knot_xdp_send(knot_xdp_socket_t *socket, const knot_xdp_msg_t msgs[],
                  uint32_t count, uint32_t *sent)
{
	if (socket == NULL || msgs == NULL || sent == NULL) {
		return KNOT_EINVAL;
	}

	/* Now we want to do something close to
	 *   xsk_ring_prod__reserve(&socket->tx, count, *idx)
	 * but we don't know in advance if we utilize *whole* `count`,
	 * and the API doesn't allow "cancelling reservations".
	 * Therefore we handle `socket->tx.cached_prod` by hand;
	 * that's simplified by the fact that there is always free space.
	 */
	assert(UMEM_RING_LEN_TX > UMEM_FRAME_COUNT_TX);
	uint32_t idx = socket->tx.cached_prod;

	for (uint32_t i = 0; i < count; ++i) {
		const knot_xdp_msg_t *msg = &msgs[i];

		if (msg->payload.iov_len && msg->ip_from.sin6_family == AF_INET) {
			xsk_sendmsg_ipv4(socket, msg, idx++);
		} else if (msg->payload.iov_len && msg->ip_from.sin6_family == AF_INET6) {
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
int knot_xdp_send_finish(knot_xdp_socket_t *socket)
{
	if (socket == NULL) {
		return KNOT_EINVAL;
	}

	/* Trigger sending queued packets. */
	if (!socket->kernel_needs_wakeup) {
		return KNOT_EOK;
	}

	int ret = sendto(xsk_socket__fd(socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	const bool is_ok = (ret >= 0);
	// List of "safe" errors taken from
	// https://github.com/torvalds/linux/blame/master/samples/bpf/xdpsock_user.c
	const bool is_again = !is_ok && (errno == ENOBUFS || errno == EAGAIN
	                                || errno == EBUSY || errno == ENETDOWN);
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

static void rx_desc(knot_xdp_socket_t *socket, const struct xdp_desc *desc,
                    knot_xdp_msg_t *msg)
{
	uint8_t *uframe_p = socket->umem->frames->bytes + desc->addr;
	const struct ethhdr *eth = (struct ethhdr *)uframe_p;
	const struct iphdr *ip4 = NULL;
	const struct ipv6hdr *ip6 = NULL;
	const struct udphdr *udp = NULL;
	VALGRIND_MAKE_MEM_DEFINED(uframe_p, desc->len);

	if (desc->len <= sizeof(*eth)) {
		assert(0);
		msg->payload.iov_len  = 0; // not enough data to be a valid eth packet.
	}

	switch (eth->h_proto) {
	case __constant_htons(ETH_P_IP):
		if (desc->len <= KNOT_XDP_PAYLOAD_OFFSET4) {
			assert(0);
			msg->payload.iov_len  = 0; // not enough data to be a valid ipv4 udp request.
		}
		ip4 = (struct iphdr *)(uframe_p + sizeof(struct ethhdr));
		// Next conditions are ensured by the BPF filter.
		assert(ip4->version == 4);
		assert(ip4->frag_off == 0 ||
		       ip4->frag_off == __constant_htons(IP_DF));
		assert(ip4->protocol == IPPROTO_UDP);
		// IPv4 header checksum is not verified!
		udp = (struct udphdr *)(uframe_p + sizeof(struct ethhdr) +
		                        ip4->ihl * 4);
		break;
	case __constant_htons(ETH_P_IPV6):
		if (desc->len <= KNOT_XDP_PAYLOAD_OFFSET6) {
			assert(0);
			msg->payload.iov_len  = 0; // not enough data to be a valid ipv6 udp request.
		}
		ip6 = (struct ipv6hdr *)(uframe_p + sizeof(struct ethhdr));
		// Next conditions are ensured by the BPF filter.
		assert(ip6->version == 6);
		assert(ip6->nexthdr == IPPROTO_UDP);
		udp = (struct udphdr *)(uframe_p + sizeof(struct ethhdr) +
		                        sizeof(struct ipv6hdr));
		break;
	default:
		assert(0);
		msg->payload.iov_len = 0;
		return;
	}
	// UDP checksum is not verified!

	assert(eth && (!!ip4 != !!ip6) && udp);

	// Process the packet; ownership is passed on, beware of holding frames.

	msg->payload.iov_base = (uint8_t *)udp + sizeof(struct udphdr);
	msg->payload.iov_len = be16toh(udp->len) - sizeof(struct udphdr);

	msg->eth_from = (void *)&eth->h_source;
	msg->eth_to = (void *)&eth->h_dest;

	if (ip4 != NULL) {
		struct sockaddr_in *src_v4 = (struct sockaddr_in *)&msg->ip_from;
		struct sockaddr_in *dst_v4 = (struct sockaddr_in *)&msg->ip_to;
		memcpy(&src_v4->sin_addr, &ip4->saddr, sizeof(src_v4->sin_addr));
		memcpy(&dst_v4->sin_addr, &ip4->daddr, sizeof(dst_v4->sin_addr));
		src_v4->sin_port = udp->source;
		dst_v4->sin_port = udp->dest;
		src_v4->sin_family = AF_INET;
		dst_v4->sin_family = AF_INET;
	} else {
		assert(ip6);
		struct sockaddr_in6 *src_v6 = (struct sockaddr_in6 *)&msg->ip_from;
		struct sockaddr_in6 *dst_v6 = (struct sockaddr_in6 *)&msg->ip_to;
		memcpy(&src_v6->sin6_addr, &ip6->saddr, sizeof(src_v6->sin6_addr));
		memcpy(&dst_v6->sin6_addr, &ip6->daddr, sizeof(dst_v6->sin6_addr));
		src_v6->sin6_port = udp->source;
		dst_v6->sin6_port = udp->dest;
		src_v6->sin6_family = AF_INET6;
		dst_v6->sin6_family = AF_INET6;
		// Flow label is ignored.
	}
}

_public_
int knot_xdp_recv(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[],
                  uint32_t max_count, uint32_t *count)
{
	if (socket == NULL || msgs == NULL || count == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t idx = 0;
	const uint32_t available = xsk_ring_cons__peek(&socket->rx, max_count, &idx);
	if (available == 0) {
		*count = 0;
		return KNOT_EOK;
	}
	assert(available <= max_count);

	for (uint32_t i = 0; i < available; ++i) {
		rx_desc(socket, xsk_ring_cons__rx_desc(&socket->rx, idx++), &msgs[i]);
	}

	xsk_ring_cons__release(&socket->rx, available);
	*count = available;

	return KNOT_EOK;
}

_public_
void knot_xdp_recv_finish(knot_xdp_socket_t *socket, const knot_xdp_msg_t msgs[],
                          uint32_t count)
{
	if (socket == NULL || msgs == NULL) {
		return;
	}

	struct kxsk_umem *const umem = socket->umem;
	struct xsk_ring_prod *const fq = &umem->fq;

	uint32_t idx = 0;
	const uint32_t reserved = xsk_ring_prod__reserve(fq, count, &idx);
	assert(reserved == count);

	for (uint32_t i = 0; i < reserved; ++i) {
		bool ipv6 = msgs[i].ip_from.sin6_family == AF_INET6;
		/* Since memory buffer is reused, inform valgrind that data in the buffer is not valid even though app has set the value at somepoint. */
		VALGRIND_MAKE_MEM_UNDEFINED((uint8_t*)msgs[i].payload.iov_base - (ipv6 ? KNOT_XDP_PAYLOAD_OFFSET6 : KNOT_XDP_PAYLOAD_OFFSET4), FRAME_SIZE);
		uint8_t *uframe_p = msg_uframe_ptr(socket, &msgs[i], ipv6);
		uint64_t offset = uframe_p - umem->frames->bytes;
		*xsk_ring_prod__fill_addr(fq, idx++) = offset;
	}

	xsk_ring_prod__submit(fq, reserved);
}

_public_
void knot_xdp_info(const knot_xdp_socket_t *socket, FILE *file)
{
	if (socket == NULL || file == NULL) {
		return;
	}

	// The number of busy frames
	#define RING_BUSY(ring) \
		((*(ring)->producer - *(ring)->consumer) & (ring)->mask)

	#define RING_PRINFO(name, ring) \
		fprintf(file, "Ring %s: size %4d, busy %4d (prod %4d, cons %4d)\n", \
		        name, (unsigned)(ring)->size, \
		        (unsigned)RING_BUSY((ring)), \
		        (unsigned)*(ring)->producer, (unsigned)*(ring)->consumer)

	const int rx_busyf = RING_BUSY(&socket->umem->fq) + RING_BUSY(&socket->rx);
	fprintf(file, "\nLOST RX frames: %4d", (int)(UMEM_FRAME_COUNT_RX - rx_busyf));

	const int tx_busyf = RING_BUSY(&socket->umem->cq) + RING_BUSY(&socket->tx);
	const int tx_freef = socket->umem->tx_free_count;
	fprintf(file, "\nLOST TX frames: %4d\n", (int)(UMEM_FRAME_COUNT_TX - tx_busyf - tx_freef));

	RING_PRINFO("FQ", &socket->umem->fq);
	RING_PRINFO("RX", &socket->rx);
	RING_PRINFO("TX", &socket->tx);
	RING_PRINFO("CQ", &socket->umem->cq);
	fprintf(file, "TX free frames: %4d\n", tx_freef);
}
