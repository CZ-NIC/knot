/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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



/* LATER:
 *  - XDP_USE_NEED_WAKEUP (optimization discussed in summer 2019)
 */

#include "libknot/xdp/af_xdp.h"

#include "libknot/attribute.h"
#include "libknot/error.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#ifdef KR_XDP_ETH_CRC
#include <zlib.h>
#endif

#include <byteswap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_link.h>
#include <linux/filter.h>
//#include <linux/icmpv6.h>

//#include "contrib/ucw/lib.h"
#include "contrib/ucw/mempool.h"
#include "contrib/macros.h"

//#include "lib/resolve.h"
//#include "daemon/session.h"
//#include "daemon/worker.h"


#include "libknot/xdp/bpf-user.h"

// placate libclang :-/
//typedef uint64_t size_t;

#define FRAME_SIZE 4096
#define RX_BATCH_SIZE 64

/** The memory layout of each umem frame. */
struct umem_frame {
	union { uint8_t bytes[FRAME_SIZE]; struct {

	struct udpv4 udpv4;

	}; };
};

static const size_t UDPV4_PAYLOAD_OFFSET = offsetof(struct udpv4, data);
static const size_t FRAME_PAYLOAD_OFFSET = UDPV4_PAYLOAD_OFFSET + offsetof(struct umem_frame, udpv4);

// FIXME later: get rid of those singletons!
struct xsk_socket_info *the_socket = NULL;
struct kxsk_config *the_config = NULL;

/** Swap two bytes as a *constant* expression.  ATM we assume we're LE, i.e. we do need to swap. */
#define BS16(n) (((n) >> 8) + (((n) & 0xff) << 8))
#define BS32 bswap_32

static struct xsk_umem_info *configure_xsk_umem(const struct xsk_umem_config *umem_config,
						uint32_t frame_count)
{
	struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
	if (!umem) return NULL;

	/* Allocate memory for the frames, aligned to a page boundary. */
	umem->frame_count = frame_count;
	errno = posix_memalign((void **)&umem->frames, getpagesize(), FRAME_SIZE * frame_count);
	if (errno) goto failed;
	/* Initialize our "frame allocator". */
	umem->free_indices = malloc(frame_count * sizeof(umem->free_indices[0]));
	if (!umem->free_indices) goto failed;
	umem->free_count = frame_count;
	for (uint32_t i = 0; i < frame_count; ++i)
		umem->free_indices[i] = i;

	// NOTE: we don't need a fill queue (fq), but the API won't allow us to call
	// with NULL - perhaps it doesn't matter that we don't utilize it later.
	errno = -xsk_umem__create(&umem->umem, umem->frames, FRAME_SIZE * frame_count,
				  &umem->fq, &umem->cq, umem_config);
	if (errno) goto failed;

	return umem;
failed:
	free(umem->free_indices);
	free(umem->frames);
	free(umem);
	return NULL;
}

static struct umem_frame *xsk_alloc_umem_frame(struct xsk_umem_info *umem)
{
	if (unlikely(umem->free_count == 0)) {
		return NULL;
	}

	uint32_t index = umem->free_indices[--umem->free_count];
	return umem->frames + index;
}

_public_
struct iovec knot_xsk_alloc_frame()
{
	struct iovec res = { 0 };

	struct umem_frame *uframe = xsk_alloc_umem_frame(the_socket->umem);
	if (uframe != NULL) {
		res.iov_len = MIN(UINT16_MAX, FRAME_SIZE - FRAME_PAYLOAD_OFFSET - 4/*eth CRC*/);
		res.iov_base = uframe->udpv4.data;
	}
	return res;
}

static void xsk_dealloc_umem_frame(struct xsk_umem_info *umem, uint8_t *uframe_p)
// TODO: confusing to use xsk_
{
	assert(umem->free_count < umem->frame_count);
	ptrdiff_t diff = uframe_p - umem->frames->bytes;
	size_t index = diff / FRAME_SIZE;
	assert(index < umem->frame_count);
	umem->free_indices[umem->free_count++] = index;
}

_public_
void knot_xsk_deinit()
{
	if (!the_socket)
		return;
	kxsk_socket_stop(the_socket->iface, the_config->xsk_if_queue);
	xsk_socket__delete(the_socket->xsk);
	xsk_umem__delete(the_socket->umem->umem);

	kxsk_iface_free((struct kxsk_iface *)/*const-cast*/the_socket->iface, false);
	//TODO: more memory
}

/** Add some free frames into the RX fill queue (possibly zero, etc.) */
static int kxsk_umem_refill(const struct kxsk_config *cfg, struct xsk_umem_info *umem)
{
	/* First find to_reserve: how many frames to move to the RX fill queue.
	 * Let's keep about as many frames ready for TX (free_count) as for RX (fq_ready),
	 * and don't fill the queue to more than a half. */
	const int fq_target = cfg->umem.fill_size / 2;
	uint32_t fq_free = xsk_prod_nb_free(&umem->fq, fq_target);
	printf("refill target %d free %u\n", fq_target, fq_free);
	if (fq_free <= fq_target)
		return 0;
	const int fq_ready = cfg->umem.fill_size - fq_free;
	const int balance = (fq_ready + umem->free_count) / 2;
	const int fq_want = MIN(balance, fq_target); // don't overshoot the target
	const int to_reserve = fq_want - fq_ready;
	//kr_log_verbose("[uxsk] refilling %d frames TX->RX; TX = %d, RX = %d\n",
	//               to_reserve, (int)umem->free_count, (int)fq_ready);
	printf("refill ready=%d balance=%d want=%d reserve=%d\n", fq_ready, balance, fq_want, to_reserve);
	if (to_reserve <= 0)
		return 0;

	/* Now really reserve the frames. */
	uint32_t idx;
	int ret = xsk_ring_prod__reserve(&umem->fq, to_reserve, &idx);
	if (ret != to_reserve) {
		assert(false);
		return ENOSPC;
	}
	for (int i = 0; i < to_reserve; ++i, ++idx) {
		struct umem_frame *uframe = xsk_alloc_umem_frame(umem);
		if (!uframe) {
			assert(false);
			return ENOSPC;
		}
		size_t offset = uframe->bytes - umem->frames->bytes;
		*xsk_ring_prod__fill_addr(&umem->fq, idx) = offset;
	}
	xsk_ring_prod__submit(&umem->fq, to_reserve);
	return 0;
}

static struct xsk_socket_info *xsk_configure_socket(struct kxsk_config *cfg,
                                                    struct xsk_umem_info *umem,
                                                    const struct kxsk_iface *iface)
{
	/* Put a couple RX buffers into the fill queue.
	 * Even if we don't need them, it silences a dmesg line,
	 * and it avoids 100% CPU usage of ksoftirqd/i for each queue i!
	 */
	errno = kxsk_umem_refill(cfg, umem);
	if (errno)
		return NULL;

	struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;
	xsk_info->iface = iface;
	xsk_info->umem = umem;

	assert(cfg->xsk.libbpf_flags & XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD);
	errno = xsk_socket__create(&xsk_info->xsk, iface->ifname,
	                           cfg->xsk_if_queue, umem->umem,
	                           &xsk_info->rx, &xsk_info->tx, &cfg->xsk);

	return xsk_info;
}

/* Two helper functions taken from Linux kernel 5.2, slightly modified. */
__attribute__ ((unused))
static inline uint32_t from64to32(uint64_t x)
{
	/* add up 32-bit and 32-bit for 32+c bit */
	x = (x & 0xffffffff) + (x >> 32);
	/* add up carry.. */
	x = (x & 0xffffffff) + (x >> 32);
	return (uint32_t)x;
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
	for (int i = 0; i < 10; ++i)
		if (i != 5)
			sum32 += BS16(ha[i]);
	return ~BS16(from32to16(sum32));
}

static int pkt_send(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len)
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

static uint8_t *msg_uframe_p(const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg->payload.iov_base - FRAME_PAYLOAD_OFFSET;
	const uint8_t *umem_mem_start = the_socket->umem->frames->bytes;
	if (((uframe_p - (uint8_t *)NULL) % FRAME_SIZE != 0) ||
	    ((uframe_p - umem_mem_start) / FRAME_SIZE >= the_socket->umem->frame_count)) {
		// not allocated msg->payload correctly
		return NULL;
	}

	return uframe_p;
}

_public_
int knot_xsk_sendmsg(const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg_uframe_p(msg);
	if (uframe_p == NULL) {
		return KNOT_EINVAL;
	}

	struct umem_frame *uframe = (struct umem_frame *)uframe_p;
	struct udpv4 *h = &uframe->udpv4;

	// sockaddr* contents is already in network byte order
	const struct sockaddr_in *src_v4 = (const struct sockaddr_in *)&msg->ip_from;
	const struct sockaddr_in *dst_v4 = (const struct sockaddr_in *)&msg->ip_to;

	const uint16_t udp_len = sizeof(h->udp) + msg->payload.iov_len;
	h->udp.len = BS16(udp_len);
	h->udp.source = src_v4->sin_port;
	h->udp.dest   = dst_v4->sin_port;
	h->udp.check  = 0;

	h->ipv4.ihl      = 5; // required <= hdr len 20
	h->ipv4.version  = 4;
	h->ipv4.tos      = 0; // default: best-effort DSCP + no ECN support
	h->ipv4.tot_len  = BS16(20 + udp_len);
	h->ipv4.id       = BS16(0); // probably anything; details: RFC 6864
	h->ipv4.frag_off = 0; // TODO ?
	h->ipv4.ttl      = IPDEFTTL;
	h->ipv4.protocol = 0x11; // UDP

	memcpy(&h->ipv4.saddr, &src_v4->sin_addr, sizeof(src_v4->sin_addr));
	memcpy(&h->ipv4.daddr, &dst_v4->sin_addr, sizeof(dst_v4->sin_addr));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
	h->ipv4.check = pkt_ipv4_checksum_2(&h->ipv4);
#pragma GCC diagnostic pop

	memcpy(h->eth.h_dest, msg->eth_to, sizeof(msg->eth_to));
	memcpy(h->eth.h_source, msg->eth_from, sizeof(msg->eth_from));
	h->eth.h_proto = BS16(ETH_P_IP);

	uint32_t eth_len = FRAME_PAYLOAD_OFFSET + msg->payload.iov_len + 4/*CRC*/;

	return pkt_send(the_socket, h->bytes - the_socket->umem->frames->bytes, eth_len);
}

_public_
int knot_xsk_sendmmsg(const knot_xsk_msg_t msgs[], uint32_t count)
{
	int ret = KNOT_EOK;
	for (int i = 0; i < count && ret == KNOT_EOK; i++) {
		if (msgs[i].payload.iov_len > 0) {
			ret = knot_xsk_sendmsg(&msgs[i]);
		}
	}
	return ret;
}

/** Periodical callback. Just using 'the_socket' global. */
_public_
int knot_xsk_check()
{
	/* Trigger sending queued packets.
	 * LATER(opt.): the periodical epoll due to the uv_poll* stuff
	 * is probably enough to wake the kernel even for sending
	 * (though AFAIK it might be specific to driver and/or kernel version). */
	if (the_socket->kernel_needs_wakeup) {
		int sendret = sendto(xsk_socket__fd(the_socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		bool is_ok = (sendret != -1);
		const bool is_again = !is_ok && (errno == EWOULDBLOCK || errno == EAGAIN);
		if (is_ok || is_again) {
			the_socket->kernel_needs_wakeup = false;
			// EAGAIN is unclear; we'll retry the syscall later, to be sure
		}
		if (!is_ok && !is_again) {
			return KNOT_EAGAIN;
		}
	}

	/* Collect completed packets. */
	struct xsk_ring_cons *cq = &the_socket->umem->cq;
	uint32_t idx_cq;
	const uint32_t completed = xsk_ring_cons__peek(cq, UINT32_MAX, &idx_cq);
	printf("completed %u\n", completed);
	if (!completed) return KNOT_EOK; // ?

	/* Free shared memory. */
	for (int i = 0; i < completed; ++i, ++idx_cq) {
		uint8_t *uframe_p = (uint8_t *)the_socket->umem->frames	+ *xsk_ring_cons__comp_addr(cq, idx_cq) - offsetof(struct umem_frame, udpv4);
		xsk_dealloc_umem_frame(the_socket->umem, uframe_p);
	}

	xsk_ring_cons__release(cq, completed);
	//TODO: one uncompleted packet/batch is left until the next I/O :-/
	/* And feed frames into RX fill queue. */
	return kxsk_umem_refill(the_config, the_socket->umem);
}

static int rx_desc(struct xsk_socket_info *xsi, const struct xdp_desc *desc,
		   knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = xsi->umem->frames->bytes + desc->addr;
	const struct ethhdr *eth = (struct ethhdr *)uframe_p;
	const struct iphdr *ipv4 = NULL;
	const struct ipv6hdr *ipv6 = NULL;
	const struct udphdr *udp;

	printf("recv %p\n", uframe_p);

	int ret = KNOT_EOK;

	// FIXME: length checks on multiple places
	if (eth->h_proto == BS16(ETH_P_IP)) {
		ipv4 = (struct iphdr *)(uframe_p + sizeof(struct ethhdr));
		// Any fragmentation stuff is bad for use, except for the DF flag
		uint16_t frag_off = BS16(ipv4->frag_off);
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

	} else if (eth->h_proto == BS16(ETH_P_IPV6)) {
		(void)ipv6;
		ret = KNOT_ENOTSUP; // FIXME later
		goto free_frame;
	} else {
		ret = KNOT_ENOTSUP;
		goto free_frame;
	}

	assert(eth && (!!ipv4 != !!ipv6) && udp);

	msg->payload.iov_base = (uint8_t *)udp + sizeof(struct udphdr);
	msg->payload.iov_len = BS16(udp->len) - sizeof(struct udphdr);

	memcpy(msg->eth_from, eth->h_source, sizeof(msg->eth_from));
	memcpy(msg->eth_to, eth->h_dest, sizeof(msg->eth_to));

	// process the packet; ownership is passed on, but beware of holding frames
	// LATER: filter the address-port combinations that we listen on?

	assert(ipv4);
	struct sockaddr_in *src_v4 = (struct sockaddr_in *)&msg->ip_from;
	struct sockaddr_in *dst_v4 = (struct sockaddr_in *)&msg->ip_to;
	memcpy(&src_v4->sin_addr, &ipv4->saddr, sizeof(src_v4->sin_addr));
	memcpy(&dst_v4->sin_addr, &ipv4->daddr, sizeof(dst_v4->sin_addr));
	src_v4->sin_port = udp->source;
	dst_v4->sin_port = udp->dest;

	return KNOT_EOK;

free_frame:
	xsk_dealloc_umem_frame(xsi->umem, uframe_p);
	return ret;
}

_public_
int knot_xsk_recvmmsg(knot_xsk_msg_t msgs[], uint32_t max_count, uint32_t *count)
{
	uint32_t idx_rx = 0;
	int ret = KNOT_EOK;
	*count = xsk_ring_cons__peek(&the_socket->rx, max_count, &idx_rx);
	assert(*count <= max_count);

	for (size_t i = 0; i < *count && ret == KNOT_EOK; ++i, ++idx_rx) {
		ret = rx_desc(the_socket, xsk_ring_cons__rx_desc(&the_socket->rx, idx_rx), &msgs[i]);
	}

	if (ret == KNOT_EOK && *count > 0) {
		xsk_ring_cons__release(&the_socket->rx, *count);
	}
	return ret;
}

_public_
void knot_xsk_free_recvd(const knot_xsk_msg_t *msg)
{
	uint8_t *uframe_p = msg_uframe_p(msg);
	if (uframe_p != NULL) {
		xsk_dealloc_umem_frame(the_socket->umem, uframe_p);
	}
}

static struct kxsk_config the_config_storage = { // static to get zeroed by default
	.xsk_if_queue = 0, // defaults overridable by command-line -x eth3:0
	.umem_frame_count = 8192,
	.umem = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE, // we need to know this value explicitly
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	},
	.xsk = {
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
	},
};

_public_
int knot_xsk_init(const char *ifname, const char *prog_fname,
                  ssize_t *out_busy_frames)
{
	the_config = &the_config_storage;

	struct kxsk_iface *iface = kxsk_iface_new(ifname, prog_fname);
	if (!iface) {
		return KNOT_EINVAL;
	}

	/* Initialize shared packet_buffer for umem usage */
	struct xsk_umem_info *umem =
		configure_xsk_umem(&the_config->umem, the_config->umem_frame_count);
	if (umem == NULL) {
		kxsk_iface_free(iface, false);
		return KNOT_ENOMEM;
	}

	/* Open and configure the AF_XDP (xsk) socket */
	assert(!the_socket);

	the_socket = xsk_configure_socket(the_config, umem, iface);
	if (!the_socket) {
		xsk_umem__delete(umem->umem);
		kxsk_iface_free(iface, false);
		return KNOT_NET_ESOCKET;
	}

	int ret = kxsk_socket_start(iface, the_config->xsk_if_queue, the_socket->xsk);
	if (ret != KNOT_EOK) {
		xsk_socket__delete(the_socket->xsk);
		xsk_umem__delete(the_socket->umem->umem);
		kxsk_iface_free(iface, false);
		return ret;
	}

	if (out_busy_frames != NULL) {
		*out_busy_frames = the_socket->umem->frame_count - the_socket->umem->free_count;
	}

	return ret;
}

_public_
int knot_xsk_get_poll_fd()
{
	return xsk_socket__fd(the_socket->xsk);
}
