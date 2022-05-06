/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <time.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/xdp/bpf-user.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/msg_init.h"
#include "libknot/xdp/protocols.h"
#include "libknot/xdp/xdp.h"
#include "contrib/macros.h"
#include "contrib/net.h"

#define FRAME_SIZE 2048
#define UMEM_FRAME_COUNT_RX 4096
#define UMEM_FRAME_COUNT_TX UMEM_FRAME_COUNT_RX // No reason to differ so far.
#define UMEM_RING_LEN_RX (UMEM_FRAME_COUNT_RX * 2)
#define UMEM_RING_LEN_TX (UMEM_FRAME_COUNT_TX * 2)
#define UMEM_FRAME_COUNT (UMEM_FRAME_COUNT_RX + UMEM_FRAME_COUNT_TX)

#define ALLOC_RETRY_NUM   15
#define ALLOC_RETRY_DELAY 20 // In nanoseconds.

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

struct umem_frame {
	uint8_t bytes[FRAME_SIZE];
};

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
                  knot_xdp_filter_flag_t flags, uint16_t udp_port, uint16_t quic_port,
                  knot_xdp_load_bpf_t load_bpf)
{
	if (socket == NULL || if_name == NULL ||
	    (udp_port == quic_port && (flags & KNOT_XDP_FILTER_QUIC)) ||
	    (flags & (KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_TCP | KNOT_XDP_FILTER_QUIC)) == 0) {
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

	(*socket)->frame_limit = FRAME_SIZE;
	ret = knot_eth_mtu(if_name);
	if (ret > 0) {
		(*socket)->frame_limit = MIN((unsigned)ret, (*socket)->frame_limit);
	}

	ret = kxsk_socket_start(iface, flags, udp_port, quic_port, (*socket)->xsk);
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
	if (unlikely(socket->send_mock != NULL)) {
		free(socket);
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
	if (socket == NULL || unlikely(socket->send_mock != NULL)) {
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

static struct umem_frame *alloc_tx_frame(knot_xdp_socket_t *socket)
{
	if (unlikely(socket->send_mock != NULL)) {
		return malloc(sizeof(struct umem_frame));
	}

	const struct timespec delay = { .tv_nsec = ALLOC_RETRY_DELAY };
	struct kxsk_umem *umem = socket->umem;

	for (int i = 0; unlikely(umem->tx_free_count == 0); i++) {
		if (i == ALLOC_RETRY_NUM) {
			return NULL;
		}
		nanosleep(&delay, NULL);
		knot_xdp_send_prepare(socket);
	}

	uint32_t index = umem->tx_free_indices[--umem->tx_free_count];
	return umem->frames + index;
}

static void prepare_payload(knot_xdp_msg_t *msg, void *uframe)
{
	size_t hdr_len = prot_write_hdrs_len(msg);
	msg->payload.iov_base = uframe + hdr_len;
	msg->payload.iov_len = FRAME_SIZE - hdr_len;
}

_public_
int knot_xdp_send_alloc(knot_xdp_socket_t *socket, knot_xdp_msg_flag_t flags,
                        knot_xdp_msg_t *out)
{
	if (socket == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	struct umem_frame *uframe = alloc_tx_frame(socket);
	if (uframe == NULL) {
		return KNOT_ENOMEM;
	}

	msg_init(out, flags);
	prepare_payload(out, uframe);

	return KNOT_EOK;
}

_public_
int knot_xdp_reply_alloc(knot_xdp_socket_t *socket, const knot_xdp_msg_t *query,
                         knot_xdp_msg_t *out)
{
	if (socket == NULL || query == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	struct umem_frame *uframe = alloc_tx_frame(socket);
	if (uframe == NULL) {
		return KNOT_ENOMEM;
	}

	msg_init_reply(out, query);
	prepare_payload(out, uframe);

	return KNOT_EOK;
}

static void free_unsent(knot_xdp_socket_t *socket, const knot_xdp_msg_t *msg)
{
	if (unlikely(socket->send_mock != NULL)) {
		free(msg->payload.iov_base - prot_write_hdrs_len(msg));
		return;
	}
	uint64_t addr_relative = (uint8_t *)msg->payload.iov_base
	                         - socket->umem->frames->bytes;
	tx_free_relative(socket->umem, addr_relative);
}

_public_
int knot_xdp_send(knot_xdp_socket_t *socket, const knot_xdp_msg_t msgs[],
                  uint32_t count, uint32_t *sent)
{
	if (socket == NULL || msgs == NULL || sent == NULL) {
		return KNOT_EINVAL;
	}
	if (unlikely(socket->send_mock != NULL)) {
		int ret = socket->send_mock(socket, msgs, count, sent);
		for (uint32_t i = 0; i < count; ++i) {
			free_unsent(socket, &msgs[i]);
		}
		return ret;
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

		if (empty_msg(msg)) {
			free_unsent(socket, msg);
		} else {
			size_t hdr_len = prot_write_hdrs_len(msg);
			size_t tot_len = hdr_len + msg->payload.iov_len;
			uint8_t *msg_beg = msg->payload.iov_base - hdr_len;
			uint16_t mss = MIN(socket->frame_limit - hdr_len, KNOT_TCP_MSS);
			prot_write_eth(msg_beg, msg, msg_beg + tot_len, mss);

			*xsk_ring_prod__tx_desc(&socket->tx, idx++) = (struct xdp_desc) {
				.addr = msg_beg - socket->umem->frames->bytes,
				.len = tot_len,
			};
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
void knot_xdp_send_free(knot_xdp_socket_t *socket, const knot_xdp_msg_t msgs[],
                        uint32_t count)
{
	for (uint32_t i = 0; i < count; i++) {
		free_unsent(socket, &msgs[i]);
	}
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

_public_
int knot_xdp_recv(knot_xdp_socket_t *socket, knot_xdp_msg_t msgs[],
                  uint32_t max_count, uint32_t *count, size_t *wire_size)
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
		knot_xdp_msg_t *msg = &msgs[i];
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&socket->rx, idx++);
		uint8_t *uframe_p = socket->umem->frames->bytes + desc->addr;

		void *payl_end, *payl_start = prot_read_eth(uframe_p, msg, &payl_end);

		msg->payload.iov_base = payl_start;
		msg->payload.iov_len = payl_end - payl_start;
		msg->mss = MIN(msg->mss, FRAME_SIZE - (payl_start - (void *)uframe_p));

		if (wire_size != NULL) {
			(*wire_size) += desc->len;
		}
	}

	xsk_ring_cons__release(&socket->rx, available);
	*count = available;

	return KNOT_EOK;
}

static uint8_t *msg_uframe_ptr(const knot_xdp_msg_t *msg)
{
	return NULL + ((msg->payload.iov_base - NULL) & ~(FRAME_SIZE - 1));
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
		uint8_t *uframe_p = msg_uframe_ptr(&msgs[i]);
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
