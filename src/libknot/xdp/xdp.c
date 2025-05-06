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

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libknot/attribute.h"
#include "libknot/endian.h"
#include "libknot/errcode.h"
#include "libknot/xdp/bpf-consts.h"
#include "libknot/xdp/bpf-user.h"
#include "libknot/xdp/eth.h"
#include "libknot/xdp/msg_init.h"
#include "libknot/xdp/protocols.h"
#include "libknot/xdp/xdp.h"
#include "contrib/macros.h"
#include "contrib/net.h"

#define FRAME_SIZE		2048
#define DEFAULT_RING_SIZE	2048
#define RETRY_DELAY		20 // In nanoseconds.

struct umem_frame {
	uint8_t bytes[FRAME_SIZE];
};

static bool valid_config(const knot_xdp_config_t *config)
{
	if (FRAME_SIZE != 2048 && FRAME_SIZE != 4096) {
		return false;
	}

	if (config == NULL) {
		return true;
	}

	if ((config->ring_size & (config->ring_size - 1)) != 0) {
		return false;
	}

	return true;
}

static uint32_t ring_size(const knot_xdp_config_t *config)
{
	return config != NULL ? config->ring_size : DEFAULT_RING_SIZE;
}

static int configure_xsk_umem(struct kxsk_umem **out_umem, uint32_t ring_size)
{
	/* Allocate memory and call driver to create the UMEM. */
	struct kxsk_umem *umem = calloc(1,
		offsetof(struct kxsk_umem, tx_free_indices)
		+ sizeof(umem->tx_free_indices[0]) * ring_size);
	if (umem == NULL) {
		return KNOT_ENOMEM;
	}
	umem->ring_size = ring_size;

	/* It's recommended that the FQ ring size >= HW RX ring size + AF_XDP RX ring size.
	 * However, the performance is better if FQ size == AF_XDP RX size. */
	const uint32_t FQ_SIZE = umem->ring_size;
	const uint32_t CQ_SIZE = umem->ring_size;
	const uint32_t FRAMES = FQ_SIZE + CQ_SIZE;

	int ret = posix_memalign((void **)&umem->frames, getpagesize(),
	                         FRAME_SIZE * FRAMES);
	if (ret != 0) {
		free(umem);
		return KNOT_ENOMEM;
	}

	const struct xsk_umem_config umem_config = {
		.fill_size = FQ_SIZE,
		.comp_size = CQ_SIZE,
		.frame_size = FRAME_SIZE,
		.frame_headroom = KNOT_XDP_PKT_ALIGNMENT,
	};

	ret = xsk_umem__create(&umem->umem, umem->frames, FRAME_SIZE * FRAMES,
	                       &umem->fq, &umem->cq, &umem_config);
	if (ret != KNOT_EOK) {
		free(umem->frames);
		free(umem);
		return ret;
	}
	*out_umem = umem;

	/* Designate the starting chunk of buffers for TX, and put them onto the stack. */
	umem->tx_free_count = CQ_SIZE;
	for (uint32_t i = 0; i < CQ_SIZE; ++i) {
		umem->tx_free_indices[i] = i;
	}

	/* Designate the rest of buffers for RX, and pass them to the driver. */
	uint32_t idx = 0;
	ret = xsk_ring_prod__reserve(&umem->fq, FQ_SIZE, &idx);
	if (ret != FQ_SIZE) {
		assert(0);
		return KNOT_ERROR;
	}
	assert(idx == 0);
	for (uint32_t i = CQ_SIZE; i < CQ_SIZE + FQ_SIZE; ++i) {
		*xsk_ring_prod__fill_addr(&umem->fq, idx++) = i * FRAME_SIZE;
	}
	xsk_ring_prod__submit(&umem->fq, FQ_SIZE);

	return KNOT_EOK;
}

static void deconfigure_xsk_umem(struct kxsk_umem *umem)
{
	(void)xsk_umem__delete(umem->umem);
	free(umem->frames);
	free(umem);
}

static int enable_busypoll(int socket, unsigned timeout_us, unsigned budget)
{
#if defined(SO_PREFER_BUSY_POLL) && defined(SO_BUSY_POLL_BUDGET)
	int opt_val = 1;
	if (setsockopt(socket, SOL_SOCKET, SO_PREFER_BUSY_POLL,
	               &opt_val, sizeof(opt_val)) != 0) {
		return knot_map_errno();
	}

	opt_val = timeout_us;
	if (setsockopt(socket, SOL_SOCKET, SO_BUSY_POLL,
	               &opt_val, sizeof(opt_val)) != 0) {
		return knot_map_errno();
	}

	opt_val = budget;
	if (setsockopt(socket, SOL_SOCKET, SO_BUSY_POLL_BUDGET,
	               &opt_val, sizeof(opt_val)) != 0) {
		return knot_map_errno();
	}

	return KNOT_EOK;
#else
	return KNOT_ENOTSUP;
#endif
}

static int configure_xsk_socket(struct kxsk_umem *umem,
                                const struct kxsk_iface *iface,
                                knot_xdp_socket_t **out_sock,
                                const knot_xdp_config_t *config)
{
	knot_xdp_socket_t *xsk_info = calloc(1, sizeof(*xsk_info));
	if (xsk_info == NULL) {
		return KNOT_ENOMEM;
	}
	xsk_info->iface = iface;
	xsk_info->umem = umem;

	uint16_t bind_flags = XDP_USE_NEED_WAKEUP;
	if (config != NULL && config->force_copy) {
		bind_flags |= XDP_COPY;
	}

	const struct xsk_socket_config sock_conf = {
		.tx_size = umem->ring_size,
		.rx_size = umem->ring_size,
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.bind_flags = bind_flags,
	};

	int ret = xsk_socket__create(&xsk_info->xsk, iface->if_name,
	                             iface->if_queue, umem->umem,
	                             &xsk_info->rx, &xsk_info->tx, &sock_conf);
	if (ret != 0) {
		free(xsk_info);
		return ret;
	}

	if (config != NULL && config->busy_poll_budget > 0) {
		ret = enable_busypoll(xsk_socket__fd(xsk_info->xsk),
		                      config->busy_poll_timeout, config->busy_poll_budget);
		if (ret != KNOT_EOK) {
			xsk_socket__delete(xsk_info->xsk);
			free(xsk_info);
			return ret;
		}
		xsk_info->busy_poll = true;
	}

	*out_sock = xsk_info;
	return KNOT_EOK;
}

_public_
int knot_xdp_init(knot_xdp_socket_t **socket, const char *if_name, int if_queue,
                  knot_xdp_filter_flag_t flags, uint16_t udp_port, uint16_t quic_port,
                  knot_xdp_load_bpf_t load_bpf, const knot_xdp_config_t *xdp_config)
{
	if (socket == NULL || if_name == NULL || !valid_config(xdp_config) ||
	    (udp_port == quic_port && (flags & KNOT_XDP_FILTER_UDP) && (flags & KNOT_XDP_FILTER_QUIC)) ||
	    (flags & (KNOT_XDP_FILTER_UDP | KNOT_XDP_FILTER_TCP | KNOT_XDP_FILTER_QUIC)) == 0) {
		return KNOT_EINVAL;
	}

	struct kxsk_iface *iface;
	const bool generic_xdp = (xdp_config != NULL && xdp_config->force_generic);
	int ret = kxsk_iface_new(if_name, if_queue, load_bpf, generic_xdp, &iface);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Initialize shared packet_buffer for umem usage. */
	struct kxsk_umem *umem = NULL;
	ret = configure_xsk_umem(&umem, ring_size(xdp_config));
	if (ret != KNOT_EOK) {
		kxsk_iface_free(iface);
		return ret;
	}

	ret = configure_xsk_socket(umem, iface, socket, xdp_config);
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

	if (flags & KNOT_XDP_FILTER_ROUTE) {
		ret = knot_eth_vlans(&(*socket)->vlan_map, &(*socket)->vlan_map_max);
		if (ret != KNOT_EOK) {
			xsk_socket__delete((*socket)->xsk);
			deconfigure_xsk_umem(umem);
			kxsk_iface_free(iface);
			free(*socket);
			*socket = NULL;
			return ret;
		}
	}

	ret = kxsk_socket_start(iface, flags, udp_port, quic_port, (*socket)->xsk);
	if (ret != KNOT_EOK) {
		free((*socket)->vlan_map);
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
	free(socket->vlan_map);
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
	assert(index < umem->ring_size);
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
	assert(umem->tx_free_count + completed <= umem->ring_size);

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

	struct kxsk_umem *umem = socket->umem;

	const struct timespec delay = { .tv_nsec = RETRY_DELAY };
	while (unlikely(umem->tx_free_count == 0)) {
		if (socket->busy_poll || xsk_ring_prod__needs_wakeup(&socket->tx)) {
			(void)sendto(xsk_socket__fd(socket->xsk), NULL, 0,
			             MSG_DONTWAIT, NULL, 0);
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
	msg->payload.iov_base = uframe + hdr_len + KNOT_XDP_PKT_ALIGNMENT;
	msg->payload.iov_len = FRAME_SIZE - hdr_len - KNOT_XDP_PKT_ALIGNMENT;
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
		free(msg->payload.iov_base - prot_write_hdrs_len(msg) - KNOT_XDP_PKT_ALIGNMENT);
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
		knot_xdp_send_free(socket, msgs, count);
		return ret;
	}

	/* Now we want to do something close to
	 *   xsk_ring_prod__reserve(&socket->tx, count, *idx)
	 * but we don't know in advance if we utilize *whole* `count`,
	 * and the API doesn't allow "cancelling reservations".
	 * Therefore we handle `socket->tx.cached_prod` by hand.
	 */
	const struct timespec delay = { .tv_nsec = RETRY_DELAY };
	while (unlikely(xsk_prod_nb_free(&socket->tx, count) < count)) {
		if (socket->busy_poll || xsk_ring_prod__needs_wakeup(&socket->tx)) {
			(void)sendto(xsk_socket__fd(socket->xsk), NULL, 0,
			             MSG_DONTWAIT, NULL, 0);
		}
		nanosleep(&delay, NULL);
	}
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

	if (!socket->busy_poll && !xsk_ring_prod__needs_wakeup(&socket->tx)) {
		return KNOT_EOK;
	}

	int ret = sendto(xsk_socket__fd(socket->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0) {
		return KNOT_EOK;
	} else if (errno == ENOBUFS || errno == EAGAIN || errno == EBUSY ||
	           errno == ENETDOWN) {
		return KNOT_NET_EAGAIN;
	} else {
		return -errno;
	}
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
		uint8_t *uframe_p = (uint8_t *)socket->umem->frames + desc->addr;

		void *payl_end;
		void *payl_start = prot_read_eth(uframe_p, msg, &payl_end,
		                                 socket->vlan_map, socket->vlan_map_max);

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
	return (uint8_t *)((uintptr_t)msg->payload.iov_base & ~(FRAME_SIZE - 1));
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
	const struct timespec delay = { .tv_nsec = RETRY_DELAY };
	while (unlikely(xsk_ring_prod__reserve(fq, count, &idx) != count)) {
		if (socket->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
			(void)recvfrom(xsk_socket__fd(socket->xsk), NULL, 0,
			               MSG_DONTWAIT, NULL, NULL);
		}
		nanosleep(&delay, NULL);
	}

	for (uint32_t i = 0; i < count; ++i) {
		uint8_t *uframe_p = msg_uframe_ptr(&msgs[i]);
		uint64_t offset = uframe_p - umem->frames->bytes;
		*xsk_ring_prod__fill_addr(fq, idx++) = offset;
	}

	xsk_ring_prod__submit(fq, count);
	// recvfrom() here slightly worsens the performance, poll is called later anyway.
}

// The number of busy frames
#define RING_BUSY(ring) ((*(ring)->producer - *(ring)->consumer) & (ring)->mask)

_public_
void knot_xdp_socket_info(const knot_xdp_socket_t *socket, FILE *file)
{
	if (socket == NULL || file == NULL) {
		return;
	}

	#define RING_PRINFO(name, ring) \
		fprintf(file, "Ring %s: size %4d, busy %4d (prod %4d, cons %4d)\n", \
		        name, (unsigned)(ring)->size, \
		        (unsigned)RING_BUSY((ring)), \
		        (unsigned)*(ring)->producer, (unsigned)*(ring)->consumer)

	const int rx_busyf = RING_BUSY(&socket->umem->fq) + RING_BUSY(&socket->rx);
	fprintf(file, "\nLOST RX frames: %4d", (int)(socket->umem->ring_size - rx_busyf));

	const int tx_busyf = RING_BUSY(&socket->umem->cq) + RING_BUSY(&socket->tx);
	const int tx_freef = socket->umem->tx_free_count;
	fprintf(file, "\nLOST TX frames: %4d\n", (int)(socket->umem->ring_size - tx_busyf - tx_freef));

	RING_PRINFO("FQ", &socket->umem->fq);
	RING_PRINFO("RX", &socket->rx);
	RING_PRINFO("TX", &socket->tx);
	RING_PRINFO("CQ", &socket->umem->cq);
	fprintf(file, "TX free frames: %4d\n", tx_freef);
}

_public_
int knot_xdp_socket_stats(knot_xdp_socket_t *socket, knot_xdp_stats_t *stats)
{
	if (socket == NULL || stats == NULL) {
		return KNOT_EINVAL;
	}

	memset(stats, 0, sizeof(*stats));

	stats->if_name = socket->iface->if_name;
	stats->if_index = socket->iface->if_index;
	stats->if_queue = socket->iface->if_queue;

	struct xdp_statistics xdp_stats;
	socklen_t optlen = sizeof(xdp_stats);

	int fd = knot_xdp_socket_fd(socket);
	int ret = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen);
	if (ret != 0) {
		return knot_map_errno();
	} else if (optlen != sizeof(xdp_stats)) {
		return KNOT_EINVAL;
	}

	size_t common_size = MIN(sizeof(xdp_stats), sizeof(stats->socket));
	memcpy(&stats->socket, &xdp_stats, common_size);

	stats->rings.tx_busy = socket->umem->ring_size - socket->umem->tx_free_count;
	stats->rings.fq_fill = RING_BUSY(&socket->umem->fq);
	stats->rings.rx_fill = RING_BUSY(&socket->rx);
	stats->rings.tx_fill = RING_BUSY(&socket->tx);
	stats->rings.cq_fill = RING_BUSY(&socket->umem->cq);

	return KNOT_EOK;
}
