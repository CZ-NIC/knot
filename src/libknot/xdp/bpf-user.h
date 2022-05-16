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

/*!
 * \file
 *
 * \brief XDP socket interface.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <bpf/xsk.h>

#include "libknot/xdp/xdp.h"

struct kxsk_iface {
	/*! Interface name. */
	const char *if_name;
	/*! Interface name index (derived from ifname). */
	int if_index;
	/*! Network card queue id. */
	unsigned if_queue;

	/*! Configuration BPF map file descriptor. */
	int opts_map_fd;
	/*! XSK BPF map file descriptor. */
	int xsks_map_fd;

	/*! BPF program object. */
	struct bpf_object *prog_obj;
};

struct kxsk_umem {
	/*! Fill queue: passing memory frames to kernel - ready to receive. */
	struct xsk_ring_prod fq;
	/*! Completion queue: passing memory frames from kernel - after send finishes. */
	struct xsk_ring_cons cq;
	/*! Handle internal to libbpf. */
	struct xsk_umem *umem;

	/*! The memory frames. */
	struct umem_frame *frames;
	/*! The number of free frames (for TX). */
	uint32_t tx_free_count;
	/*! Stack of indices of the free frames (for TX). */
	uint16_t tx_free_indices[];
};

struct knot_xdp_socket {
	/*! Receive queue: passing arrived packets from kernel. */
	struct xsk_ring_cons rx;
	/*! Transmit queue: passing packets to kernel for sending. */
	struct xsk_ring_prod tx;
	/*! Information about memory frames for all the passed packets. */
	struct kxsk_umem *umem;
	/*! Handle internal to libbpf. */
	struct xsk_socket *xsk;

	/*! Interface context. */
	const struct kxsk_iface *iface;

	/*! If non-NULL, it's a mocked socket with this send function. */
	int (*send_mock)(struct knot_xdp_socket *, const knot_xdp_msg_t[], uint32_t, uint32_t *);

	/*! The kernel has to be woken up by a syscall indication. */
	bool kernel_needs_wakeup;

	/*! The limit of frame size. */
	unsigned frame_limit;
};

/*!
 * \brief Set up BPF program and map for one XDP socket.
 *
 * \param if_name    Name of the net iface (e.g. eth0).
 * \param if_queue   Network card queue id.
 * \param load_bpf   Insert BPF program into packet processing.
 * \param out_iface  Output: created interface context.
 *
 * \return KNOT_E* or -errno
 */
int kxsk_iface_new(const char *if_name, unsigned if_queue, knot_xdp_load_bpf_t load_bpf,
                   struct kxsk_iface **out_iface);

/*!
 * \brief Unload BPF maps for a socket.
 *
 * \note This keeps the loaded BPF program. We don't care.
 *
 * \param iface  Interface context to be freed.
 */
void kxsk_iface_free(struct kxsk_iface *iface);

/*!
 * \brief Activate this AF_XDP socket through the BPF maps.
 *
 * \param iface        Interface context.
 * \param flags        XDP filter configuration flags.
 * \param udp_port     UDP and/or TCP port to listen on if enabled via \a opts.
 * \param quic_port    QUIC/UDP port to listen on if enabled via \a opts.
 * \param xsk          Socket ctx.
 *
 * \return KNOT_E* or -errno
 */
int kxsk_socket_start(const struct kxsk_iface *iface, knot_xdp_filter_flag_t flags,
                      uint16_t udp_port, uint16_t quic_port, struct xsk_socket *xsk);

/*!
 * \brief Deactivate this AF_XDP socket through the BPF maps.
 *
 * \param iface  Interface context.
 */
void kxsk_socket_stop(const struct kxsk_iface *iface);

/*! @} */
