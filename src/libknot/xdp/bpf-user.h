/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#if USE_LIBXDP
 #include <xdp/xsk.h>
#else
 #include <bpf/xsk.h>
#endif

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
	/*! Size of RX and TX rings. */
	uint16_t ring_size;
	/*! The number of free frames (for TX). */
	uint16_t tx_free_count;
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

	/*! The limit of frame size. */
	unsigned frame_limit;

	/*! Mapping of interface indices to VLAN tags. */
	uint16_t *vlan_map;
	uint16_t vlan_map_max;

	/*! Enabled preferred busy polling. */
	bool busy_poll;
};

/*!
 * \brief Set up BPF program and map for one XDP socket.
 *
 * \param if_name      Name of the net iface (e.g. eth0).
 * \param if_queue     Network card queue id.
 * \param load_bpf     Insert BPF program into packet processing.
 * \param generic_xdp  Use generic XDP implementation instead of a native one.
 * \param out_iface    Output: created interface context.
 *
 * \return KNOT_E* or -errno
 */
int kxsk_iface_new(const char *if_name, unsigned if_queue, knot_xdp_load_bpf_t load_bpf,
                   bool generic_xdp, struct kxsk_iface **out_iface);

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
