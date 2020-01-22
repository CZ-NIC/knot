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

#pragma once

#include  <stdint.h>

#include <bpf/xsk.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

struct udpv4 {
	union { uint8_t bytes[1]; struct {

	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct iphdr ipv4;
	struct udphdr udp;
	uint8_t data[];

	} __attribute__((packed)); };
};

struct udpv6 {
	union { uint8_t bytes[1]; struct {

	struct ethhdr eth; // no VLAN support; CRC at the "end" of .data!
	struct ipv6hdr ipv6;
	struct udphdr udp;
	uint8_t data[];

	} __attribute__((packed)); };
};

/** Data around one network interface. */
struct kxsk_iface {
	const char *ifname;
	int ifindex; /**< computed from ifname */

	/* File-descriptors to BPF maps for the program running on the interface. */
	int qidconf_map_fd;
	int xsks_map_fd;

	struct bpf_object *prog_obj;
};

struct xsk_umem_info {
	/** Fill queue: passing memory frames to kernel - ready to receive. */
	struct xsk_ring_prod fq;
	/** Completion queue: passing memory frames from kernel - after send finishes. */
	struct xsk_ring_cons cq;
	/** Handle internal to libbpf. */
	struct xsk_umem *umem;

	struct umem_frame *frames; /**< The memory frames. TODO: (uint8_t *frammem) might be more practical. */
	uint32_t frame_count;
	uint32_t free_count; /**< The number of free frames. */
	uint32_t *free_indices; /**< Stack of indices of the free frames. */
};

typedef struct knot_xsk_socket {
	/** Receive queue: passing arrived packets from kernel. */
	struct xsk_ring_cons rx;
	/** Transmit queue: passing packets to kernel for sending. */
	struct xsk_ring_prod tx;
	/** Information about memory frames for all the passed packets. */
	struct xsk_umem_info *umem;
	/** Handle internal to libbpf. */
	struct xsk_socket *xsk;

	bool kernel_needs_wakeup;

	const struct kxsk_iface *iface;
	int if_queue;
} knot_xsk_socket_t;

/*!
 * \brief Set up BPF program and map for one XDP socket.
 *
 * \param ifname       Name of the net iface (e.g. eth0).
 * \param load_bpf     Insert BPF program into packet processing.
 * \param out_iface    Output: created interface context.
 *
 * \return KNOT_E*
 */
int kxsk_iface_new(const char *ifname, bool load_bpf, struct kxsk_iface **out_iface);

/*!
 * \brief Unload BPF maps for a socket.
 *
 * \param iface   Interface context to be freed.
 *
 * \note This keeps the loaded BPF program. We don't care.
 */
void kxsk_iface_free(struct kxsk_iface *iface);

/*! \brief Activate this AF_XDP socket through the BPF maps. */
int kxsk_socket_start(const struct kxsk_iface *iface, int queue_id,
                      uint32_t listen_port, struct xsk_socket *xsk);

/*! \brief Deactivate this AF_XDP socket through the BPF maps. */
int kxsk_socket_stop(const struct kxsk_iface *iface, int queue_id);
